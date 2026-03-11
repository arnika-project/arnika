// Package auth provides the security-hardened UDP protocol implementation
// including packet signing, encryption, and replay protection.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"runtime/secret"
)

// PacketType identifies the message type in the security-hardened UDP protocol.
type PacketType byte

const (
	PacketData PacketType = 'D' // Client sends encrypted data (signed + AES-GCM encrypted payload)
	PacketAck  PacketType = 'A' // Server acknowledges receipt
)

// Packet represents a security-hardened UDP message with HMAC authentication
// and timestamp for replay protection.
type Packet struct {
	Type      PacketType
	Timestamp int64  // Unix timestamp for replay protection
	Payload   []byte // Encrypted data (AES-GCM) or nil
	Signature []byte // HMAC-SHA256 over all preceding fields (32 bytes)
}

// deriveKey derives a 32-byte AES-256 key from the PSK.
func deriveKey(psk []byte) []byte {
	// sha256 is fine since its only about Proof of Possession
	hash := sha256.Sum256(psk)
	return hash[:]
}

// deriveHMACKey derives a separate key for HMAC operations.
// Uses domain separation ("hmac-key:" prefix) to prevent key reuse with AES.
func deriveHMACKey(psk []byte) []byte {
	hash := sha256.Sum256(append([]byte("hmac-key:"), psk...))
	return hash[:]
}

// Sign computes HMAC-SHA256 over the given data using the PSK.
// Uses runtime/secret.Do to ensure sensitive key material is zeroed after use.
func Sign(psk, data []byte) []byte {
	result := make([]byte, sha256.Size)
	secret.Do(func() {
		key := deriveHMACKey(psk)
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		copy(result, mac.Sum(nil))
	})
	return result
}

// Verify checks an HMAC-SHA256 signature using constant-time comparison.
// Returns true if the signature is valid, false otherwise.
// Timing is identical regardless of where the mismatch occurs.
func Verify(psk, data, signature []byte) bool {
	expected := Sign(psk, data)
	return subtle.ConstantTimeCompare(expected, signature) == 1
}

// Encrypt encrypts data using AES-256-GCM with the given PSK.
// Uses runtime/secret.Do to ensure derived key material is zeroed.
func Encrypt(psk, plaintext []byte) ([]byte, error) {
	var result []byte
	var encErr error
	secret.Do(func() {
		key := deriveKey(psk)
		block, err := aes.NewCipher(key)
		if err != nil {
			encErr = err
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			encErr = err
			return
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			encErr = err
			return
		}
		sealed := gcm.Seal(nonce, nonce, plaintext, nil)
		result = make([]byte, len(sealed))
		copy(result, sealed)
	})
	return result, encErr
}

// Decrypt decrypts data using AES-256-GCM with the given PSK.
// Uses runtime/secret.Do to ensure derived key material is zeroed.
// Returns a uniform error message regardless of failure reason (side-channel resistant).
func Decrypt(psk, ciphertext []byte) ([]byte, error) {
	var result []byte
	var decErr error
	secret.Do(func() {
		key := deriveKey(psk)
		block, err := aes.NewCipher(key)
		if err != nil {
			decErr = fmt.Errorf("authentication failed")
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			decErr = fmt.Errorf("authentication failed")
			return
		}
		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			decErr = fmt.Errorf("authentication failed")
			return
		}
		nonce := ciphertext[:nonceSize]
		enc := ciphertext[nonceSize:]
		plain, err := gcm.Open(nil, nonce, enc, nil)
		if err != nil {
			decErr = fmt.Errorf("authentication failed")
			return
		}
		result = make([]byte, len(plain))
		copy(result, plain)
	})
	return result, decErr
}

// signedPayload returns the bytes covered by the HMAC signature.
func (p *Packet) signedPayload() []byte {
	buf := make([]byte, 0, 1+8+len(p.Payload))
	buf = append(buf, byte(p.Type))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(p.Timestamp))
	buf = append(buf, ts...)
	buf = append(buf, p.Payload...)
	return buf
}

// Marshal encodes a Packet to bytes and signs it with the PSK.
// Wire format: [type(1)][timestamp(8)][payload_len(2)][payload(N)][signature(32)]
func (p *Packet) Marshal(psk []byte) []byte {
	p.Signature = Sign(psk, p.signedPayload())

	payloadLen := len(p.Payload)
	totalLen := 1 + 8 + 2 + payloadLen + 32

	buf := make([]byte, totalLen)
	buf[0] = byte(p.Type)
	binary.BigEndian.PutUint64(buf[1:9], uint64(p.Timestamp))
	binary.BigEndian.PutUint16(buf[9:11], uint16(payloadLen))
	copy(buf[11:11+payloadLen], p.Payload)
	copy(buf[11+payloadLen:], p.Signature)

	return buf
}

// UnmarshalPacket decodes bytes into a Packet and verifies the HMAC signature.
// Returns a uniform error message regardless of failure reason (side-channel resistant).
func UnmarshalPacket(psk, data []byte) (*Packet, error) {
	// Minimum: type(1) + timestamp(8) + payload_len(2) + signature(32) = 43
	if len(data) < 43 {
		return nil, fmt.Errorf("authentication failed")
	}

	p := &Packet{}
	p.Type = PacketType(data[0])
	p.Timestamp = int64(binary.BigEndian.Uint64(data[1:9]))

	payloadLen := int(binary.BigEndian.Uint16(data[9:11]))
	if len(data) < 11+payloadLen+32 {
		return nil, fmt.Errorf("authentication failed")
	}
	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		copy(p.Payload, data[11:11+payloadLen])
	}

	p.Signature = make([]byte, 32)
	copy(p.Signature, data[11+payloadLen:11+payloadLen+32])

	// Verify signature using constant-time comparison
	if !Verify(psk, p.signedPayload(), p.Signature) {
		return nil, fmt.Errorf("authentication failed")
	}

	return p, nil
}
