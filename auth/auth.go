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
	PacketInit   PacketType = 'I' // Client requests a cookie (no payload, cheap to process)
	PacketCookie PacketType = 'C' // Server sends cookie back (DDoS proof-of-origin)
	PacketData   PacketType = 'D' // Client sends encrypted data with cookie
	PacketAck    PacketType = 'A' // Server acknowledges receipt
)

// Packet represents a security-hardened UDP message with HMAC authentication,
// timestamp for replay protection, and cookie for DDoS mitigation.
type Packet struct {
	Type      PacketType
	Timestamp int64  // Unix timestamp for replay protection
	Cookie    []byte // Stateless cookie for DDoS protection (40 bytes or nil)
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

// deriveCookieKey derives a separate key for cookie generation.
// Uses domain separation ("cookie-key:" prefix).
func deriveCookieKey(serverSecret []byte) []byte {
	hash := sha256.Sum256(append([]byte("cookie-key:"), serverSecret...))
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
	buf := make([]byte, 0, 1+8+len(p.Cookie)+len(p.Payload))
	buf = append(buf, byte(p.Type))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(p.Timestamp))
	buf = append(buf, ts...)
	buf = append(buf, p.Cookie...)
	buf = append(buf, p.Payload...)
	return buf
}

// Marshal encodes a Packet to bytes and signs it with the PSK.
// Wire format: [type(1)][timestamp(8)][cookie_len(2)][cookie(N)][payload_len(2)][payload(N)][signature(32)]
func (p *Packet) Marshal(psk []byte) []byte {
	p.Signature = Sign(psk, p.signedPayload())

	cookieLen := len(p.Cookie)
	payloadLen := len(p.Payload)
	totalLen := 1 + 8 + 2 + cookieLen + 2 + payloadLen + 32

	buf := make([]byte, totalLen)
	buf[0] = byte(p.Type)
	binary.BigEndian.PutUint64(buf[1:9], uint64(p.Timestamp))
	binary.BigEndian.PutUint16(buf[9:11], uint16(cookieLen))
	copy(buf[11:11+cookieLen], p.Cookie)
	off := 11 + cookieLen
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(payloadLen))
	copy(buf[off+2:off+2+payloadLen], p.Payload)
	copy(buf[off+2+payloadLen:], p.Signature)

	return buf
}

// UnmarshalPacket decodes bytes into a Packet and verifies the HMAC signature.
// Returns a uniform error message regardless of failure reason (side-channel resistant).
func UnmarshalPacket(psk, data []byte) (*Packet, error) {
	// Minimum: type(1) + timestamp(8) + cookie_len(2) + payload_len(2) + signature(32) = 45
	if len(data) < 45 {
		return nil, fmt.Errorf("authentication failed")
	}

	p := &Packet{}
	p.Type = PacketType(data[0])
	p.Timestamp = int64(binary.BigEndian.Uint64(data[1:9]))

	cookieLen := int(binary.BigEndian.Uint16(data[9:11]))
	if len(data) < 11+cookieLen+2+32 {
		return nil, fmt.Errorf("authentication failed")
	}
	if cookieLen > 0 {
		p.Cookie = make([]byte, cookieLen)
		copy(p.Cookie, data[11:11+cookieLen])
	}

	off := 11 + cookieLen
	payloadLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	if len(data) < off+2+payloadLen+32 {
		return nil, fmt.Errorf("authentication failed")
	}
	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		copy(p.Payload, data[off+2:off+2+payloadLen])
	}

	p.Signature = make([]byte, 32)
	copy(p.Signature, data[off+2+payloadLen:off+2+payloadLen+32])

	// Verify signature using constant-time comparison
	if !Verify(psk, p.signedPayload(), p.Signature) {
		return nil, fmt.Errorf("authentication failed")
	}

	return p, nil
}

// GenerateCookie creates a stateless cookie for DDoS protection.
// Format: [8 bytes timestamp][32 bytes HMAC(cookieKey, clientIP + timestamp)]
// The cookie embeds its own creation timestamp so the server can verify expiry.
func GenerateCookie(serverSecret []byte, clientIP string, timestamp int64) []byte {
	cookie := make([]byte, 40)
	binary.BigEndian.PutUint64(cookie[:8], uint64(timestamp))

	data := append([]byte(clientIP), cookie[:8]...)
	secret.Do(func() {
		key := deriveCookieKey(serverSecret)
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		copy(cookie[8:], mac.Sum(nil))
	})

	return cookie
}

// VerifyCookie verifies a stateless cookie using constant-time comparison.
// Checks both the HMAC and that the cookie timestamp is within maxAge seconds of now.
func VerifyCookie(serverSecret []byte, clientIP string, cookie []byte, nowUnix int64, maxAge int64) bool {
	if len(cookie) != 40 {
		return false
	}

	cookieTimestamp := int64(binary.BigEndian.Uint64(cookie[:8]))

	// Check cookie age
	diff := nowUnix - cookieTimestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > maxAge {
		return false
	}

	// Recompute expected HMAC
	data := append([]byte(clientIP), cookie[:8]...)
	var expected []byte
	secret.Do(func() {
		key := deriveCookieKey(serverSecret)
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		expected = make([]byte, sha256.Size)
		copy(expected, mac.Sum(nil))
	})

	return subtle.ConstantTimeCompare(expected, cookie[8:]) == 1
}
