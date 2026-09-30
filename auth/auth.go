// Package auth signs, encrypts and replay-checks Arnika's UDP peer packets.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"runtime/secret"
	"time"
)

var errAuth = errors.New("authentication failed") // one error for every failure so the cause never leaks

type PacketType byte

const (
	PacketData PacketType = 'D'
	PacketAck  PacketType = 'A'
	PacketPQC  PacketType = 'Q' // the PQC frame kind lives inside the payload
)

// Direction keys the HMAC per sending peer, so a packet reflected back to its sender fails verification.
type Direction string

const (
	DirEven Direction = "even"
	DirOdd  Direction = "odd"
)

// DirectionFor labels by ARNIKA_ID parity, which the two peers are required to differ in.
func DirectionFor(arnikaID int) (out, in Direction) {
	if arnikaID%2 == 0 {
		return DirEven, DirOdd
	}
	return DirOdd, DirEven
}

type Packet struct {
	Type      PacketType
	Timestamp int64
	Payload   []byte
	Signature []byte
}

func deriveKey(psk []byte) []byte {
	hash := sha256.Sum256(psk)
	return hash[:]
}

func deriveHMACKey(psk []byte, dir Direction) []byte {
	hash := sha256.Sum256(append([]byte("hmac-key:"+string(dir)+":"), psk...))
	return hash[:]
}

func Sign(psk, data []byte, dir Direction) []byte {
	result := make([]byte, sha256.Size)
	secret.Do(func() {
		key := deriveHMACKey(psk, dir)
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		copy(result, mac.Sum(nil))
	})
	return result
}

func Verify(psk, data, signature []byte, dir Direction) bool {
	expected := Sign(psk, data, dir)
	return subtle.ConstantTimeCompare(expected, signature) == 1
}

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

func Decrypt(psk, ciphertext []byte) ([]byte, error) {
	var result []byte
	var decErr error
	secret.Do(func() {
		key := deriveKey(psk)
		block, err := aes.NewCipher(key)
		if err != nil {
			decErr = errAuth
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			decErr = errAuth
			return
		}
		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			decErr = errAuth
			return
		}
		nonce := ciphertext[:nonceSize]
		enc := ciphertext[nonceSize:]
		plain, err := gcm.Open(nil, nonce, enc, nil)
		if err != nil {
			decErr = errAuth
			return
		}
		result = make([]byte, len(plain))
		copy(result, plain)
	})
	return result, decErr
}

func WithinSkew(ts int64, max time.Duration) bool {
	diff := time.Now().Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	return diff <= int64(max.Seconds())
}

func (p *Packet) signedPayload() []byte {
	buf := make([]byte, 0, 1+8+len(p.Payload))
	buf = append(buf, byte(p.Type))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(p.Timestamp))
	buf = append(buf, ts...)
	buf = append(buf, p.Payload...)
	return buf
}

func (p *Packet) Marshal(psk []byte, dir Direction) []byte {
	p.Signature = Sign(psk, p.signedPayload(), dir)

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

func UnmarshalPacket(psk, data []byte, dir Direction) (*Packet, error) {
	if len(data) < 1+8+2+32 {
		return nil, errAuth
	}

	p := &Packet{}
	p.Type = PacketType(data[0])
	p.Timestamp = int64(binary.BigEndian.Uint64(data[1:9]))

	payloadLen := int(binary.BigEndian.Uint16(data[9:11]))
	if len(data) < 11+payloadLen+32 {
		return nil, errAuth
	}
	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		copy(p.Payload, data[11:11+payloadLen])
	}

	p.Signature = make([]byte, 32)
	copy(p.Signature, data[11+payloadLen:11+payloadLen+32])

	if !Verify(psk, p.signedPayload(), p.Signature, dir) {
		return nil, errAuth
	}

	return p, nil
}
