package auth

import (
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	psk := []byte("test-psk-secret-key")
	data := []byte("hello world")

	sig := Sign(psk, data)
	if len(sig) != 32 {
		t.Fatalf("expected 32-byte signature, got %d", len(sig))
	}
	if !Verify(psk, data, sig) {
		t.Fatal("signature verification failed for valid data")
	}
}

func TestVerifyRejectsWrongPSK(t *testing.T) {
	psk1 := []byte("correct-psk")
	psk2 := []byte("wrong-psk")
	data := []byte("hello world")

	sig := Sign(psk1, data)
	if Verify(psk2, data, sig) {
		t.Fatal("signature verification should fail with wrong PSK")
	}
}

func TestVerifyRejectsTamperedData(t *testing.T) {
	psk := []byte("test-psk")
	data := []byte("original data")

	sig := Sign(psk, data)
	tampered := []byte("tampered data")
	if Verify(psk, tampered, sig) {
		t.Fatal("signature verification should fail with tampered data")
	}
}

func TestVerifyRejectsTruncatedSignature(t *testing.T) {
	psk := []byte("test-psk")
	data := []byte("data")

	sig := Sign(psk, data)
	if Verify(psk, data, sig[:16]) {
		t.Fatal("signature verification should fail with truncated signature")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	psk := []byte("test-encryption-key")
	plaintext := []byte("secret-key-id-12345")

	ciphertext, err := Encrypt(psk, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	decrypted, err := Decrypt(psk, ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptFailsWithWrongPSK(t *testing.T) {
	psk1 := []byte("correct-psk")
	psk2 := []byte("wrong-psk")
	plaintext := []byte("secret data")

	ciphertext, err := Encrypt(psk1, plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}
	_, err = Decrypt(psk2, ciphertext)
	if err == nil {
		t.Fatal("decryption should fail with wrong PSK")
	}
	if err.Error() != "authentication failed" {
		t.Fatalf("expected uniform error, got %q", err.Error())
	}
}

func TestDecryptUniformErrors(t *testing.T) {
	psk := []byte("test-psk")

	tests := []struct {
		name       string
		ciphertext []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{1, 2, 3}},
		{"garbage", []byte("this is not encrypted data at all and is very long")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(psk, tt.ciphertext)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != "authentication failed" {
				t.Fatalf("expected uniform error, got %q", err.Error())
			}
		})
	}
}

func TestPacketMarshalUnmarshal(t *testing.T) {
	psk := []byte("test-packet-psk")

	tests := []struct {
		name string
		pkt  Packet
	}{
		{name: "DATA", pkt: Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("encrypted-key-id-data")}},
		{name: "ACK", pkt: Packet{Type: PacketAck, Timestamp: time.Now().Unix()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.pkt.Marshal(psk)
			parsed, err := UnmarshalPacket(psk, data)
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if parsed.Type != tt.pkt.Type {
				t.Fatalf("type mismatch: got %c, want %c", parsed.Type, tt.pkt.Type)
			}
			if parsed.Timestamp != tt.pkt.Timestamp {
				t.Fatalf("timestamp mismatch")
			}
			if len(parsed.Payload) != len(tt.pkt.Payload) {
				t.Fatalf("payload length mismatch")
			}
		})
	}
}

func TestUnmarshalRejectsWrongPSK(t *testing.T) {
	psk1 := []byte("correct-psk")
	psk2 := []byte("wrong-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix()}
	data := pkt.Marshal(psk1)

	_, err := UnmarshalPacket(psk2, data)
	if err == nil {
		t.Fatal("unmarshal should fail with wrong PSK")
	}
	if err.Error() != "authentication failed" {
		t.Fatalf("expected uniform error, got %q", err.Error())
	}
}

func TestUnmarshalRejectsTamperedData(t *testing.T) {
	psk := []byte("test-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("original-data")}
	data := pkt.Marshal(psk)

	if len(data) > 20 {
		data[20] ^= 0xFF
	}
	_, err := UnmarshalPacket(psk, data)
	if err == nil {
		t.Fatal("unmarshal should fail with tampered data")
	}
}

func TestUnmarshalRejectsTruncated(t *testing.T) {
	psk := []byte("test-psk")

	_, err := UnmarshalPacket(psk, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("unmarshal should fail with truncated data")
	}
}

func TestDomainSeparation(t *testing.T) {
	psk := []byte("same-psk")
	aesKey := deriveKey(psk)
	hmacKey := deriveHMACKey(psk)

	if string(aesKey) == string(hmacKey) {
		t.Fatal("AES key and HMAC key must be different (domain separation)")
	}
}

// --- Security validation tests (attack vector coverage) ---

// TestReplayDetectable verifies that the timestamp in a packet is preserved
// faithfully so that the application layer can detect stale packets.
func TestReplayDetectable(t *testing.T) {
	psk := []byte("replay-psk")
	oldTime := time.Now().Add(-10 * time.Minute).Unix()

	pkt := Packet{Type: PacketData, Timestamp: oldTime, Payload: []byte("old-data")}
	data := pkt.Marshal(psk)

	parsed, err := UnmarshalPacket(psk, data)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	// The timestamp should be faithfully preserved so the caller can reject it.
	if parsed.Timestamp != oldTime {
		t.Fatal("timestamp must be preserved for replay detection")
	}
	// Verify it is actually old (application-layer check).
	if time.Now().Unix()-parsed.Timestamp < 300 {
		t.Fatal("expected stale timestamp to be detectable")
	}
}

// TestSignatureBindsToPacketType verifies that changing the packet type byte
// after signing invalidates the HMAC, preventing type-confusion attacks.
func TestSignatureBindsToPacketType(t *testing.T) {
	psk := []byte("type-confusion-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("payload")}
	data := pkt.Marshal(psk)

	// Flip type byte from 'D' to 'A' — should break HMAC
	data[0] = byte(PacketAck)

	_, err := UnmarshalPacket(psk, data)
	if err == nil {
		t.Fatal("changing packet type must invalidate signature")
	}
}

// TestSignatureBindsToTimestamp verifies that modifying the timestamp after
// signing invalidates the HMAC, preventing timestamp-manipulation attacks.
func TestSignatureBindsToTimestamp(t *testing.T) {
	psk := []byte("ts-tamper-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("data")}
	data := pkt.Marshal(psk)

	// Flip a bit in the timestamp field (bytes 1–8)
	data[5] ^= 0x01

	_, err := UnmarshalPacket(psk, data)
	if err == nil {
		t.Fatal("modifying timestamp must invalidate signature")
	}
}

// TestEncryptNonDeterministic verifies that AES-GCM encryption is
// non-deterministic: encrypting the same plaintext twice with the same PSK
// must produce different ciphertexts (due to random nonce).
func TestEncryptNonDeterministic(t *testing.T) {
	psk := []byte("nonce-psk")
	plaintext := []byte("same-input")

	ct1, err := Encrypt(psk, plaintext)
	if err != nil {
		t.Fatalf("encrypt 1 failed: %v", err)
	}
	ct2, err := Encrypt(psk, plaintext)
	if err != nil {
		t.Fatalf("encrypt 2 failed: %v", err)
	}
	if string(ct1) == string(ct2) {
		t.Fatal("two encryptions of the same plaintext must differ (random nonce)")
	}
}

// TestBitFlipInPayload verifies that flipping a single bit anywhere in the
// encrypted payload invalidates the HMAC before decryption is attempted.
func TestBitFlipInPayload(t *testing.T) {
	psk := []byte("bitflip-psk")
	payload := []byte("encrypted-key-material")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: payload}
	data := pkt.Marshal(psk)

	// Flip one bit in the payload region (starts at offset 11)
	data[15] ^= 0x02

	_, err := UnmarshalPacket(psk, data)
	if err == nil {
		t.Fatal("single bit flip in payload must invalidate signature")
	}
}

// TestBitFlipInSignature verifies that corrupting the signature itself causes
// rejection.
func TestBitFlipInSignature(t *testing.T) {
	psk := []byte("sigflip-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("data")}
	data := pkt.Marshal(psk)

	// Flip one bit in the last byte of the signature
	data[len(data)-1] ^= 0x01

	_, err := UnmarshalPacket(psk, data)
	if err == nil {
		t.Fatal("corrupted signature must be rejected")
	}
}

// TestUnmarshalRejectsInvalidLengthFields verifies that a packet with a
// payload_len larger than remaining data is rejected.
func TestUnmarshalRejectsInvalidLengthFields(t *testing.T) {
	psk := []byte("length-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("x")}
	data := pkt.Marshal(psk)

	// Overwrite payload_len to a huge value (0xFFFF) while keeping small data
	data[9] = 0xFF
	data[10] = 0xFF

	_, err := UnmarshalPacket(psk, data)
	if err == nil {
		t.Fatal("oversized payload_len must be rejected")
	}
}

// TestEmptyPSKStillProducesDeterministicKeys ensures that even an empty PSK
// produces consistent domain-separated keys (no panics, deterministic behavior).
func TestEmptyPSKStillProducesDeterministicKeys(t *testing.T) {
	psk := []byte{}
	k1 := deriveKey(psk)
	k2 := deriveKey(psk)
	h1 := deriveHMACKey(psk)
	h2 := deriveHMACKey(psk)

	if string(k1) != string(k2) {
		t.Fatal("deriveKey must be deterministic")
	}
	if string(h1) != string(h2) {
		t.Fatal("deriveHMACKey must be deterministic")
	}
	if string(k1) == string(h1) {
		t.Fatal("domain separation must hold even for empty PSK")
	}
}
