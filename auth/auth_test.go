package auth

import (
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	psk := []byte("test-psk-secret-key")
	data := []byte("hello world")

	sig := Sign(psk, data, DirEven)
	if len(sig) != 32 {
		t.Fatalf("expected 32-byte signature, got %d", len(sig))
	}
	if !Verify(psk, data, sig, DirEven) {
		t.Fatal("signature verification failed for valid data")
	}
}

func TestVerifyRejectsWrongPSK(t *testing.T) {
	psk1 := []byte("correct-psk")
	psk2 := []byte("wrong-psk")
	data := []byte("hello world")

	sig := Sign(psk1, data, DirEven)
	if Verify(psk2, data, sig, DirEven) {
		t.Fatal("signature verification should fail with wrong PSK")
	}
}

func TestVerifyRejectsTamperedData(t *testing.T) {
	psk := []byte("test-psk")
	data := []byte("original data")

	sig := Sign(psk, data, DirEven)
	tampered := []byte("tampered data")
	if Verify(psk, tampered, sig, DirEven) {
		t.Fatal("signature verification should fail with tampered data")
	}
}

func TestVerifyRejectsTruncatedSignature(t *testing.T) {
	psk := []byte("test-psk")
	data := []byte("data")

	sig := Sign(psk, data, DirEven)
	if Verify(psk, data, sig[:16], DirEven) {
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
			data := tt.pkt.Marshal(psk, DirEven)
			parsed, err := UnmarshalPacket(psk, data, DirEven)
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
	data := pkt.Marshal(psk1, DirEven)

	_, err := UnmarshalPacket(psk2, data, DirEven)
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
	data := pkt.Marshal(psk, DirEven)

	if len(data) > 20 {
		data[20] ^= 0xFF
	}
	_, err := UnmarshalPacket(psk, data, DirEven)
	if err == nil {
		t.Fatal("unmarshal should fail with tampered data")
	}
}

func TestUnmarshalRejectsTruncated(t *testing.T) {
	psk := []byte("test-psk")

	_, err := UnmarshalPacket(psk, []byte{1, 2, 3}, DirEven)
	if err == nil {
		t.Fatal("unmarshal should fail with truncated data")
	}
}

func TestDomainSeparation(t *testing.T) {
	psk := []byte("same-psk")
	aesKey := deriveKey(psk)
	hmacKey := deriveHMACKey(psk, DirEven)

	if string(aesKey) == string(hmacKey) {
		t.Fatal("AES key and HMAC key must be different (domain separation)")
	}

	if string(deriveHMACKey(psk, DirEven)) == string(deriveHMACKey(psk, DirOdd)) {
		t.Fatal("the two directions must derive different HMAC keys")
	}
}

func TestReplayDetectable(t *testing.T) {
	psk := []byte("replay-psk")
	oldTime := time.Now().Add(-10 * time.Minute).Unix()

	pkt := Packet{Type: PacketData, Timestamp: oldTime, Payload: []byte("old-data")}
	data := pkt.Marshal(psk, DirEven)

	parsed, err := UnmarshalPacket(psk, data, DirEven)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if parsed.Timestamp != oldTime {
		t.Fatal("timestamp must be preserved for replay detection")
	}
	if time.Now().Unix()-parsed.Timestamp < 300 {
		t.Fatal("expected stale timestamp to be detectable")
	}
}

func TestSignatureBindsToPacketType(t *testing.T) {
	psk := []byte("type-confusion-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("payload")}
	data := pkt.Marshal(psk, DirEven)

	data[0] = byte(PacketAck)

	_, err := UnmarshalPacket(psk, data, DirEven)
	if err == nil {
		t.Fatal("changing packet type must invalidate signature")
	}
}

func TestSignatureBindsToTimestamp(t *testing.T) {
	psk := []byte("ts-tamper-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("data")}
	data := pkt.Marshal(psk, DirEven)

	data[5] ^= 0x01

	_, err := UnmarshalPacket(psk, data, DirEven)
	if err == nil {
		t.Fatal("modifying timestamp must invalidate signature")
	}
}

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

func TestBitFlipInPayload(t *testing.T) {
	psk := []byte("bitflip-psk")
	payload := []byte("encrypted-key-material")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: payload}
	data := pkt.Marshal(psk, DirEven)

	data[15] ^= 0x02

	_, err := UnmarshalPacket(psk, data, DirEven)
	if err == nil {
		t.Fatal("single bit flip in payload must invalidate signature")
	}
}

func TestBitFlipInSignature(t *testing.T) {
	psk := []byte("sigflip-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("data")}
	data := pkt.Marshal(psk, DirEven)

	data[len(data)-1] ^= 0x01

	_, err := UnmarshalPacket(psk, data, DirEven)
	if err == nil {
		t.Fatal("corrupted signature must be rejected")
	}
}

func TestUnmarshalRejectsInvalidLengthFields(t *testing.T) {
	psk := []byte("length-psk")

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Payload: []byte("x")}
	data := pkt.Marshal(psk, DirEven)

	data[9] = 0xFF
	data[10] = 0xFF

	_, err := UnmarshalPacket(psk, data, DirEven)
	if err == nil {
		t.Fatal("oversized payload_len must be rejected")
	}
}

func TestEmptyPSKStillProducesDeterministicKeys(t *testing.T) {
	psk := []byte{}
	k1 := deriveKey(psk)
	k2 := deriveKey(psk)
	h1 := deriveHMACKey(psk, DirEven)
	h2 := deriveHMACKey(psk, DirEven)

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

func TestDirectionForParity(t *testing.T) {
	outA, inA := DirectionFor(9999)
	outB, inB := DirectionFor(9998)

	if outA == outB {
		t.Fatalf("peers with different ID parity must sign with different labels, both got %q", outA)
	}
	if outA != inB || outB != inA {
		t.Fatalf("labels must pair up: A out=%q in=%q, B out=%q in=%q", outA, inA, outB, inB)
	}
}

func TestReflectedPacketFailsAtSender(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	outA, inA := DirectionFor(9999)

	pkt := &Packet{Type: PacketData, Timestamp: 1234567890, Payload: []byte("key-id")}
	wire := pkt.Marshal(psk, outA)

	if _, err := UnmarshalPacket(psk, wire, outA); err != nil {
		t.Fatalf("peer should accept a correctly directed packet: %v", err)
	}

	if _, err := UnmarshalPacket(psk, wire, inA); err == nil {
		t.Fatal("reflected packet verified at its own sender; direction separation is not working")
	}
}

func TestPacketPQCRoundTrip(t *testing.T) {
	psk := []byte("test-psk-at-least-32-bytes-long!!")
	if PacketPQC == PacketData || PacketPQC == PacketAck {
		t.Fatal("PacketPQC must be distinct from PacketData and PacketAck")
	}

	payload := []byte("frame bytes")
	pkt := &Packet{Type: PacketPQC, Timestamp: 1234567890, Payload: payload}
	parsed, err := UnmarshalPacket(psk, pkt.Marshal(psk, DirEven), DirEven)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.Type != PacketPQC {
		t.Errorf("type = %q, want %q", parsed.Type, PacketPQC)
	}
	if string(parsed.Payload) != string(payload) {
		t.Errorf("payload = %q, want %q", parsed.Payload, payload)
	}
}
