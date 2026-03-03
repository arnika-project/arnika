package auth

import (
	"crypto/rand"
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
		{name: "INIT", pkt: Packet{Type: PacketInit, Timestamp: time.Now().Unix()}},
		{name: "COOKIE", pkt: Packet{Type: PacketCookie, Timestamp: time.Now().Unix(), Cookie: make([]byte, 40)}},
		{name: "DATA", pkt: Packet{Type: PacketData, Timestamp: time.Now().Unix(), Cookie: make([]byte, 40), Payload: []byte("encrypted-key-id-data")}},
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
			if len(parsed.Cookie) != len(tt.pkt.Cookie) {
				t.Fatalf("cookie length mismatch")
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

	pkt := Packet{Type: PacketInit, Timestamp: time.Now().Unix()}
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

	pkt := Packet{Type: PacketData, Timestamp: time.Now().Unix(), Cookie: make([]byte, 40), Payload: []byte("original-data")}
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

func TestGenerateVerifyCookie(t *testing.T) {
	serverSecret := make([]byte, 32)
	if _, err := rand.Read(serverSecret); err != nil {
		t.Fatalf("failed to generate server secret: %v", err)
	}

	clientIP := "192.168.1.100"
	timestamp := time.Now().Unix()

	cookie := GenerateCookie(serverSecret, clientIP, timestamp)
	if len(cookie) != 40 {
		t.Fatalf("expected 40-byte cookie, got %d", len(cookie))
	}
	if !VerifyCookie(serverSecret, clientIP, cookie, timestamp, 60) {
		t.Fatal("cookie verification failed for valid cookie")
	}
}

func TestCookieRejectsWrongIP(t *testing.T) {
	serverSecret := make([]byte, 32)
	rand.Read(serverSecret)

	timestamp := time.Now().Unix()
	cookie := GenerateCookie(serverSecret, "192.168.1.100", timestamp)

	if VerifyCookie(serverSecret, "10.0.0.1", cookie, timestamp, 60) {
		t.Fatal("cookie should be rejected for different IP")
	}
}

func TestCookieRejectsExpired(t *testing.T) {
	serverSecret := make([]byte, 32)
	rand.Read(serverSecret)

	oldTimestamp := time.Now().Add(-2 * time.Minute).Unix()
	cookie := GenerateCookie(serverSecret, "192.168.1.100", oldTimestamp)

	if VerifyCookie(serverSecret, "192.168.1.100", cookie, time.Now().Unix(), 60) {
		t.Fatal("cookie should be rejected when expired")
	}
}

func TestCookieRejectsWrongSecret(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	rand.Read(secret1)
	rand.Read(secret2)

	timestamp := time.Now().Unix()
	cookie := GenerateCookie(secret1, "192.168.1.100", timestamp)

	if VerifyCookie(secret2, "192.168.1.100", cookie, timestamp, 60) {
		t.Fatal("cookie should be rejected with wrong server secret")
	}
}

func TestCookieRejectsTruncated(t *testing.T) {
	serverSecret := make([]byte, 32)
	rand.Read(serverSecret)

	if VerifyCookie(serverSecret, "192.168.1.100", []byte{1, 2, 3}, time.Now().Unix(), 60) {
		t.Fatal("cookie should be rejected when truncated")
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
