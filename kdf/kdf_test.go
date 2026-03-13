package kdf

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	qkd := []byte("0123456789abcdef0123456789abcdef")
	pqc := []byte("fedcba9876543210fedcba9876543210")

	derived, err := DeriveKey(qkd, pqc)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(derived) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(derived))
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	qkd := []byte("deterministic-qkd-key-material!!")
	pqc := []byte("deterministic-pqc-key-material!!")

	d1, err := DeriveKey(qkd, pqc)
	if err != nil {
		t.Fatalf("first DeriveKey failed: %v", err)
	}
	d2, err := DeriveKey(qkd, pqc)
	if err != nil {
		t.Fatalf("second DeriveKey failed: %v", err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatal("DeriveKey is not deterministic")
	}
}

func TestDeriveKeyDifferentInputs(t *testing.T) {
	qkd := []byte("0123456789abcdef0123456789abcdef")
	pqc1 := []byte("fedcba9876543210fedcba9876543210")
	pqc2 := []byte("different-pqc-key-material-here!")

	d1, err := DeriveKey(qkd, pqc1)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	d2, err := DeriveKey(qkd, pqc2)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if bytes.Equal(d1, d2) {
		t.Fatal("different PQC keys must produce different derived keys")
	}
}

func TestDeriveKeyDoesNotMutateInputs(t *testing.T) {
	qkdOrig := []byte("qkd-key-material-for-test-32b!!")
	pqcOrig := []byte("pqc-key-material-for-test-32b!!")

	qkd := make([]byte, len(qkdOrig))
	copy(qkd, qkdOrig)
	pqc := make([]byte, len(pqcOrig))
	copy(pqc, pqcOrig)

	_, err := DeriveKey(qkd, pqc)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if !bytes.Equal(qkd, qkdOrig) {
		t.Fatal("DeriveKey mutated the QKD input slice")
	}
	if !bytes.Equal(pqc, pqcOrig) {
		t.Fatal("DeriveKey mutated the PQC input slice")
	}
}
