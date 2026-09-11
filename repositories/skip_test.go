package repositories

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newSKIPTestRepo builds a SKIPRepository for testing using the standard constructor.
func newSKIPTestRepo(baseURL string, maxRetries int) *SKIPRepository {
	auth := &KMSAuth{}
	return NewSKIPRepository(
		baseURL,
		"test-system",
		2*time.Second,
		maxRetries,
		time.Millisecond,
		auth,
	)
}

// TestSKIPRepository_GetNewKey_Success verifies the happy path for obtaining a new key.
func TestSKIPRepository_GetNewKey_Success(t *testing.T) {
	validKeyBytes := make([]byte, 32)
	for i := range validKeyBytes {
		validKeyBytes[i] = byte(i)
	}
	validKeyHex := hex.EncodeToString(validKeyBytes)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/key" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("remoteSystemID") != "test-system" {
			http.Error(w, "bad remoteSystemID", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(skipResponse{
			KeyID: "key-123",
			Key:   validKeyHex,
		})
	}))
	defer srv.Close()

	keyID, keyBytes, err := newSKIPTestRepo(srv.URL, 0).GetNewKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if keyID != "key-123" {
		t.Errorf("expected keyID 'key-123', got '%s'", keyID)
	}
	if len(keyBytes) != 32 {
		t.Errorf("expected key length 32, got %d", len(keyBytes))
	}
}

// TestSKIPRepository_GetKeyByID_Success verifies fetching a key by its hex ID.
func TestSKIPRepository_GetKeyByID_Success(t *testing.T) {
	validKeyBytes := make([]byte, 32)
	validKeyHex := hex.EncodeToString(validKeyBytes)
	validkeyIDHex := "0102030405060708"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/key/" + validkeyIDHex
		if r.URL.Path != expectedPath {
			http.Error(w, "not found path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("remoteSystemID") != "test-system" {
			http.Error(w, "bad remoteSystemID", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(skipResponse{
			KeyID: validkeyIDHex,
			Key:   validKeyHex,
		})
	}))
	defer srv.Close()

	keyIDPtr := &validkeyIDHex
	keyBytes, err := newSKIPTestRepo(srv.URL, 0).GetKeyByID(keyIDPtr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keyBytes) != 32 {
		t.Errorf("expected key length 32, got %d", len(keyBytes))
	}
}

// TestSKIPRepository_Non200IsAnError checks that non-2xx server responses result in errors.
func TestSKIPRepository_Non200IsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, "Internal Server Error")
	}))
	defer srv.Close()

	_, _, err := newSKIPTestRepo(srv.URL, 0).GetNewKey()
	if err == nil {
		t.Fatal("expected an error for 500 status, got nil")
	}
}

// TestSKIPRepository_MalformedOrShortKey ensures invalid or incorrectly sized keys are rejected.
func TestSKIPRepository_MalformedOrShortKey(t *testing.T) {
	t.Run("MalformedHex", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(skipResponse{
				KeyID: "key-123",
				Key:   "not-a-valid-hex-string-xyz",
			})
		}))
		defer srv.Close()

		_, _, err := newSKIPTestRepo(srv.URL, 0).GetNewKey()
		if err == nil {
			t.Fatal("expected error for malformed hex key, got nil")
		}
	})

	t.Run("ShortKey", func(t *testing.T) {
		shortKeyHex := hex.EncodeToString([]byte("too-short")) // méně než 32 bajtů
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(skipResponse{
				KeyID: "key-123",
				Key:   shortKeyHex,
			})
		}))
		defer srv.Close()

		_, _, err := newSKIPTestRepo(srv.URL, 0).GetNewKey()
		if err == nil {
			t.Fatal("expected error for short key length, got nil")
		}
	})
}

// TestSKIPRepository_keyIDValidation checks that empty, nil, or invalid hex keyIDs are rejected early.
func TestSKIPRepository_keyIDValidation(t *testing.T) {
	repo := newSKIPTestRepo("http://localhost", 0)

	t.Run("NilkeyID", func(t *testing.T) {
		_, err := repo.GetKeyByID(nil)
		if err == nil {
			t.Fatal("expected error for nil keyID, got nil")
		}
	})

	t.Run("EmptykeyID", func(t *testing.T) {
		emptyID := ""
		_, err := repo.GetKeyByID(&emptyID)
		if err == nil {
			t.Fatal("expected error for empty keyID, got nil")
		}
	})

	t.Run("InvalidHexkeyID", func(t *testing.T) {
		invalidID := "not-hex-!!spec"
		_, err := repo.GetKeyByID(&invalidID)
		if err == nil {
			t.Fatal("expected error for non-hex keyID, got nil")
		}
	})
}
