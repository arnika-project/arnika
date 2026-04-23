package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func resetKeyStore() {
	keyStore.mu.Lock()
	defer keyStore.mu.Unlock()
	keyStore.keys = make(map[string]string)
}

func TestEncKeysGetReturnsKey(t *testing.T) {
	resetKeyStore()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/CONSA/enc_keys?number=1&size=256", nil)
	w := httptest.NewRecorder()

	handleEncKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}

	resp := KeyResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.Keys) != 1 {
		t.Fatalf("expected one key, got %d", len(resp.Keys))
	}
	if resp.Keys[0].KeyID == "" || resp.Keys[0].Key == "" {
		t.Fatalf("expected non-empty key_ID and key")
	}
}

func TestEncKeysPostReturnsKey(t *testing.T) {
	resetKeyStore()
	body := `{"number":1,"size":256}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/CONSA/enc_keys", strings.NewReader(body))
	w := httptest.NewRecorder()

	handleEncKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}

	resp := KeyResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.Keys) != 1 || resp.Keys[0].KeyID == "" {
		t.Fatalf("expected exactly one generated key")
	}
}

func TestEncKeysPostRejectsUnsupportedSize(t *testing.T) {
	resetKeyStore()
	body := `{"number":1,"size":128}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/CONSA/enc_keys", strings.NewReader(body))
	w := httptest.NewRecorder()

	handleEncKeys(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestEncKeysResponseDoesNotContainExtensionFields(t *testing.T) {
	resetKeyStore()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/CONSA/enc_keys", strings.NewReader(`{"number":1,"size":256}`))
	w := httptest.NewRecorder()

	handleEncKeys(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}

	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("failed to decode raw response payload: %v", err)
	}

	keys, ok := raw["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected keys array with one element, got %+v", raw["keys"])
	}

	entry, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("expected key entry object, got %+v", keys[0])
	}

	if _, exists := entry["key_ID_extension"]; exists {
		t.Fatalf("key_ID_extension must not be present")
	}
	if _, exists := entry["key_extension"]; exists {
		t.Fatalf("key_extension must not be present")
	}
	if _, exists := entry["key_container_extension"]; exists {
		t.Fatalf("key_container_extension must not be present")
	}
}

func TestDecKeysPostReturnsStoredKey(t *testing.T) {
	resetKeyStore()
	encReq := httptest.NewRequest(http.MethodGet, "/api/v1/keys/CONSA/enc_keys?number=1&size=256", nil)
	encW := httptest.NewRecorder()
	handleEncKeys(encW, encReq)
	if encW.Code != http.StatusOK {
		t.Fatalf("failed to create key: status=%d body=%s", encW.Code, encW.Body.String())
	}

	encResp := KeyResponse{}
	if err := json.Unmarshal(encW.Body.Bytes(), &encResp); err != nil {
		t.Fatalf("failed to parse enc response: %v", err)
	}
	keyID := encResp.Keys[0].KeyID

	decBody := `{"key_IDs":[{"key_ID":"` + keyID + `"}]}`
	decReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/CONSA/dec_keys", strings.NewReader(decBody))
	decW := httptest.NewRecorder()
	handleDecKeys(decW, decReq)

	if decW.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", decW.Code, decW.Body.String())
	}

	decResp := KeyResponse{}
	if err := json.Unmarshal(decW.Body.Bytes(), &decResp); err != nil {
		t.Fatalf("failed to parse dec response: %v", err)
	}
	if len(decResp.Keys) != 1 || decResp.Keys[0].KeyID != keyID {
		t.Fatalf("expected returned key_ID=%s, got %+v", keyID, decResp.Keys)
	}
}

func TestDecKeysPostRejectsMultipleKeyIDs(t *testing.T) {
	resetKeyStore()
	body := `{"key_IDs":[{"key_ID":"id-1"},{"key_ID":"id-2"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/CONSA/dec_keys", strings.NewReader(body))
	w := httptest.NewRecorder()

	handleDecKeys(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", w.Code, w.Body.String())
	}
	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("expected JSON error response, got body=%s", w.Body.String())
	}
	if !strings.Contains(errResp.Message, "only one key_ID is supported") {
		t.Fatalf("expected single-key support error message, got message=%s", errResp.Message)
	}
}

func TestStatusResponseHasExpectedFieldsAndBounds(t *testing.T) {
	resetKeyStore()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/CONSA/status", nil)
	w := httptest.NewRecorder()

	handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}

	resp := StatusResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal status response: %v", err)
	}

	if resp.SourceKMEID != "CONSA" || resp.TargetKMEID != "CONSB" {
		t.Fatalf("unexpected source/target IDs: %+v", resp)
	}
	if resp.KeySize != 256 || resp.MaxKeyPerReq != 1 || resp.MinKeySize != 256 || resp.MaxKeySize != 256 {
		t.Fatalf("unexpected static key settings: %+v", resp)
	}
	if resp.StoredKeyCount < 10 || resp.StoredKeyCount > 10000 {
		t.Fatalf("stored_key_count out of bounds: %d", resp.StoredKeyCount)
	}
	if resp.MaxKeyCount < 10 || resp.MaxKeyCount > 10000 {
		t.Fatalf("max_key_count out of bounds: %d", resp.MaxKeyCount)
	}
	if resp.MaxKeyCount < resp.StoredKeyCount {
		t.Fatalf("expected max_key_count >= stored_key_count, got max=%d stored=%d", resp.MaxKeyCount, resp.StoredKeyCount)
	}

	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("failed to decode raw status payload: %v", err)
	}
	if _, exists := raw["status_extension"]; exists {
		t.Fatalf("status_extension must not be present in status response")
	}
}
