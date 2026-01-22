package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/google/uuid"
)

const Port = "8080"

const LOG = "%s [%d] %s %s from %s"

type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]string // key_ID -> key
}

type KeyResponse struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	KeyID string `json:"key_ID"`
	Key   string `json:"key"`
}

var keyStore = &KeyStore{
	keys: make(map[string]string),
}

func main() {
	// Register handlers for both CONSA and CONSB
	http.HandleFunc("/api/v1/keys/CONSA/enc_keys", handleEncKeys)
	http.HandleFunc("/api/v1/keys/CONSA/dec_keys", handleDecKeys)
	http.HandleFunc("/api/v1/keys/CONSB/enc_keys", handleEncKeys)
	http.HandleFunc("/api/v1/keys/CONSB/dec_keys", handleDecKeys)
	log.Printf("======== QKD KMS Simulator ========")
	log.Printf("[CONF] listening on port:%s", Port)
	log.Printf("[CONF] supported key size=256")
	log.Printf("[CONF] supported key number=1")
	log.Printf("[CONF] available SAE:")
	log.Printf("[CONF]  /api/v1/keys/CONSA/enc_keys")
	log.Printf("[CONF]  /api/v1/keys/CONSA/dec_keys")
	log.Printf("[CONF]  /api/v1/keys/CONSB/enc_keys")
	log.Printf("[CONF]  /api/v1/keys/CONSB/dec_keys")
	log.Printf("===================================")

	if err := http.ListenAndServe(":"+Port, nil); err != nil {
		panic("[ERROR] failed starting server: " + err.Error())
	}
}

// handleEncKeys generates a new key and returns it
func handleEncKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "[ERROR] Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// create an RFC4122-compatible UUID whose first 4 bytes are 0xff
	u := uuid.New()             // type uuid.UUID == [16]byte
	for i := 0; i < 4; i++ {    // set first 4 bytes -> first 8 hex chars "ffffffff"
		u[i] = 0xff
	}
	// ensure RFC4122 v4 version and variant bits are correct
	u[6] = (u[6] & 0x0f) | 0x40 // set version = 4
	u[8] = (u[8] & 0x3f) | 0x80 // set variant = RFC4122 (10xx)

	keyID := u.String() // e.g. "ffffffff-xxxx-4xxx-8xxx-xxxxxxxxxxxx"

	// Generate key material as SHA256 hash of the UUID
	hash := sha256.Sum256([]byte(keyID))
	keyMaterial := base64.StdEncoding.EncodeToString(hash[:])

	// Store the key
	keyStore.mu.Lock()
	keyStore.keys[keyID] = keyMaterial
	keyStore.mu.Unlock()

	// Return the key
	response := KeyResponse{
		Keys: []Key{
			{
				KeyID: keyID,
				Key:   keyMaterial,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[ERROR] failed encoding response: %v", err)
	}

	log.Printf(LOG, "[INFO]", http.StatusOK, r.Method, r.URL.Path, r.RemoteAddr)
}

// handleDecKeys retrieves a previously generated key by ID
func handleDecKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "[ERROR] method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get key_ID from query parameter
	keyID := r.URL.Query().Get("key_ID")
	if keyID == "" {
		http.Error(w, "[ERROR] missing key_ID parameter", http.StatusBadRequest)
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path , r.RemoteAddr)
		return
	}

	// Retrieve the key
	keyStore.mu.RLock()
	keyMaterial, exists := keyStore.keys[keyID]
	keyStore.mu.RUnlock()

	if !exists {
		http.Error(w, "[ERROR] key not found", http.StatusNotFound)
		log.Printf(LOG, "[INFO]", http.StatusNotFound, r.Method, r.URL.Path+"?key_ID="+keyID , r.RemoteAddr)
		return
	}

	// Return the key
	response := KeyResponse{
		Keys: []Key{
			{
				KeyID: keyID,
				Key:   keyMaterial,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[ERROR] failed encoding response: %v", err)
	}

	log.Printf(LOG, "[INFO]", http.StatusOK, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
}

func getQueryParameters(r *http.Request) string {
	if r.URL.RawQuery != "" {
		return "?" + r.URL.RawQuery
	}
	return ""
}
