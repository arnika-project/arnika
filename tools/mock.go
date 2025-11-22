package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

const Port = "8080"

const LOG = "[%d] %s %s"

type KeyResponse struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	KeyID string `json:"key_ID"`
	Key   string `json:"key"`
}

var counter atomic.Int64

func main() {
	// Register handlers for both CONSA and CONSB
	http.HandleFunc("/api/v1/keys/CONSA/enc_keys", handleEncKeys)
	http.HandleFunc("/api/v1/keys/CONSA/dec_keys", handleDecKeys)
	http.HandleFunc("/api/v1/keys/CONSB/enc_keys", handleEncKeys)
	http.HandleFunc("/api/v1/keys/CONSB/dec_keys", handleDecKeys)

	log.Printf("QKD Simulator starting on port %s", Port)
	if err := http.ListenAndServe(":"+Port, nil); err != nil {
		panic("error starting server: " + err.Error())
	}
}

// handleEncKeys generates a new key and returns it
func handleEncKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Generate reproducible key ID using counter in UUIDv4 format
	// Format: ffffffff-xxxx-4xxx-8xxx-xxxxxxxxxxxx with counter at the end
	// UUIDv4: version 4 (0100) in position 12-15, variant (10xx) in position 16-17
	keyID := fmt.Sprintf("ffffffff-ffff-4fff-8fff-%012d", counter.Add(1))
	
	// Generate key material as SHA256 hash of the key ID
	hash := sha256.Sum256([]byte(keyID))
	keyMaterial := base64.StdEncoding.EncodeToString(hash[:])

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
		log.Printf("Error encoding response: %v", err)
	}

	log.Printf(LOG, http.StatusOK, r.Method, r.URL.Path)
}

// handleDecKeys retrieves a previously generated key by ID
func handleDecKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get key_ID from query parameter
	keyID := r.URL.Query().Get("key_ID")
	if keyID == "" {
		http.Error(w, "Missing key_ID parameter", http.StatusBadRequest)
		log.Printf(LOG, http.StatusBadRequest, r.Method, r.URL.Path)
		return
	}

	// Regenerate the key material from the key ID (deterministic)
	hash := sha256.Sum256([]byte(keyID))
	keyMaterial := base64.StdEncoding.EncodeToString(hash[:])

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
		log.Printf("Error encoding response: %v", err)
	}

	log.Printf(LOG, http.StatusOK, r.Method, r.URL.Path+getQueryParameters(r))
}

func getQueryParameters(r *http.Request) string {
	if r.URL.RawQuery != "" {
		return "?" + r.URL.RawQuery
	}
	return ""
}
