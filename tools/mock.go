package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const LOG = "%s [%d] %s %s from %s"
const DEBUG = "[DEBUG]"

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

type EncKeysPostRequest struct {
	Number *int `json:"number"`
	Size   *int `json:"size"`
}

type DecKeyIDEntry struct {
	KeyID string `json:"key_ID"`
}

type DecKeysPostRequest struct {
	KeyIDs []DecKeyIDEntry `json:"key_IDs"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type StatusResponse struct {
	SourceKMEID    string `json:"source_KME_ID"`
	TargetKMEID    string `json:"target_KME_ID"`
	MasterSAEID    string `json:"master_SAE_ID"`
	SlaveSAEID     string `json:"slave_SAE_ID"`
	KeySize        int    `json:"key_size"`
	StoredKeyCount int    `json:"stored_key_count"`
	MaxKeyCount    int    `json:"max_key_count"`
	MaxKeyPerReq   int    `json:"max_key_per_request"`
	MaxKeySize     int    `json:"max_key_size"`
	MinKeySize     int    `json:"min_key_size"`
	MaxSAEIDCount  int    `json:"max_SAE_ID_count"`
}

var keyStore = &KeyStore{
	keys: make(map[string]string),
}

var randomizer = rand.New(rand.NewSource(time.Now().UnixNano()))
var debugEnabled = isDebugEnabled()
var listenAddr = getListenAddr()

const (
	defaultKeyNumber          = 1
	defaultKeySize            = 256
	minStatusKeyCount         = 10
	maxStatusKeyCount         = 10000
	statusMaxKeyCount         = 100000
	statusMaxKeyPerRequest    = 1
	statusMaxKeySize          = 256
	statusMinKeySize          = 256
	statusMaxSAEIDCount       = 0
	statusRandomRangeExponent = 10
)

func main() {
	// Register handlers for both CONSA and CONSB
	http.HandleFunc("/api/v1/keys/CONSA/enc_keys", handleEncKeys)
	http.HandleFunc("/api/v1/keys/CONSA/dec_keys", handleDecKeys)
	http.HandleFunc("/api/v1/keys/CONSA/status", handleStatus)
	http.HandleFunc("/api/v1/keys/CONSB/enc_keys", handleEncKeys)
	http.HandleFunc("/api/v1/keys/CONSB/dec_keys", handleDecKeys)
	http.HandleFunc("/api/v1/keys/CONSB/status", handleStatus)
	log.Printf("======== QKD KMS Simulator ========")
	log.Printf("[CONF] listen address=%s (set LISTEN=host:port to override)", listenAddr)
	log.Printf("[CONF] supported key size=%d", defaultKeySize)
	log.Printf("[CONF] supported key number=%d", defaultKeyNumber)
	log.Printf("[CONF] available SAE:")
	log.Printf("[CONF]  /api/v1/keys/CONSA/enc_keys")
	log.Printf("[CONF]  /api/v1/keys/CONSA/dec_keys")
	log.Printf("[CONF]  /api/v1/keys/CONSA/status")
	log.Printf("[CONF]  /api/v1/keys/CONSB/enc_keys")
	log.Printf("[CONF]  /api/v1/keys/CONSB/dec_keys")
	log.Printf("[CONF]  /api/v1/keys/CONSB/status")
	log.Printf("[CONF] debug logging enabled=%t (set DEBUG=true to enable)", debugEnabled)
	log.Printf("===================================")

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		panic("[ERROR] failed starting server: " + err.Error())
	}
}

// handleEncKeys generates a new key and returns it
func handleEncKeys(w http.ResponseWriter, r *http.Request) {
	rawBody, err := readAndRestoreBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to read request body")
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
		return
	}
	debugLogRequest(r, rawBody)

	number, size, err := parseEncKeysRequest(r)
	if err != nil {
		if err.Error() == "method not allowed" {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
		return
	}

	if number != defaultKeyNumber {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported number: %d", number))
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
		return
	}

	if size != defaultKeySize {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported size: %d", size))
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// create an RFC4122-compatible UUID whose first 4 bytes are 0xff
	u := uuid.New()          // type uuid.UUID == [16]byte
	for i := 0; i < 4; i++ { // set first 4 bytes -> first 8 hex chars "ffffffff"
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

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		log.Printf("[ERROR] failed writing response: %v", err)
	}

	log.Printf(LOG, "[INFO]", http.StatusOK, r.Method, r.URL.Path, r.RemoteAddr)
}

// handleDecKeys retrieves a previously generated key by ID
func handleDecKeys(w http.ResponseWriter, r *http.Request) {
	rawBody, err := readAndRestoreBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to read request body")
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
		return
	}
	debugLogRequest(r, rawBody)

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	keyIDs, err := parseDecKeysRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
		return
	}

	keyID := keyIDs[0]

	// Retrieve the key
	keyStore.mu.RLock()
	keyMaterial, exists := keyStore.keys[keyID]
	keyStore.mu.RUnlock()

	if !exists {
		writeError(w, http.StatusNotFound, "key not found")
		log.Printf(LOG, "[INFO]", http.StatusNotFound, r.Method, r.URL.Path+"?key_ID="+keyID, r.RemoteAddr)
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

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		log.Printf("[ERROR] failed writing response: %v", err)
	}

	log.Printf(LOG, "[INFO]", http.StatusOK, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	rawBody, err := readAndRestoreBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to read request body")
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
		return
	}
	debugLogRequest(r, rawBody)

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	masterSAEID, slaveSAEID := parseSAEPair(r.URL.Path)
	if masterSAEID == "" || slaveSAEID == "" {
		writeError(w, http.StatusBadRequest, "unknown SAE")
		log.Printf(LOG, "[INFO]", http.StatusBadRequest, r.Method, r.URL.Path, r.RemoteAddr)
		return
	}

	response := StatusResponse{
		SourceKMEID:    masterSAEID,
		TargetKMEID:    slaveSAEID,
		MasterSAEID:    masterSAEID,
		SlaveSAEID:     slaveSAEID,
		KeySize:        defaultKeySize,
		StoredKeyCount: boundedDummyCount(masterSAEID, slaveSAEID, "stored"),
		MaxKeyCount:    boundedDummyCount(masterSAEID, slaveSAEID, "max"),
		MaxKeyPerReq:   statusMaxKeyPerRequest,
		MaxKeySize:     statusMaxKeySize,
		MinKeySize:     statusMinKeySize,
		MaxSAEIDCount:  statusMaxSAEIDCount,
	}

	if response.MaxKeyCount < response.StoredKeyCount {
		response.MaxKeyCount = response.StoredKeyCount
	}

	if err := writeJSON(w, http.StatusOK, response); err != nil {
		log.Printf("[ERROR] failed writing status response: %v", err)
	}

	log.Printf(LOG, "[INFO]", http.StatusOK, r.Method, r.URL.Path+getQueryParameters(r), r.RemoteAddr)
}

func parseEncKeysRequest(r *http.Request) (int, int, error) {
	switch r.Method {
	case http.MethodGet:
		return parseEncKeysGetParams(r)
	case http.MethodPost:
		return parseEncKeysPostBody(r)
	default:
		return 0, 0, fmt.Errorf("method not allowed")
	}
}

func parseEncKeysGetParams(r *http.Request) (int, int, error) {
	number := defaultKeyNumber
	size := defaultKeySize

	if rawNumber := strings.TrimSpace(r.URL.Query().Get("number")); rawNumber != "" {
		parsed, err := strconv.Atoi(rawNumber)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid number parameter")
		}
		number = parsed
	}

	if rawSize := strings.TrimSpace(r.URL.Query().Get("size")); rawSize != "" {
		parsed, err := strconv.Atoi(rawSize)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid size parameter")
		}
		size = parsed
	}

	return number, size, nil
}

func parseEncKeysPostBody(r *http.Request) (int, int, error) {
	defer func() { _ = r.Body.Close() }()

	request := EncKeysPostRequest{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return 0, 0, fmt.Errorf("invalid JSON payload")
	}

	number := defaultKeyNumber
	size := defaultKeySize
	if request.Number != nil {
		number = *request.Number
	}
	if request.Size != nil {
		size = *request.Size
	}

	return number, size, nil
}

func parseDecKeysRequest(r *http.Request) ([]string, error) {
	switch r.Method {
	case http.MethodGet:
		keyID := strings.TrimSpace(r.URL.Query().Get("key_ID"))
		if keyID == "" {
			return nil, fmt.Errorf("missing key_ID parameter")
		}
		return []string{keyID}, nil
	case http.MethodPost:
		defer func() { _ = r.Body.Close() }()
		request := DecKeysPostRequest{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			return nil, fmt.Errorf("invalid JSON payload")
		}
		if len(request.KeyIDs) == 0 {
			return nil, fmt.Errorf("missing key_IDs parameter")
		}
		if len(request.KeyIDs) != 1 {
			return nil, fmt.Errorf("only one key_ID is supported")
		}
		first := strings.TrimSpace(request.KeyIDs[0].KeyID)
		if first == "" {
			return nil, fmt.Errorf("key_IDs[0].key_ID cannot be empty")
		}
		return []string{first}, nil
	default:
		return nil, fmt.Errorf("method not allowed")
	}
}

func parseSAEPair(path string) (masterSAEID string, slaveSAEID string) {
	if strings.Contains(path, "/CONSA/") {
		return "CONSA", "CONSB"
	}
	if strings.Contains(path, "/CONSB/") {
		return "CONSB", "CONSA"
	}
	return "", ""
}

func boundedDummyCount(masterSAEID, slaveSAEID, field string) int {
	seedInput := fmt.Sprintf("%s|%s|%s", masterSAEID, slaveSAEID, field)
	hash := sha256.Sum256([]byte(seedInput))
	seed := int64(binary.BigEndian.Uint64(hash[:8]))

	localRandomizer := rand.New(rand.NewSource(seed))
	_ = statusRandomRangeExponent
	v := localRandomizer.Intn(maxStatusKeyCount-minStatusKeyCount+1) + minStatusKeyCount

	// Slight process-local variation while keeping strict bounds.
	offset := randomizer.Intn(11) - 5
	v += offset

	if v < minStatusKeyCount {
		return minStatusKeyCount
	}
	if v > maxStatusKeyCount {
		return maxStatusKeyCount
	}
	return v
}

func readAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

func debugLogRequest(r *http.Request, body []byte) {
	if !debugEnabled {
		return
	}

	log.Printf("%s [REQ] method=%s path=%s query=%s remote=%s", DEBUG, r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
	log.Printf("%s [REQ] headers=%v", DEBUG, r.Header)
	if len(body) == 0 {
		log.Printf("%s [REQ] body=<empty>", DEBUG)
		return
	}
	log.Printf("%s [REQ] body=%s", DEBUG, string(body))
}

func debugLogResponse(status int, contentType string, body []byte) {
	if !debugEnabled {
		return
	}

	log.Printf("%s [RESP] status=%d content_type=%s", DEBUG, status, contentType)
	if len(body) == 0 {
		log.Printf("%s [RESP] body=<empty>", DEBUG)
		return
	}
	log.Printf("%s [RESP] body=%s", DEBUG, string(body))
}

func isDebugEnabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("DEBUG")))
	return value == "true"
}

func getListenAddr() string {
	if addr := strings.TrimSpace(os.Getenv("LISTEN")); addr != "" {
		return addr
	}
	return ":8080"
}

func writeJSON(w http.ResponseWriter, status int, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	contentType := "application/json"
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		return err
	}

	debugLogResponse(status, contentType, body)
	return nil
}

func writeError(w http.ResponseWriter, status int, message string) {
	errResp := ErrorResponse{Message: message}
	body, err := json.Marshal(errResp)
	if err != nil {
		log.Printf("[ERROR] failed marshaling error response: %v", err)
		return
	}

	contentType := "application/json"
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		log.Printf("[ERROR] failed writing error response: %v", err)
	}
	debugLogResponse(status, contentType, body)
}

func getQueryParameters(r *http.Request) string {
	if r.URL.RawQuery != "" {
		return "?" + r.URL.RawQuery
	}
	return ""
}
