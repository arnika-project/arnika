package repositories

import (
	"net/http"
	"time"
)

type WireguardMikrotikRepository struct {
	baseUrl          string
	maxRetries       int
	backoffBaseDelay time.Duration
	conn             *http.Client
}
