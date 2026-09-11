//go:build qkd_none

// Wiring for a binary built without a QKD key reader: the PSK comes from the
// PQC key agreement alone. Selected with the qkd_none build tag, which leaves
// net/http and crypto/tls out of the binary. See KEYCONTROL.md.

package main

import (
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/services"
)

// qkdCompiled is false here, which is what removes the key_id flow and the KMS
// client from the binary. Its twin lives in qkdkms.go.
const qkdCompiled = false

// getQKDService has no reader to build. main.go only calls it inside a branch
// guarded by qkdCompiled, so this body never runs; the declaration exists so
// that the call site still type-checks.
func getQKDService(*config.Config) *services.KeyReaderService { return nil }
