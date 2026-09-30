//go:build qkd_none

package main

import (
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/services"
)

const qkdCompiled = false

// getQKDService only keeps main.go type-checking; its caller sits behind qkdCompiled.
func getQKDService(*config.Config) *services.KeyReaderService { return nil }
