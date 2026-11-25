// Arnika rotates a WireGuard pre-shared key derived from a QKD key and a post-quantum key agreement with the peer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/secret"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/auth"
	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/hardening"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/repositories/pqchpke"
	"github.com/arnika-project/arnika/services"
	"github.com/arnika-project/arnika/transport"
)

var (
	Version string
	APPName string
)

// shouldSetPSKOnQKDFailure is false exactly when runPQCSetPSKLoop takes over the rotation instead.
func shouldSetPSKOnQKDFailure(cfg *config.Config) bool {
	return cfg.IsQKDRequired() || !cfg.UsePQC()
}

func shouldRunQKD(cfg *config.Config) bool {
	return qkdCompiled && !cfg.IsPQCOnly()
}

var lastQKDPSKAt atomic.Int64

// pskMu makes every build-then-write of the PSK on this node one step, so a QKD install and the PQC fallback cannot interleave.
var pskMu sync.Mutex

// setPSK installs a PSK from qkd and the latest PQC round and returns that round, empty when it used none.
func setPSK(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, qkd []byte, cfg *config.Config, logger *slog.Logger) (pqcRound string, ok bool) {
	pskMu.Lock()
	defer pskMu.Unlock()
	return setPSKLocked(keyWriter, pqc, qkd, cfg, logger)
}

func setPSKLocked(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, qkd []byte, cfg *config.Config, logger *slog.Logger) (pqcRound string, ok bool) {
	psk, pqcRound := buildPSK(keyWriter, latestPQC(pqc), qkd, cfg, logger)
	return pqcRound, psk != nil && writePSK(keyWriter, psk, qkd != nil, cfg, logger)
}

func latestPQC(pqc *services.KeyReaderService) func() (*services.Key, error) {
	return func() (*services.Key, error) { return pqc.GetNewKey() }
}

// roundPQC resolves the PQC round the peer derived its PSK from; empty means it used none.
func roundPQC(pqc *services.KeyReaderService, round string) func() (*services.Key, error) {
	return func() (*services.Key, error) {
		if round == "" {
			return nil, errors.New("the peer derived its PSK without a PQC key")
		}
		return pqc.GetKeyByID(round)
	}
}

// buildPSK invalidates the tunnel and returns nil when no valid PSK can be built, so a failed rotation never keeps the old key; pqcRound names the PQC round it used.
func buildPSK(keyWriter *services.KeyWriterService, pqcKeyFn func() (*services.Key, error), qkd []byte, cfg *config.Config, logger *slog.Logger) (psk []byte, pqcRound string) {
	if cfg.IsPQCOnly() {
		qkd = nil
	}
	if qkd != nil {
		psk = make([]byte, len(qkd))
		copy(psk, qkd)
	}
	var failure string
	var failureAttrs []any
	defer func() {
		if failure == "" {
			return
		}
		clear(psk)
		psk, pqcRound = nil, ""
		invalidate(keyWriter, logger, failure, failureAttrs...)
	}()
	if len(qkd) == 0 {
		if cfg.IsQKDRequired() {
			failure, failureAttrs = "no QKD key received", []any{"mode", cfg.Mode}
			return
		}
		if qkdCompiled && !cfg.IsPQCOnly() {
			logger.Warn("no QKD key, falling back to the PQC key", "mode", cfg.Mode)
		}
	}
	if cfg.UsePQC() {
		pqcKey, err := pqcKeyFn()
		if err != nil {
			if cfg.IsPQCRequired() {
				failure, failureAttrs = "failed to retrieve the PQC key", []any{"err", err, "mode", cfg.Mode}
				return
			}
			logger.Warn("no PQC key, falling back to the QKD key", "err", err, "mode", cfg.Mode)
		} else {
			defer pqcKey.Zero()
			var derivedKey []byte
			secret.Do(func() {
				derivedKey, err = kdf.DeriveKey(psk, pqcKey.Key)
			})
			if err != nil {
				failure, failureAttrs = "failed to derive the PSK", []any{"err", err, "mode", cfg.Mode}
				return
			}
			clear(psk)
			psk, pqcRound = derivedKey, pqcKey.ID
			if qkd == nil {
				logger.Info("HKDF derivation completed for the PQC-only key")
			} else {
				logger.Info("HKDF derivation completed for the QKD+PQC key")
			}
		}
	}
	if len(psk) == 0 {
		failure = "no key material available for a PSK"
		return
	}
	return psk, pqcRound
}

func writePSK(keyWriter *services.KeyWriterService, psk []byte, fromQKD bool, cfg *config.Config, logger *slog.Logger) bool {
	defer clear(psk)
	if err := keyWriter.SetPSK(psk); err != nil {
		invalidate(keyWriter, logger, "failed to configure the PSK on the WireGuard interface", "err", err)
		return false
	}
	if fromQKD {
		lastQKDPSKAt.Store(time.Now().UnixNano())
	}
	logger.Info("PSK configured on WireGuard interface", // message counted by ci/local-darwin/run.sh and ci/e2e
		"iface", cfg.WireGuardInterface, "peer", cfg.WireguardPeerPublicKey)
	return true
}

func invalidate(keyWriter *services.KeyWriterService, logger *slog.Logger, reason string, attrs ...any) {
	logger.Error(reason, attrs...)
	logger.Error("configuring a random PSK to invalidate the WireGuard session")
	if err := keyWriter.InvalidateTunnel(); err != nil {
		logger.Error("failed to configure the random PSK", "err", err)
	}
}

// intervalAt numbers intervals by clock so both peers share boundaries and counters without drift, and skips served, which the clock names again when the monotonic sleep wakes early.
func intervalAt(now time.Time, interval time.Duration, served uint64) (uint64, time.Time) {
	n := uint64(now.UnixNano() / int64(interval))
	if n == served {
		n++
	}
	return n, time.Unix(0, int64(n+1)*int64(interval))
}

// nextPQCSetPSKAt falls between two rounds on the scheduler's RoundSeconds grid, so both peers read the same round's key.
func nextPQCSetPSKAt(now time.Time, roundInterval, roundTimeout time.Duration) time.Time {
	secs := pqchpke.RoundSeconds(roundInterval)
	boundary := time.Unix((now.Unix()/secs+1)*secs, 0)
	quiet := time.Duration(secs)*time.Second - roundTimeout
	if quiet <= 0 {
		return boundary
	}
	return boundary.Add(quiet / 2)
}

func runPQCSetPSKLoop(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, cfg *config.Config, logger *slog.Logger, due func() bool) {
	for {
		time.Sleep(time.Until(nextPQCSetPSKAt(time.Now(), cfg.PQCRoundInterval, cfg.PQCRoundTimeout)))
		pskMu.Lock()
		if due == nil || due() {
			setPSKLocked(keyWriter, pqc, nil, cfg, logger)
		}
		pskMu.Unlock()
	}
}

func main() {
	logLevelWarning := setUpLogging()
	versionLong := flag.Bool("version", false, "print version and exit")
	versionShort := flag.Bool("v", false, "alias for version")
	help := flag.Bool("help", false, "print usage and exit")
	switch {
	case *versionLong || *versionShort:
		fmt.Printf("%s version %s\n", APPName, Version)
		os.Exit(0)
	case *help:
		flag.Usage()
		os.Exit(0)
	}

	if logLevelWarning != "" {
		slog.Warn(logLevelWarning)
	}
	for _, err := range hardening.Process() { // before config.Parse, so ARNIKA_PSK never sits in a dumpable, ptraceable or swappable process
		slog.Warn("process hardening incomplete", "err", err)
	}
	var secretErasure bool
	secret.Do(func() { secretErasure = secret.Enabled() })
	if !secretErasure {
		slog.Warn("runtime/secret erasure is inert on this platform: key material is not wiped from registers, stack or freed heap",
			"goos", runtime.GOOS, "goarch", runtime.GOARCH)
	}

	cfg, err := config.Parse()
	if err != nil {
		fatal("failed to parse the configuration", "err", err)
	}
	if err := cfg.ValidateKeySources(qkdCompiled); err != nil {
		fatal(err.Error())
	}
	if err := os.Unsetenv("ARNIKA_PSK"); err != nil {
		slog.Warn("failed to drop ARNIKA_PSK from the environment", "err", err)
	}
	setLogIdentity(cfg)
	logger := slog.Default()
	if os.Getenv("ARNIKA_ID") != "" {
		logger.Warn("ARNIKA_ID is ignored: the role follows from which of SERVER_ADDRESS and LISTEN_ADDRESS is set")
	}
	if !cfg.IsPrimary() {
		limit, budget, warning := transport.EffectiveRateLimit(cfg)
		if warning != "" {
			logger.Warn(warning)
		}
		cfg.RateLimit = limit
		logger.Info("per-IP rate limit", "limit", cfg.RateLimit, "window", cfg.RateWindow, "calculated_budget", budget)
	}
	cfg.PrintStartupConfig()
	done := make(chan bool)
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
		<-quit
		logger.Info("shutdown triggered")
		close(done)
	}()
	keyWriter, err := getKeyWriterService(cfg)
	if err != nil {
		fatal("failed to create the WireGuard key writer", "err", err)
	}
	dirOut, dirIn := auth.DirectionFor(cfg.IsPrimary())
	var pqc *services.KeyReaderService
	var pqcHandle transport.PQCHandler
	if cfg.UsePQC() {
		pqcService, pqcRun, handle, err := getPQCService(cfg, logger, dirOut, dirIn)
		if err != nil {
			fatal("failed to create the PQC key reader", "err", err)
		}
		pqc, pqcHandle = pqcService, handle
		pqcCtx, cancelPQC := context.WithCancel(context.Background())
		defer cancelPQC()
		go pqcRun(pqcCtx)
	}

	switch {
	case !shouldRunQKD(cfg):
		go runPQCSetPSKLoop(keyWriter, pqc, cfg, logger, nil)
	case cfg.UsePQC() && !cfg.IsQKDRequired():
		lastQKDPSKAt.Store(time.Now().UnixNano())
		go runPQCSetPSKLoop(keyWriter, pqc, cfg, logger, func() bool {
			if time.Since(time.Unix(0, lastQKDPSKAt.Load())) < 2*cfg.Interval { // not one: a single lost key often hits only one peer and would split their PSKs
				return false
			}
			logger.Warn("no QKD key, installing a PQC-only PSK",
				"no_key_for", 2*cfg.Interval, "mode", cfg.Mode)
			return true
		})
	}
	switch {
	case !cfg.IsPrimary():
		go runBackup(keyWriter, pqc, pqcHandle, cfg, dirOut, dirIn, done, logger)
	case shouldRunQKD(cfg):
		go runPrimary(getQKDService(cfg), keyWriter, pqc, cfg, dirOut, dirIn, logger)
	}
	<-done
	cfg.ZeroSecrets()
}

func runBackup(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, pqcHandle transport.PQCHandler, cfg *config.Config, dirOut, dirIn auth.Direction, done <-chan bool, logger *slog.Logger) {
	result := make(chan transport.KeyIDRequest, transport.QKDQueueDepth)
	if shouldRunQKD(cfg) {
		qkd := getQKDService(cfg)
		var gotKeyID atomic.Bool
		go transport.RunKeyIDWorker(done, result, func(r string) (string, bool) {
			gotKeyID.Store(true)
			logger.Info("requesting the QKD key for the peer's key_id", "key_id", r, "kms", cfg.KMSURL)
			key, err := qkd.GetKeyByID(r)
			if err != nil {
				logger.Error("failed to retrieve the QKD key for the peer's key_id", "key_id", r, "kms", cfg.KMSURL, "err", err)
				if shouldSetPSKOnQKDFailure(cfg) {
					setPSK(keyWriter, pqc, nil, cfg, logger)
				}
				return "", false
			}
			return setPSK(keyWriter, pqc, key.Key, cfg, logger)
		})
		go runBackupWatchdog(&gotKeyID, keyWriter, pqc, cfg, logger)
	} else {
		go transport.RunKeyIDWorker(done, result, func(r string) (string, bool) {
			logger.Warn("received a key_id from the peer, but QKD is disabled", "key_id", r, "mode", cfg.Mode)
			return "", false
		})
	}
	if err := transport.Serve(transport.ServerConfig{
		Address:      cfg.ListenAddress,
		PSK:          cfg.ArnikaPSK,
		DirOut:       dirOut,
		DirIn:        dirIn,
		KeyIDs:       result,
		Done:         done,
		PQC:          pqcHandle,
		RateLimit:    cfg.RateLimit,
		RateWindow:   cfg.RateWindow,
		MaxClockSkew: cfg.MaxClockSkew,
		Interval:     cfg.Interval,
		Log:          logger,
	}); err != nil {
		fatal("UDP server stopped", "err", err)
	}
}

func runPrimary(qkd *services.KeyReaderService, keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, cfg *config.Config, dirOut, dirIn auth.Direction, logger *slog.Logger) {
	served := ^uint64(0)
	for {
		intervalCounter, intervalEnd := intervalAt(time.Now(), cfg.Interval, served)
		served = intervalCounter
		rotateAsPrimary(qkd, keyWriter, pqc, cfg, dirOut, dirIn, intervalCounter, intervalEnd, logger)
		time.Sleep(time.Until(intervalEnd))
	}
}

func rotateAsPrimary(qkd *services.KeyReaderService, keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, cfg *config.Config, dirOut, dirIn auth.Direction, intervalCounter uint64, intervalEnd time.Time, logger *slog.Logger) {
	logger.Info("requesting a new QKD key", "kms", cfg.KMSURL)
	key, err := qkd.GetNewKey()
	for err != nil {
		logger.Error("failed to retrieve a QKD key", "kms", cfg.KMSURL, "err", err)
		if shouldSetPSKOnQKDFailure(cfg) {
			setPSK(keyWriter, pqc, nil, cfg, logger)
		}
		if time.Until(intervalEnd) <= cfg.KMSRetryInterval {
			return
		}
		time.Sleep(cfg.KMSRetryInterval)
		logger.Info("requesting a new QKD key", "kms", cfg.KMSURL)
		key, err = qkd.GetNewKey()
	}
	now := time.Now()
	logger.Info("serving this interval", "interval", intervalCounter)
	time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now)) // the backup drops a different key_id stamped no later than the last one
	skip := ""
	switch {
	case key.ID == "":
		skip = "the KMS returned an empty key_id, skipping this interval"
	case time.Until(intervalEnd) < cfg.ArnikaPeerTimeout: // sending would leave only the peer on the new key
		skip = "the KMS answered too late in the interval, skipping it"
	}
	if skip != "" {
		logger.Error(skip, "key_id", key.ID)
		if shouldSetPSKOnQKDFailure(cfg) {
			setPSK(keyWriter, pqc, nil, cfg, logger)
		}
		return
	}
	pskMu.Lock()
	probe, _ := buildPSK(keyWriter, latestPQC(pqc), key.Key, cfg, logger) // this side's MODE decision, before the peer installs anything
	pskMu.Unlock()
	if probe == nil {
		return
	}
	clear(probe)
	logger.Info("sending the key_id to the peer", "key_id", key.ID, "peer", cfg.ServerAddress)
	pqcRound, err := transport.SendKeyID(transport.ClientConfig{
		Address:      cfg.ServerAddress,
		PSK:          cfg.ArnikaPSK,
		DirOut:       dirOut,
		DirIn:        dirIn,
		KeyID:        key.ID,
		Timeout:      cfg.ArnikaPeerTimeout,
		Deadline:     intervalEnd,
		MaxClockSkew: cfg.MaxClockSkew,
		Log:          logger,
	})
	if err != nil {
		logger.Error("the peer did not confirm the key_id", "key_id", key.ID, "peer", cfg.ServerAddress, "err", err)
		if shouldSetPSKOnQKDFailure(cfg) {
			setPSK(keyWriter, pqc, nil, cfg, logger)
		}
		return
	}
	pskMu.Lock()
	defer pskMu.Unlock()
	if psk, _ := buildPSK(keyWriter, roundPQC(pqc, pqcRound), key.Key, cfg, logger); psk != nil { // the backup's round, not this side's latest, which may have moved on
		writePSK(keyWriter, psk, true, cfg, logger)
	}
}

// runBackupWatchdog takes the MODE failure path for every wall-clock interval in which no key_id reached the worker.
func runBackupWatchdog(gotKeyID *atomic.Bool, keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, cfg *config.Config, logger *slog.Logger) {
	served := ^uint64(0)
	for {
		intervalCounter, intervalEnd := intervalAt(time.Now(), cfg.Interval, served)
		served = intervalCounter
		logger.Info("waiting for a key_id from the peer", "interval", intervalCounter)
		time.Sleep(time.Until(intervalEnd))
		if !gotKeyID.Swap(false) && shouldSetPSKOnQKDFailure(cfg) {
			logger.Error("no key_id from the peer", "interval", intervalCounter)
			setPSK(keyWriter, pqc, nil, cfg, logger)
		}
	}
}
