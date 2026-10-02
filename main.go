// Arnika rotates a WireGuard pre-shared key derived from a QKD key and a post-quantum key agreement with the peer.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/arnika-project/arnika/auth"
	"log/slog"
	"strconv"

	"os"

	"runtime"
	"runtime/secret"
	"sync/atomic"
	"time"

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

func setPSK(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, qkd []byte, cfg *config.Config, logger *slog.Logger) bool {
	psk := buildPSK(keyWriter, pqc, qkd, cfg, logger)
	return psk != nil && writePSK(keyWriter, psk, qkd != nil, cfg, logger)
}

// buildPSK invalidates the tunnel and returns nil when no valid PSK can be built, so a failed rotation never keeps the old key.
func buildPSK(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, qkd []byte, cfg *config.Config, logger *slog.Logger) (psk []byte) {
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
		psk = nil
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
		pqcKey, err := pqc.GetNewKey()
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
			psk = derivedKey
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
	return psk
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
		if due != nil && !due() {
			continue
		}
		setPSK(keyWriter, pqc, nil, cfg, logger)
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
	limit, budget, warning := transport.EffectiveRateLimit(cfg)
	if warning != "" {
		slog.Warn(warning)
	}
	cfg.RateLimit = limit
	arnikaID, _ := strconv.Atoi(cfg.ArnikaID)
	setLogIdentity(arnikaID)
	arnikaLog := slog.Default()
	primaryLog := arnikaLog.With("role", "primary")
	backupLog := arnikaLog.With("role", "backup")
	arnikaLog.Info("per-IP rate limit",
		"limit", cfg.RateLimit, "window", cfg.RateWindow, "calculated_budget", budget)
	cfg.PrintStartupConfig()
	interval := cfg.Interval
	done := make(chan bool)
	var peerSentKeyID atomic.Bool
	result := make(chan transport.KeyIDRequest, transport.QKDQueueDepth)
	keyWriter, err := getKeyWriterService(cfg)
	if err != nil {
		fatal("failed to create the WireGuard key writer", "err", err)
	}
	dirOut, dirIn := auth.DirectionFor(arnikaID)
	var pqc *services.KeyReaderService
	var pqcHandle transport.PQCHandler
	if cfg.UsePQC() {
		pqcService, pqcRun, handle, err := getPQCService(cfg, arnikaLog, dirOut, dirIn)
		if err != nil {
			fatal("failed to create the PQC key reader", "err", err)
		}
		pqc, pqcHandle = pqcService, handle
		pqcCtx, cancelPQC := context.WithCancel(context.Background())
		defer cancelPQC()
		go pqcRun(pqcCtx)
	}

	go func() {
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
			Log:          arnikaLog,
		}); err != nil {
			fatal("UDP server stopped", "err", err)
		}
	}()
	if shouldRunQKD(cfg) {
		if cfg.UsePQC() && !cfg.IsQKDRequired() {
			lastQKDPSKAt.Store(time.Now().UnixNano())
			go runPQCSetPSKLoop(keyWriter, pqc, cfg, arnikaLog, func() bool {
				if time.Since(time.Unix(0, lastQKDPSKAt.Load())) < 2*interval { // not one: a single lost key often hits only one peer and would split their PSKs
					return false
				}
				arnikaLog.Warn("no QKD key, installing a PQC-only PSK",
					"no_key_for", 2*interval, "mode", cfg.Mode)
				return true
			})
		}
		qkd := getQKDService(cfg)
		go transport.RunKeyIDWorker(done, result, func(r string) bool {
			peerSentKeyID.Store(true)
			backupLog.Info("requesting the QKD key for the peer's key_id", "key_id", r, "kms", cfg.KMSURL)
			key, err := qkd.GetKeyByID(r)
			if err != nil {
				backupLog.Error("failed to retrieve the QKD key for the peer's key_id", "key_id", r, "kms", cfg.KMSURL, "err", err)
				if shouldSetPSKOnQKDFailure(cfg) {
					setPSK(keyWriter, pqc, nil, cfg, backupLog)
				}
				return false
			}
			return setPSK(keyWriter, pqc, key.Key, cfg, backupLog)
		})
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			var intervalCounter uint64
			for {
				ticker.Reset(interval)
				intervalEnd := time.Now().Add(interval)
				backup := !cfg.IsPrimary(intervalCounter)
				if backup {
					backupLog.Info("waiting for a key_id from the peer", "interval", intervalCounter)
				} else {
					peerSentKeyID.Store(false)
					primaryLog.Info("requesting a new QKD key", "kms", cfg.KMSURL)
					key, err := qkd.GetNewKey()
					if err != nil {
						primaryLog.Error("failed to retrieve a QKD key", "kms", cfg.KMSURL, "err", err)
						ticker.Reset(cfg.KMSRetryInterval)
						if shouldSetPSKOnQKDFailure(cfg) {
							setPSK(keyWriter, pqc, nil, cfg, primaryLog)
						}
					} else {
						now := time.Now()
						nextTick := now.Truncate(time.Second).Add(time.Second)
						primaryLog.Info("serving this interval", "interval", intervalCounter)
						time.Sleep(nextTick.Sub(now))
						peerIsPrimaryToo := peerSentKeyID.Swap(false)
						if !peerIsPrimaryToo {
							if key.ID == "" {
								primaryLog.Error("the KMS returned an empty key_id, skipping this interval")
								if shouldSetPSKOnQKDFailure(cfg) {
									setPSK(keyWriter, pqc, nil, cfg, primaryLog)
								}
							} else {
								psk := buildPSK(keyWriter, pqc, key.Key, cfg, primaryLog)
								primaryLog.Info("sending the key_id to the peer", "key_id", key.ID, "peer", cfg.ServerAddress)
								err = transport.SendKeyID(transport.ClientConfig{
									Address:      cfg.ServerAddress,
									PSK:          cfg.ArnikaPSK,
									DirOut:       dirOut,
									DirIn:        dirIn,
									KeyID:        key.ID,
									Timeout:      cfg.ArnikaPeerTimeout,
									Deadline:     intervalEnd,
									MaxClockSkew: cfg.MaxClockSkew,
									Log:          primaryLog,
								})
								switch {
								case err != nil:
									primaryLog.Error("the peer did not confirm the key_id", "key_id", key.ID, "peer", cfg.ServerAddress, "err", err)
									if psk != nil {
										clear(psk)
										if shouldSetPSKOnQKDFailure(cfg) {
											setPSK(keyWriter, pqc, nil, cfg, primaryLog)
										}
									}
								case psk != nil:
									writePSK(keyWriter, psk, true, cfg, primaryLog)
								}
							}
						}
					}
				}
				intervalCounter++
				<-ticker.C
				sawKeyID := peerSentKeyID.Swap(false) // outside the if: a late key_id in a PRIMARY interval must not leak into the next BACKUP one
				if backup && !sawKeyID {
					if shouldSetPSKOnQKDFailure(cfg) {
						backupLog.Error("no key_id from the peer", "interval", intervalCounter-1)
						setPSK(keyWriter, pqc, nil, cfg, backupLog)
					}
				}
			}
		}()
	} else {
		go transport.RunKeyIDWorker(done, result, func(r string) bool {
			arnikaLog.Warn("received a key_id from the peer, but QKD is disabled", "key_id", r, "mode", cfg.Mode)
			return false
		})
		go runPQCSetPSKLoop(keyWriter, pqc, cfg, arnikaLog, nil)
	}
	<-done
	cfg.ZeroSecrets()
}
