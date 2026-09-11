// Arnika installs a rotating WireGuard pre-shared key derived from a QKD key
// and a post-quantum key agreement with the peer.
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
	// Version allows setting a version on build.
	Version string
	// APPName allows setting an app name on a build.
	APPName string
)

// shouldSetPSKOnQKDFailure reports whether to set a new PSK right away after
// a failed QKD request, or leave it to the next scheduled PQC key rotation.
//
// Returns false only for MODE=AtLeastPqcRequired or EitherQkdOrPqcRequired
// with PQC_ENABLED=true; true in every other case.
func shouldSetPSKOnQKDFailure(cfg *config.Config) bool {
	return cfg.IsQKDRequired() || !cfg.UsePQC()
}

// lastQKDPSKAt is when a QKD key was last obtained, in Unix nanoseconds. Each
// valid QKD key sets it and applies a new PSK to the WireGuard interface,
// combined with a PQC key when PQC_ENABLED is true.
var lastQKDPSKAt atomic.Int64

// setPSK builds the PSK for this rotation and applies it to the WireGuard
// interface.
//
// The argument qkd is the QKD key for this rotation, or nil if none is available. When
// PQC_ENABLED is true, it is combined with a fresh PQC key through HKDF; if
// PQC_ENABLED is false, the QKD key is used as is. Which of the two must be
// present for a valid PSK is decided by MODE.
//
// If no valid PSK can be built, it sets a random PSK to invalidate the
// tunnel instead of leaving the old key active, so a failed rotation never
// silently extends the previous key's life. Errors are logged, not
// returned, since the caller is a rotation loop that must keep running.
func setPSK(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, qkd []byte, cfg *config.Config, logger *slog.Logger) {
	var psk []byte
	if qkd != nil {
		psk = make([]byte, len(qkd))
		copy(psk, qkd)
	}
	// The failure is recorded rather than logged where it happens, so that the
	// reason and the invalidation it causes always appear together and no exit
	// path can log one without the other.
	var failure string
	var failureAttrs []any
	defer func() {
		clear(psk)
		if failure == "" {
			return
		}
		logger.Error(failure, failureAttrs...)
		logger.Error("configuring a random PSK to invalidate the WireGuard session")
		if err := keyWriter.InvalidateTunnel(); err != nil {
			logger.Error("failed to configure the random PSK", "err", err)
		}
	}()
	if len(qkd) == 0 {
		if cfg.IsQKDRequired() {
			failure, failureAttrs = "no QKD key received", []any{"mode", cfg.Mode}
			return
		}
		if qkdCompiled {
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
			logger.Info("HKDF derivation completed for the QKD+PQC key")
		}
	}
	if len(psk) == 0 {
		failure = "no key material available for a PSK"
		return
	}
	if err := keyWriter.SetPSK(psk); err != nil {
		failure, failureAttrs = "failed to configure the PSK on the WireGuard interface", []any{"err", err}
		return
	}
	if qkd != nil {
		lastQKDPSKAt.Store(time.Now().UnixNano())
	}
	// Wording is load-bearing: ci/local-darwin/run.sh and the e2e lab count this
	// line to assert that both peers rotated. Change the attributes freely, the
	// message only together with them.
	logger.Info("PSK configured on WireGuard interface",
		"iface", cfg.WireGuardInterface, "peer", cfg.WireguardPeerPublicKey)
}

// nextPQCSetPSKAt returns the next moment to set a PQC-derived PSK. Both
// peers compute the same moment from the clock alone, roughly halfway
// between one round's publish window and the next, for the widest margin.
//
// The second grid comes from the PQC scheduler itself (RoundSeconds) rather
// than from a second rounding rule here. The two must agree exactly: this
// instant is only in the scheduler's quiet window if both derive the boundary
// from the same whole seconds, and a peer that landed on a different grid would
// read a different round's key.
func nextPQCSetPSKAt(now time.Time, roundInterval, roundTimeout time.Duration) time.Time {
	secs := pqchpke.RoundSeconds(roundInterval)
	boundary := time.Unix((now.Unix()/secs+1)*secs, 0)
	quiet := time.Duration(secs)*time.Second - roundTimeout
	if quiet <= 0 {
		return boundary
	}
	return boundary.Add(quiet / 2)
}

// runPQCSetPSKLoop installs a PQC-only PSK on every nextPQCSetPSKAt instant,
// until the process ends. Both peers pick that instant from the clock alone,
// which is what keeps them on the same PQC key with no message between them;
// waking on INTERVAL instead could put them on different rounds.
//
// due gates each instant and reports whether a PSK is owed, so the caller can
// log why. A nil due installs on every instant, which is what a binary with no
// QKD key reader wants.
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
	// Harden before the configuration is read, so ARNIKA_PSK never exists in a
	// process that can be core-dumped, ptraced by its own user, or swapped out.
	for _, err := range hardening.Process() {
		slog.Warn("process hardening incomplete", "err", err)
	}
	// runtime/secret erases registers, stack and unreachable heap allocations,
	// but only on linux/amd64 and linux/arm64
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
	// Which readers exist is decided at build time, MODE and PQC_ENABLED at
	// runtime; this rejects the combinations the binary cannot serve before any
	// key is due.
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
	// From here on every record carries arnika_id, and gets a colour when
	// stderr is a terminal, which is what the four log prefixes used to do.
	setLogIdentity(arnikaID)
	arnikaLog := slog.Default()
	primaryLog := arnikaLog.With("role", "primary")
	backupLog := arnikaLog.With("role", "backup")
	arnikaLog.Info("per-IP rate limit",
		"limit", cfg.RateLimit, "window", cfg.RateWindow, "calculated_budget", budget)
	cfg.PrintStartupConfig()
	interval := cfg.Interval
	done := make(chan bool)
	// peerSentKeyID reports that a key_id arrived from the peer, which means the
	// worker goroutine has taken over the rotation for this interval. It was a
	// buffered channel used as a flag, with four send-or-drain selects whose
	// correctness rested on every reader consuming at most one signal. Swap(false)
	// says "take the signal if there is one" in a single expression, so a reader
	// cannot consume twice or forget to consume.
	var peerSentKeyID atomic.Bool
	result := make(chan string, transport.QKDQueueDepth)
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

	// Serve returns an error rather than ending the process itself, so the
	// failure surfaces here, next to every other startup failure.
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
	if qkdCompiled {
		// Without this the PSK would stay unchanged for as long as the KMS is
		// down. After two INTERVALs without a key both peers switch, at the same
		// moment taken from the wall clock, to a PSK built from the PQC key alone,
		// and renew it every PQC_ROUND_INTERVAL until the KMS returns. Two and not
		// one, because one late or lost key often affects only one of the two
		// peers, and switching on it would leave them with different PSKs.
		if cfg.UsePQC() && !cfg.IsQKDRequired() {
			lastQKDPSKAt.Store(time.Now().UnixNano())
			go runPQCSetPSKLoop(keyWriter, pqc, cfg, arnikaLog, func() bool {
				if time.Since(time.Unix(0, lastQKDPSKAt.Load())) < 2*interval {
					return false
				}
				arnikaLog.Warn("no QKD key, installing a PQC-only PSK",
					"no_key_for", 2*interval, "mode", cfg.Mode)
				return true
			})
		}
		qkd := getQKDService(cfg)
		go transport.RunKeyIDWorker(done, result, func(r string) {
			peerSentKeyID.Store(true)
			backupLog.Info("requesting the QKD key for the peer's key_id", "key_id", r, "kms", cfg.KMSURL)
			key, err := qkd.GetKeyByID(r)
			if err != nil {
				backupLog.Error("failed to retrieve the QKD key for the peer's key_id", "key_id", r, "kms", cfg.KMSURL, "err", err)
				if shouldSetPSKOnQKDFailure(cfg) {
					setPSK(keyWriter, pqc, nil, cfg, backupLog)
				}
				return
			}
			setPSK(keyWriter, pqc, key.Key, cfg, backupLog)
		})
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			var intervalCounter uint64
			for {
				ticker.Reset(interval)
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
						// wait until the next full second (e.g., 12:34:57.000)
						now := time.Now()
						nextTick := now.Truncate(time.Second).Add(time.Second)
						primaryLog.Info("serving this interval", "interval", intervalCounter)
						time.Sleep(nextTick.Sub(now))
						// A key_id from the peer in the meantime means it is
						// acting as PRIMARY for this interval too, so its
						// rotation already won and sending ours as well would
						// put the two on different keys.
						if !peerSentKeyID.Swap(false) {
							// Checked against the empty string, not against a
							// nil pointer: the previous form could never fire,
							// because the service handed out a pointer to its
							// own local variable even when the KMS returned no
							// identifier at all.
							if key.ID == "" {
								primaryLog.Error("the KMS returned an empty key_id, skipping this interval")
								if shouldSetPSKOnQKDFailure(cfg) {
									setPSK(keyWriter, pqc, nil, cfg, primaryLog)
								}
							} else {
								primaryLog.Info("sending the key_id to the peer", "key_id", key.ID, "peer", cfg.ServerAddress)
								err = transport.SendKeyID(transport.ClientConfig{
									Address:      cfg.ServerAddress,
									PSK:          cfg.ArnikaPSK,
									DirOut:       dirOut,
									DirIn:        dirIn,
									KeyID:        key.ID,
									Timeout:      cfg.ArnikaPeerTimeout,
									MaxClockSkew: cfg.MaxClockSkew,
									Log:          primaryLog,
								})
								if err != nil {
									primaryLog.Error("failed to send the key_id to the peer", "key_id", key.ID, "peer", cfg.ServerAddress, "err", err)
								}
								setPSK(keyWriter, pqc, key.Key, cfg, primaryLog)
							}
						}
					}
				}
				intervalCounter++
				<-ticker.C
				// Every interval takes the signal at its end, PRIMARY included,
				// even though only a BACKUP acts on it. Taking it inside the
				// condition let `backup &&` short-circuit past the Swap, so a
				// key_id that reached a PRIMARY interval after its own check -
				// a late udpClient retry, or two peers whose interval counters
				// drifted apart across a restart - stayed set into the next
				// interval. A BACKUP there then read it as proof that a key_id
				// had arrived when none had, and skipped failing closed.
				sawKeyID := peerSentKeyID.Swap(false)
				// Without a signal, MODE has to decide, exactly as it does for a
				// failed KMS request on the PRIMARY side: without this the
				// BACKUP kept the superseded PSK installed for an interval.
				if backup && !sawKeyID {
					if shouldSetPSKOnQKDFailure(cfg) {
						backupLog.Error("no key_id from the peer", "interval", intervalCounter-1)
						setPSK(keyWriter, pqc, nil, cfg, backupLog)
					}
				}
			}
		}()
	} else {
		// PQC-only build: so any key_id from the peer means a misconfigured
		// build or MODE mismatch. Drain and log it here, or it would just fill
		// the shared queue and get silently dropped.
		go transport.RunKeyIDWorker(done, result, func(r string) {
			arnikaLog.Warn("received a key_id from the peer, but this binary has no QKD key reader", "key_id", r)
		})
		// The PQC key agreement is the only key source here, so every instant
		// is due and there is nothing to gate on.
		go runPQCSetPSKLoop(keyWriter, pqc, cfg, arnikaLog, nil)
	}
	<-done
	cfg.ZeroSecrets()
}
