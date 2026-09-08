// Arnika installs a rotating WireGuard pre-shared key derived from a QKD key
// and a post-quantum key agreement with the peer.
//
// The rotation flows and setPSK, the single point at which a PSK reaches the
// WireGuard interface, live in main.go. Each backend below them (QKD reader,
// PQC reader, key writer) is picked at build time, one build tag per family,
// and which of them must contribute to a given PSK is MODE's runtime decision.
// See KEYCONTROL.md for the tags and CODEFLOW.md for the protocol.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/arnika-project/arnika/auth"
	"log"
	"strconv"

	"os"

	"runtime"
	"runtime/secret"
	"sync/atomic"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/services"
)

var (
	// allows to set version on build.
	Version string
	// allows to overwrite app name on build.
	APPName string
	// Prefix variables initialized after config is parsed
	PRIMARYLOGPREFIX string
	BACKUPLOGPREFIX  string
	ARNIKALOGPREFIX  string
	PQCHPKELOGPREFIX string
)

// installOnQKDFailure reports whether a failed QKD retrieval should be handed
// to setPSK on this node's own tick.
//
// In a QKD-optional mode with PQC enabled it must not be: the PQC-only
// installer owns the PSK then, and it installs on the instant both peers derive
// from the wall clock. An extra install on a local tick put the two out of step
// until the next shared instant - measured as two peers writing different keys
// five seconds apart with a KMS outage in AtLeastPqcRequired.
func installOnQKDFailure(cfg *config.Config) bool {
	return cfg.IsQKDRequired() || !cfg.UsePQC()
}

// lastQKDInstall is when a QKD-derived PSK last reached the interface, in Unix
// nanoseconds. It is the only thing the PQC-only fallback installer needs to
// know: while the QKD path is delivering, that path owns the PSK and the
// fallback must stay quiet, or the two would overwrite each other.
var lastQKDInstall atomic.Int64

// setPSK derives the pre-shared key for this rotation and installs it through
// the key writer.
//
// qkd may be nil, and pqc may be nil: a QKD retrieval is allowed to fail in
// the fallback modes, a qkd_none build has no QKD reader at all, and the PQC
// reader is only wired when PQC_ENABLED is set. Which half is mandatory is
// MODE's decision, read through cfg.IsQKDRequired and cfg.IsPQCRequired.
//
// Every path that ends without usable key material invalidates the tunnel with
// a random PSK instead of leaving the previous one installed, so a failed
// rotation cannot silently extend the life of the key it was meant to replace.
// Errors are logged, not returned: the caller is a rotation loop that must keep
// running.
func setPSK(keyWriter *services.KeyWriterService, pqc *services.KeyReaderService, qkd []byte, cfg *config.Config, logPrefix string) {
	var psk []byte
	if qkd != nil {
		psk = make([]byte, len(qkd))
		copy(psk, qkd)
	}
	msg := ""
	defer func() {
		clear(psk)
		if msg != "" {
			log.Println(msg)
			log.Printf("[ERROR] %s [STOP] configure random PSK to invalidate WireGuard session", logPrefix)
			if err := keyWriter.InvalidateTunnel(); err != nil {
				log.Printf("[ERROR] %s failed to configure random PSK: %v", logPrefix, err)
			}
		}
	}()
	if len(qkd) == 0 {
		if cfg.IsQKDRequired() {
			msg = fmt.Sprintf("[ERROR] %s mode set to %s but no QKD key received", logPrefix, cfg.Mode)
			return
		}
		if qkdCompiled {
			log.Printf("[WARNING] %s failed to retrieve QKD key, switching to PQC key since mode is set to %s", logPrefix, cfg.Mode)
		}
	}
	if cfg.UsePQC() {
		pqcKey, err := pqc.GetNewKey()
		if err != nil {
			if cfg.IsPQCRequired() {
				msg = fmt.Sprintf("[ERROR] %s failed to retrieve PQC key: %v. Abort since mode is set to %s", logPrefix, err, cfg.Mode)
				return
			}
			log.Printf("[WARNING] %s failed to retrieve PQC key, switching to QKD key since mode is set to %s", logPrefix, cfg.Mode)
		} else {
			defer pqcKey.Zero()
			var derivedKey []byte
			secret.Do(func() {
				derivedKey, err = kdf.DeriveKey(psk, pqcKey.Key)
			})
			if err != nil {
				msg = fmt.Sprintf("[ERROR] %s failed to derive key: %v. Abort since mode is set to %s", logPrefix, err, cfg.Mode)
				return
			}
			clear(psk)
			psk = derivedKey
			log.Printf("[INFO] %s [OK] HKDF derivation completed for QKD+PQC key", logPrefix)
		}
	}
	if len(psk) == 0 {
		msg = fmt.Sprintf("[ERROR] %s no PSK available", logPrefix)
		return
	}
	// Encode to base64 for WireGuard interface (requires string)
	pskStr := base64.StdEncoding.EncodeToString(psk)
	if err := keyWriter.SetPSK(pskStr); err != nil {
		msg = fmt.Sprintf("[ERROR] %s failed to configure PSK on WireGuard interface: %v", logPrefix, err)
		return
	}
	if qkd != nil {
		lastQKDInstall.Store(time.Now().UnixNano())
	}
	log.Printf("[INFO] %s [OK] PSK configured on WireGuard interface: %s for peer: %s", logPrefix, cfg.WireGuardInterface, cfg.WireguardPeerPublicKey)
}

// nextPQCInstall returns when the PSK agreed for the next PQC round boundary
// should be installed: in the middle of the part of the round in which the
// scheduler never publishes.
//
// PQCHPKERepository.Run wakes one round timeout *before* a boundary and indexes
// the round by the boundary it serves, so publishes cluster in
// [boundary-PQC_ROUND_TIMEOUT, boundary] and the rest of the round is quiet.
// Installing at the midpoint of that quiet part leaves the largest margin on
// both sides, for any PQC_ROUND_TIMEOUT shorter than PQC_ROUND_INTERVAL.
//
// Only a build without a QKD reader needs this. With one, the peer's key_id
// message is what puts both sides on the same key, and the rekey instant is
// independent of the round boundary. Without it the boundary is all the peers
// share, so it has to be derived exactly as Run derives it, from the wall
// clock, or two peers with offset tickers install keys from different rounds.
func nextPQCInstall(now time.Time, roundInterval, roundTimeout time.Duration) time.Time {
	secs := int64(roundInterval.Seconds())
	if secs < 1 {
		secs = 1
	}
	boundary := time.Unix((now.Unix()/secs+1)*secs, 0)
	// secs, not roundInterval: the scheduler rounds the boundary spacing down to
	// whole seconds too, so that is the real distance to the next publish.
	quiet := time.Duration(secs)*time.Second - roundTimeout
	if quiet <= 0 {
		return boundary // config rejects this, so it is a floor and not a schedule
	}
	return boundary.Add(quiet / 2)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
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

	// Harden before the configuration is read, so ARNIKA_PSK never exists in a
	// process that can be core-dumped, ptraced by its own user, or swapped out.
	for _, err := range hardenProcess() {
		log.Printf("[WARNING] process hardening incomplete: %v", err)
	}
	// runtime/secret erases registers, stack and unreachable heap allocations,
	// but only on linux/amd64 and linux/arm64; everywhere else secret.Do simply
	// calls its function. Enabled() reports the Do nesting depth, so it has to
	// be asked from inside a Do block.
	secretErasure := false
	secret.Do(func() { secretErasure = secret.Enabled() })
	if !secretErasure {
		log.Printf("[WARNING] runtime/secret erasure is inert on %s/%s: key material is not wiped from registers, stack or freed heap",
			runtime.GOOS, runtime.GOARCH)
	}

	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("[ERROR] failed to parse config: %v", err)
	}
	// Which readers exist is decided at build time, MODE and PQC_ENABLED at
	// runtime; this rejects the combinations the binary cannot serve before any
	// key is due.
	if err := cfg.ValidateKeySources(qkdCompiled); err != nil {
		log.Fatal(err)
	}
	// The PSK now lives in cfg.ArnikaPSK, which ZeroSecrets can wipe. Drop the
	// runtime's environment copy so it is neither inherited by a child process
	// nor echoed by an accidental os.Environ() dump.
	//
	// This does NOT scrub /proc/<pid>/environ, which reflects the environment as
	// of execve and is not writable from here; PR_SET_DUMPABLE above is what
	// keeps that unreadable.
	if err := os.Unsetenv("ARNIKA_PSK"); err != nil {
		log.Printf("[WARNING] failed to drop ARNIKA_PSK from the environment: %v", err)
	}
	cfg.PrintStartupConfig()
	var colorStart, colorEnd string
	arnikaIDInt := 0
	if _, err := fmt.Sscanf(cfg.ArnikaID, "%d", &arnikaIDInt); err != nil {
		log.Printf("[WARN] failed to parse ArnikaID %q as integer: %v", cfg.ArnikaID, err)
	}
	if arnikaIDInt%2 == 0 {
		colorStart = "\033[35m"
	} else {
		colorStart = "\033[36m"
	}
	colorEnd = "\033[0m"
	PRIMARYLOGPREFIX = fmt.Sprintf("%sPRIMARY[%s]%s", colorStart, cfg.ArnikaID, colorEnd)
	BACKUPLOGPREFIX = fmt.Sprintf("%sBACKUP[%s]%s", colorStart, cfg.ArnikaID, colorEnd)
	ARNIKALOGPREFIX = fmt.Sprintf("ARNIKA[%s]", cfg.ArnikaID)
	PQCHPKELOGPREFIX = fmt.Sprintf("%sPQC-HPKE[%s]%s", colorStart, cfg.ArnikaID, colorEnd)
	interval := cfg.Interval
	done := make(chan bool)
	skip := make(chan bool, 1)
	result := make(chan string)
	keyWriter, err := getKeyWriterService(cfg)
	if err != nil {
		log.Panicf("[ERROR] [STOP] Failed to create WireGuard repository: %v", err)
	}
	// Direction labels are derived from ARNIKA_ID parity, which the two peers
	// are required to differ in; they make a reflected packet fail at its sender.
	arnikaID, _ := strconv.Atoi(cfg.ArnikaID) // always valid, checked during Parse
	dirOut, dirIn := auth.DirectionFor(arnikaID)
	// The pqc-hpke reader agrees its key with the peer over the same port.
	// It is only constructed when enabled: with PQC off nothing is dialled, no
	// agreement goroutine runs and the UDP server drops PQC packets.
	var pqc *services.KeyReaderService
	var pqcHandle pqcHandler
	if cfg.UsePQC() {
		pqcService, pqcRun, handle, err := getPQCService(cfg, dirOut, dirIn)
		if err != nil {
			log.Panicf("[ERROR] [STOP] failed to create PQC key reader: %v", err)
		}
		pqc, pqcHandle = pqcService, handle
		pqcCtx, cancelPQC := context.WithCancel(context.Background())
		defer cancelPQC()
		go pqcRun(pqcCtx)
	}

	go udpServer(cfg.ListenAddress, cfg.ArnikaPSK, dirOut, dirIn, result, done, pqcHandle, cfg.RateLimit, cfg.RateWindow, cfg.MaxClockSkew)
	if qkdCompiled {
		// A mode with QKD optional has to keep rotating when the KMS is
		// unavailable, and without a key_id message the only thing the two
		// peers share is the wall clock. nextPQCInstall is that shared instant,
		// exactly as the qkd_none build uses it; installing on an INTERVAL
		// ticker instead would let two offset tickers pick different rounds.
		//
		// The QKD path owns the PSK whenever it is delivering, so this stays
		// quiet until it has been silent for two intervals. The register starts
		// at "now" to give that path the first two intervals uncontested.
		if cfg.UsePQC() && !cfg.IsQKDRequired() {
			lastQKDInstall.Store(time.Now().UnixNano())
			go func() {
				for {
					time.Sleep(time.Until(nextPQCInstall(time.Now(), cfg.PQCRoundInterval, cfg.PQCRoundTimeout)))
					if time.Since(time.Unix(0, lastQKDInstall.Load())) < 2*interval {
						continue
					}
					log.Printf("[WARNING] %s no QKD key for %s, installing a PQC-only PSK since mode is set to %s",
						ARNIKALOGPREFIX, 2*interval, cfg.Mode)
					setPSK(keyWriter, pqc, nil, cfg, ARNIKALOGPREFIX)
				}
			}()
		}
		qkd := getQKDService(cfg)
		go func() {
			for {
				r := <-result
				select {
				case skip <- true:
				default:
				}
				log.Printf("[INFO] %s [REQ] request QKD key for key_id %s from %s\n", BACKUPLOGPREFIX, r, cfg.KMSURL)
				key, err := qkd.GetKeyByID(&r)
				if err != nil {
					log.Printf("[ERROR] %s failed to retrieve QKD key for key_id %s from %s, %v", BACKUPLOGPREFIX, r, cfg.KMSURL, err)
					// MODE decides what a missing QKD key means; skipping the
					// call left its whole fallback and fail-closed logic
					// unreachable and the superseded PSK installed.
					if installOnQKDFailure(cfg) {
						setPSK(keyWriter, pqc, nil, cfg, BACKUPLOGPREFIX)
					}
					continue
				}
				setPSK(keyWriter, pqc, key.Key, cfg, BACKUPLOGPREFIX)
			}
		}()
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			var intervalCounter uint64
			for {
				ticker.Reset(interval)
				// The peer's key_id is the only thing that rotates a BACKUP
				// interval, so whether one arrived is checked at the end of it,
				// below. The skip signal therefore has exactly one consumer per
				// interval: draining it here as well would steal the very
				// signal that check needs and invalidate a healthy interval.
				backup := !cfg.IsPrimary(intervalCounter)
				if backup {
					log.Printf("[INFO] %s [REQ] BACKUP for interval %d, waiting for key_id from peer\n", BACKUPLOGPREFIX, intervalCounter)
				} else {
					select {
					case <-skip:
					default:
					}
					log.Printf("[INFO] %s [REQ] request QKD key from %s\n", PRIMARYLOGPREFIX, cfg.KMSURL)
					key, err := qkd.GetNewKey()
					if err != nil {
						log.Printf("[ERROR] %s failed to retrieve QKD key from %s, %v", PRIMARYLOGPREFIX, cfg.KMSURL, err)
						ticker.Reset(cfg.KMSRetryInterval)
						// Hand the failure to MODE rather than returning to the
						// ticker: setPSK invalidates the tunnel when QKD is
						// required. Without this call that never happened, so a
						// KMS outage silently extended the life of the PSK it
						// was meant to replace.
						if installOnQKDFailure(cfg) {
							setPSK(keyWriter, pqc, nil, cfg, PRIMARYLOGPREFIX)
						}
					} else {
						// Wait until the next full second (e.g., 12:34:57.000)
						now := time.Now()
						nextTick := now.Truncate(time.Second).Add(time.Second)
						log.Printf("[INFO] %s [REQ] PRIMARY for interval %d\n", PRIMARYLOGPREFIX, intervalCounter)
						time.Sleep(nextTick.Sub(now))
						select {
						case <-skip:
						default:
							if !key.IsManaged() && key.ID == nil {
								log.Printf("[ERROR] %s received empty key_id from KMS, skipping this interval", PRIMARYLOGPREFIX)
								if installOnQKDFailure(cfg) {
									setPSK(keyWriter, pqc, nil, cfg, PRIMARYLOGPREFIX)
								}
								// break, not continue: continue skipped the
								// ticker wait at the bottom of the loop and
								// span on the KMS as fast as it could answer.
								break
							}
							log.Printf("[INFO] %s [SND] send key_id %s to %s\n", PRIMARYLOGPREFIX, *key.ID, cfg.ServerAddress)
							err = udpClient(cfg.ServerAddress, cfg.ArnikaPSK, dirOut, dirIn, *key.ID, cfg.ArnikaPeerTimeout, cfg.MaxClockSkew)
							if err != nil {
								log.Printf("[ERROR] %s failed to send key_id %s to %s: %v", PRIMARYLOGPREFIX, *key.ID, cfg.ServerAddress, err)
							}
							setPSK(keyWriter, pqc, key.Key, cfg, PRIMARYLOGPREFIX)
						}
					}
				}
				intervalCounter++
				<-ticker.C
				if backup {
					select {
					case <-skip:
						// The key_id arrived and the reader goroutine rotated.
					default:
						// It did not. MODE has to decide, exactly as it does
						// for a failed KMS request on the PRIMARY side: without
						// this the BACKUP kept the superseded PSK installed for
						// an interval that produced no key material, and logged
						// nothing about it.
						if installOnQKDFailure(cfg) {
							log.Printf("[ERROR] %s no key_id from the peer for interval %d", BACKUPLOGPREFIX, intervalCounter-1)
							setPSK(keyWriter, pqc, nil, cfg, BACKUPLOGPREFIX)
						}
					}
				}
			}
		}()
	} else {
		// PQC-only build: nothing exchanges a key_id, so drain what a
		// misconfigured peer sends rather than let the UDP server block on it.
		go func() {
			for r := range result {
				log.Printf("[WARNING] %s received key_id %s from the peer, but this binary has no QKD key reader", ARNIKALOGPREFIX, r)
			}
		}()
		// Both peers derive the PQC round from the wall clock, so installing the
		// agreed key one round timeout after each boundary keeps them on the same
		// key without a key_id message. Rotating on INTERVAL instead would let two
		// offset tickers install keys from different rounds and break the tunnel.
		go func() {
			for {
				time.Sleep(time.Until(nextPQCInstall(time.Now(), cfg.PQCRoundInterval, cfg.PQCRoundTimeout)))
				setPSK(keyWriter, pqc, nil, cfg, ARNIKALOGPREFIX)
			}
		}()
	}
	<-done
	cfg.ZeroSecrets()
}
