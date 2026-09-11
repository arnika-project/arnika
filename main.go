// Arnika installs a rotating WireGuard pre-shared key derived from a QKD key
// and a post-quantum key agreement with the peer.
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
	// Version allows setting a version on build.
	Version string
	// APPName allows setting an app name on a build.
	APPName string
	// Prefix variables initialized after config is parsed
	PRIMARYLOGPREFIX string
	BACKUPLOGPREFIX  string
	ARNIKALOGPREFIX  string
	PQCHPKELOGPREFIX string
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
		lastQKDPSKAt.Store(time.Now().UnixNano())
	}
	log.Printf("[INFO] %s [OK] PSK configured on WireGuard interface: %s for peer: %s", logPrefix, cfg.WireGuardInterface, cfg.WireguardPeerPublicKey)
}

// nextPQCSetPSKAt returns the next moment to set a PQC-derived PSK. Both
// peers compute the same moment from the clock alone, roughly halfway
// between one round's publish window and the next, for the widest margin.
//
// Only used when no QKD reader is available; with QKD, the peer's key_id
// message keeps both sides in sync instead.
func nextPQCSetPSKAt(now time.Time, roundInterval, roundTimeout time.Duration) time.Time {
	secs := int64(roundInterval.Seconds())
	if secs < 1 {
		secs = 1
	}
	boundary := time.Unix((now.Unix()/secs+1)*secs, 0)
	quiet := time.Duration(secs)*time.Second - roundTimeout
	if quiet <= 0 {
		return boundary
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
	// but only on linux/amd64 and linux/arm64
	var secretErasure bool
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
	if err := os.Unsetenv("ARNIKA_PSK"); err != nil {
		log.Printf("[WARNING] failed to drop ARNIKA_PSK from the environment: %v", err)
	}
	limit, budget, warning := effectiveRateLimit(cfg)
	if warning != "" {
		log.Printf("[WARNING] %s", warning)
	}
	cfg.RateLimit = limit
	log.Printf("[INFO] per-IP rate limit: %d packets per %s (calculated legitimate budget: %d)",
		cfg.RateLimit, cfg.RateWindow, budget)
	cfg.PrintStartupConfig()
	arnikaID, _ := strconv.Atoi(cfg.ArnikaID)
	colorStart := "\033[36m"
	if arnikaID%2 == 0 {
		colorStart = "\033[35m"
	}
	colorEnd := "\033[0m"
	PRIMARYLOGPREFIX = fmt.Sprintf("%sPRIMARY[%s]%s", colorStart, cfg.ArnikaID, colorEnd)
	BACKUPLOGPREFIX = fmt.Sprintf("%sBACKUP[%s]%s", colorStart, cfg.ArnikaID, colorEnd)
	ARNIKALOGPREFIX = fmt.Sprintf("ARNIKA[%s]", cfg.ArnikaID)
	PQCHPKELOGPREFIX = fmt.Sprintf("%sPQC-HPKE[%s]%s", colorStart, cfg.ArnikaID, colorEnd)
	interval := cfg.Interval
	done := make(chan bool)
	skip := make(chan bool, 1)
	result := make(chan string, qkdQueueDepth)
	keyWriter, err := getKeyWriterService(cfg)
	if err != nil {
		log.Panicf("[ERROR] [STOP] Failed to create WireGuard repository: %v", err)
	}
	dirOut, dirIn := auth.DirectionFor(arnikaID)
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
		// Without this the PSK would stay unchanged for as long as the KMS is
		// down. After two INTERVALs without a key both peers switch, at the same
		// moment taken from the wall clock, to a PSK built from the PQC key alone,
		// and renew it every PQC_ROUND_INTERVAL until the KMS returns. Two and not
		// one, because one late or lost key often affects only one of the two
		// peers, and switching on it would leave them with different PSKs.
		if cfg.UsePQC() && !cfg.IsQKDRequired() {
			lastQKDPSKAt.Store(time.Now().UnixNano())
			go func() {
				for {
					time.Sleep(time.Until(nextPQCSetPSKAt(time.Now(), cfg.PQCRoundInterval, cfg.PQCRoundTimeout)))
					if time.Since(time.Unix(0, lastQKDPSKAt.Load())) < 2*interval {
						continue
					}
					log.Printf("[WARNING] %s no QKD key for %s, installing a PQC-only PSK since mode is set to %s",
						ARNIKALOGPREFIX, 2*interval, cfg.Mode)
					setPSK(keyWriter, pqc, nil, cfg, ARNIKALOGPREFIX)
				}
			}()
		}
		qkd := getQKDService(cfg)
		go runQKDWorker(done, result, func(r string) {
			select {
			case skip <- true:
			default:
			}
			log.Printf("[INFO] %s [REQ] request QKD key for key_id %s from %s\n", BACKUPLOGPREFIX, r, cfg.KMSURL)
			key, err := qkd.GetKeyByID(&r)
			if err != nil {
				log.Printf("[ERROR] %s failed to retrieve QKD key for key_id %s from %s, %v", BACKUPLOGPREFIX, r, cfg.KMSURL, err)
				if shouldSetPSKOnQKDFailure(cfg) {
					setPSK(keyWriter, pqc, nil, cfg, BACKUPLOGPREFIX)
				}
				return
			}
			setPSK(keyWriter, pqc, key.Key, cfg, BACKUPLOGPREFIX)
		})
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			var intervalCounter uint64
			for {
				ticker.Reset(interval)
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
						if shouldSetPSKOnQKDFailure(cfg) {
							setPSK(keyWriter, pqc, nil, cfg, PRIMARYLOGPREFIX)
						}
					} else {
						// wait until the next full second (e.g., 12:34:57.000)
						now := time.Now()
						nextTick := now.Truncate(time.Second).Add(time.Second)
						log.Printf("[INFO] %s [REQ] PRIMARY for interval %d\n", PRIMARYLOGPREFIX, intervalCounter)
						time.Sleep(nextTick.Sub(now))
						select {
						case <-skip:
						default:
							if !key.IsManaged() && key.ID == nil {
								log.Printf("[ERROR] %s received empty key_id from KMS, skipping this interval", PRIMARYLOGPREFIX)
								if shouldSetPSKOnQKDFailure(cfg) {
									setPSK(keyWriter, pqc, nil, cfg, PRIMARYLOGPREFIX)
								}
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
						// the key_id arrived and the reader goroutine rotated
					default:
						// MODE has to decide, exactly as it does for a failed
						// KMS request on the PRIMARY side: without this the
						// BACKUP kept the superseded PSK installed for an interval
						if shouldSetPSKOnQKDFailure(cfg) {
							log.Printf("[ERROR] %s no key_id from the peer for interval %d", BACKUPLOGPREFIX, intervalCounter-1)
							setPSK(keyWriter, pqc, nil, cfg, BACKUPLOGPREFIX)
						}
					}
				}
			}
		}()
	} else {
		// PQC-only build: so any key_id from the peer means a misconfigured
		// build or MODE mismatch. Drain and log it here, or it would just fill
		// the shared queue and get silently dropped.
		go runQKDWorker(done, result, func(r string) {
			log.Printf("[WARNING] %s received key_id %s from the peer, but this binary has no QKD key reader", ARNIKALOGPREFIX, r)
		})
		// Both peers pick the same moment from the clock (nextPQCSetPSKAt),
		// keeping them on the same key without ever exchanging a key_id.
		// Using INTERVAL here instead could put the two peers on different
		// rounds and break the tunnel.
		go func() {
			for {
				time.Sleep(time.Until(nextPQCSetPSKAt(time.Now(), cfg.PQCRoundInterval, cfg.PQCRoundTimeout)))
				setPSK(keyWriter, pqc, nil, cfg, ARNIKALOGPREFIX)
			}
		}()
	}
	<-done
	cfg.ZeroSecrets()
}
