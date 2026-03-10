package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"log"

	"os"

	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/kms"
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
)

func getPQCKey(pqcKeyFile string) (string, error) {
	file, err := os.Open(pqcKeyFile)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	return scanner.Text(), nil
}

func setPSK(keyWriter *services.KeyWriterService, qkd string, cfg *config.Config, logPrefix string) {
	psk := qkd
	msg := ""
	defer func() {
		if msg != "" {
			log.Println(msg)
			log.Printf("[ERROR] %s [STOP] configure random PSK to invalidate WireGuard session", logPrefix)
			if err := keyWriter.InvalidateTunnel(); err != nil {
				log.Printf("[ERROR] %s failed to configure random PSK: %v", logPrefix, err)
			}
		}
	}()
	if qkd == "" {
		if cfg.IsQKDRequired() {
			msg = fmt.Sprintf("[ERROR] %s mode set to %s but no QKD key received", logPrefix, cfg.Mode)
			return
		}
		log.Printf("[WARNING] %s failed to retrieve QKD key, switching to PQC key since mode is set to %s", logPrefix, cfg.Mode)
	}
	if cfg.UsePQC() {
		pQCKey, err := getPQCKey(cfg.PQCPSKFile)
		if err != nil {
			if cfg.IsPQCRequired() {
				msg = fmt.Sprintf("[ERROR] %s failed to retrieve PQC key: %v. Abort since mode is set to %s", logPrefix, err, cfg.Mode)
				return
			}
			log.Printf("[WARNING] %s failed to retrieve PQC key, switching to QKD key since mode is set to %s", logPrefix, cfg.Mode)
		} else {
			pqc, err := base64.StdEncoding.DecodeString(pQCKey)
			if err != nil {
				if cfg.IsPQCRequired() {
					msg = fmt.Sprintf("[ERROR] %s failed to decode PQC key: %v. Abort since mode is set to %s", logPrefix, err, cfg.Mode)
					return
				} else {
					log.Printf("[WARNING] %s failed to decode PQC key, switching to QKD key since mode is set to %s", logPrefix, cfg.Mode)
				}
			} else {
				// a key derivation will happen, either with key or with all zeros
				psk, err = kdf.DeriveKey(psk, pqc)
				if err != nil {
					msg = fmt.Sprintf("[ERROR] %s failed to derive key: %v. Abort since mode is set to %s", logPrefix, err, cfg.Mode)
					return
				}
				log.Printf("[INFO] %s [OK] HKDF derivation completed for QKD+PQC key", logPrefix)
			}
		}
	}
	if psk == "" {
		msg = fmt.Sprintf("[ERROR] %s no PSK available", logPrefix)
		return
	}
	if err := keyWriter.SetPSK(psk); err != nil {
		msg = fmt.Sprintf("[ERROR] %s failed to configure PSK on WireGuard interface: %v", logPrefix, err)
		return
	}
	log.Printf("[INFO] %s [OK] PSK configured on WireGuard interface: %s for peer: %s", logPrefix, cfg.WireGuardInterface, cfg.WireguardPeerPublicKey)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	versionLong := flag.Bool("version", false, "print version and exit")
	versionShort := flag.Bool("v", false, "alias for version")
	flag.Parse()
	if *versionShort || *versionLong {
		fmt.Printf("%s version %s\n", APPName, Version)
		os.Exit(0)
	}
	help := flag.Bool("help", false, "print usage and exit")
	flag.Parse()
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("[ERROR] failed to parse config: %v", err)
	}
	cfg.PrintStartupConfig()
	var colorStart, colorEnd string
	arnikaIDInt := 0
	fmt.Sscanf(cfg.ArnikaID, "%d", &arnikaIDInt)
	if arnikaIDInt%2 == 0 {
		colorStart = "\033[35m"
	} else {
		colorStart = "\033[36m"
	}
	colorEnd = "\033[0m"
	PRIMARYLOGPREFIX = fmt.Sprintf("%sPRIMARY[%s]%s", colorStart, cfg.ArnikaID, colorEnd)
	BACKUPLOGPREFIX = fmt.Sprintf("%sBACKUP[%s]%s", colorStart, cfg.ArnikaID, colorEnd)
	ARNIKALOGPREFIX = fmt.Sprintf("ARNIKA[%s]", cfg.ArnikaID)
	interval := cfg.Interval
	done := make(chan bool)
	skip := make(chan bool, 1)
	result := make(chan string)
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsServer := kms.NewKMSServer(cfg.KMSURL, cfg.KMSHTTPTimeout, cfg.KMSBackoffMaxRetries, cfg.KMSBackoffBaseDelay, kmsAuth)
	keyWriter, err := getKeyWriterService(cfg)
	if err != nil {
		log.Panicf("[ERROR] [STOP] Failed to create WireGuard repository: %v", err)
	}
	go udpServer(cfg.ListenAddress, cfg.ArnikaPSK, result, done, cfg.RateLimit, cfg.RateWindow, cfg.MaxClockSkew)
	go func() {
		for {
			r := <-result
			select {
			case skip <- true:
			default:
			}
			log.Printf("[INFO] %s [REQ] request QKD key for key_id %s from %s\n", BACKUPLOGPREFIX, r, cfg.KMSURL)
			key, err := kmsServer.GetKeyByID(r)
			if err != nil {
				log.Printf("[ERROR] %s failed to retrieve QKD key for key_id %s from %s, %v", BACKUPLOGPREFIX, r, cfg.KMSURL, err)
				continue
			}
			setPSK(keyWriter, key.GetKey(), cfg, BACKUPLOGPREFIX)
		}
	}()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var intervalCounter uint64
		for {
			ticker.Reset(interval)
			select {
			case <-skip:
			default:
				// get key_id and send
				log.Printf("[INFO] %s [REQ] request QKD key from %s\n", PRIMARYLOGPREFIX, cfg.KMSURL)
				key, err := kmsServer.GetNewKey()
				if err != nil {
					log.Printf("[ERROR] %s failed to retrieve QKD key from %s, %v", PRIMARYLOGPREFIX, cfg.KMSURL, err)
					ticker.Reset(cfg.KMSRetryInterval)
				} else {
					now := time.Now()
					var nextTick time.Time
					if !cfg.IsPrimary(intervalCounter) {
						// Wait until the next .5 second (e.g., 12:34:56.500)
						nextTick = now.Truncate(time.Second).Add(500 * time.Millisecond)
						if now.After(nextTick) {
							nextTick = nextTick.Add(time.Second)
						}
						log.Printf("[INFO] %s [REQ] use 500ms delay (BACKUP for interval %d)\n", BACKUPLOGPREFIX, intervalCounter)
					} else {
						// Wait until the next full second (e.g., 12:34:57.000)
						nextTick = now.Truncate(time.Second).Add(time.Second)
						log.Printf("[INFO] %s [REQ] PRIMARY for interval %d\n", PRIMARYLOGPREFIX, intervalCounter)
					}
					time.Sleep(nextTick.Sub(now))
					// Check if a key was received from peer during the delay
					select {
					case <-skip:
					default:
						log.Printf("[INFO] %s [SND] send key_id %s to %s\n", PRIMARYLOGPREFIX, key.GetID(), cfg.ServerAddress)
						err = udpClient(cfg.ServerAddress, cfg.ArnikaPSK, key.GetID(), cfg.ArnikaPeerTimeout)
						if err != nil {
							log.Printf("[ERROR] %s failed to send key_id %s to %s: %v", PRIMARYLOGPREFIX, key.GetID(), cfg.ServerAddress, err)
						}
						setPSK(keyWriter, key.GetKey(), cfg, PRIMARYLOGPREFIX)
					}
				}
			}
			intervalCounter++
			<-ticker.C
		}
	}()
	<-done
}
