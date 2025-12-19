package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arnika-project/arnika/config"
	"github.com/arnika-project/arnika/kdf"
	"github.com/arnika-project/arnika/kms"
	wg "github.com/arnika-project/arnika/wireguard"
)

var (
	// allows to set version on build.
	Version string
	// allows to overwrite app name on build.
	APPName string
)

const (
	MASTERPREFIX = "--> MASTER:"
	BACKUPPREFIX = "<-- BACKUP:"
)

func handleServerConnection(c net.Conn, result chan string) {
	// Check that c is not nil.
	if c == nil {
		panic("received nil connection")
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from panic:", r)
		}
	}()
	for {
		// scan message
		scanner := bufio.NewScanner(c)
		// Check that scanner is not nil.
		if scanner == nil {
			panic("received nil scanner")
		}
		for scanner.Scan() {
			msg := scanner.Text()
			result <- msg
			_, err := c.Write([]byte("ACK" + "\n"))
			if err != nil { // Handle the write error
				fmt.Println("Failed to write to connection:", err)
				break
			}
		}
		if errRead := scanner.Err(); errRead != nil { // Handle the read error
			if errRead == io.EOF { // Handle EOF
				fmt.Println("Connection closed by remote host.")
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func tcpServer(url string, result chan string, done chan bool) {
	// defer close(done)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit,
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	go func() {
		<-quit
		log.Println("TCP Server shutdown")
		close(done)
	}()
	log.Printf("TCP Server listening on %s\n", url)
	ln, err := net.Listen("tcp", url)
	if err != nil {
		log.Panicln(err.Error())
		return
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			go handleServerConnection(c, result)
			time.Sleep(100 * time.Millisecond)
		}
	}()
	<-done
	err = ln.Close()
	if err != nil {
		log.Println(err.Error())
	}
}

func tcpClient(url, data string) error {
	if url == "" {
		return fmt.Errorf("url is empty")
	}
	if data == "" {
		return fmt.Errorf("data is empty")
	}
	c, err := net.DialTimeout("tcp", url, time.Millisecond*100)
	if err != nil {
		return err
	}
	defer func() {
		if c != nil {
			c.Close()
		}
	}()
	_, err = c.Write([]byte(data + "\n"))
	if err != nil {
		return err
	}
	return c.SetDeadline(time.Now().Add(time.Millisecond * 100))
}

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

func setPSK(wireguard *wg.WireGuardHandler, qkd string, cfg *config.Config, logPrefix string) {
	psk := qkd
	msg := ""
	defer func() {
		if msg != "" {
			log.Println(msg)
			if err := wireguard.SetRandomPSK(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey); err != nil {
				log.Printf("%s ❌ failed to set random PSK: %v", logPrefix, err)
			}
		}
	}()
	if qkd == "" {
		if cfg.IsQKDRequired() {
			msg = fmt.Sprintf("%s ⛔ mode set to %s but no QKD key received, configure random PSK", logPrefix, cfg.Mode)
			return
		}
		log.Printf("%s failed to get QKD key, using only PQC key since mode is set to %s", logPrefix, cfg.Mode)
	}
	if cfg.UsePQC() {
		log.Printf("%s key derivation with PQC key enabled", logPrefix)
		pQCKey, err := getPQCKey(cfg.PQCPSKFile)
		if err != nil {
			if cfg.IsPQCRequired() {
				msg = fmt.Sprintf("%s ⛔ failed to read PQC key from file: %v, configure random PSK since mode is set to %s", logPrefix, err, cfg.Mode)
				return
			}
			log.Printf("%s failed to read PQC key from file, using only KMS key since mode is set to %s", logPrefix, cfg.Mode)
		} else {
			pqc, err := base64.StdEncoding.DecodeString(pQCKey)
			if err != nil {
				if cfg.IsPQCRequired() {
					msg = fmt.Sprintf("%s ⛔ failed to decode PQC key: %v, configure random PSK since mode is set to %s", logPrefix, err, cfg.Mode)
					return
				} else {
					log.Printf("%s failed to decode PQC key, using only KMS key since mode is set to %s", logPrefix, cfg.Mode)
				}
			}
			if len(pqc) > 0 {
				psk, err = kdf.DeriveKey(psk, pqc)
				if err != nil {
					msg = fmt.Sprintf("%s ⛔ failed to derive key: %v, configure random PSK since mode is set to %s", logPrefix, err, cfg.Mode)
					return
				}
			}
		}
	}
	if psk == "" {
		msg = fmt.Sprintf("%s ⛔ no keys left, configure random PSK", logPrefix)
		return
	}
	if err := wireguard.SetKey(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey, psk); err != nil {
		msg = fmt.Sprintf("%s ❌ failed to set PSK: %v", logPrefix, err)
		return
	}
	log.Printf("%s ✅ configure wireguard interface", logPrefix)
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
		log.Fatalf("Failed to parse config: %v", err)
	}
	cfg.PrintStartupConfig()
	interval := cfg.Interval
	done := make(chan bool)
	skip := make(chan bool, 1)
	result := make(chan string)
	kmsAuth := kms.NewClientCertificateAuth(cfg.Certificate, cfg.PrivateKey, cfg.CACertificate)
	kmsServer := kms.NewKMSServer(cfg.KMSURL, cfg.KMSHTTPTimeout, cfg.KMSBackoffMaxRetries, cfg.KMSBackoffBaseDelay, kmsAuth)
	wireguard, err := wg.NewWireGuardHandler()
	if err != nil {
		log.Panicf("Failed to create WireGuard handler: %v", err)
	}
	for {
		go tcpServer(cfg.ListenAddress, result, done)
		go func() {
			for {
				r := <-result
				select {
				case skip <- true:
				default:
				}
				log.Printf("%s received key_id %s", BACKUPPREFIX, r)
				log.Printf("%s fetch key_id from %s\n", BACKUPPREFIX, cfg.KMSURL)
				key, err := kmsServer.GetKeyByID(r)
				if err != nil {
					log.Printf("%s failed to get QKD from KMS: %v", BACKUPPREFIX, err)
				}
				setPSK(wireguard, key.GetKey(), cfg, BACKUPPREFIX)
			}
		}()
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				ticker.Reset(interval)
				select {
				case <-skip:
				default:
					// get key_id and send
					log.Printf("%s fetch QKD key from %s\n", MASTERPREFIX, cfg.KMSURL)
					key, err := kmsServer.GetNewKey()
					if err != nil {
						log.Printf("%s failed to get QKD from KMS: %v", MASTERPREFIX, err)
						ticker.Reset(cfg.KMSRetryInterval)
					} else {
						log.Printf("%s send key_id %s to %s\n", MASTERPREFIX, key.GetID(), cfg.ServerAddress)
						err = tcpClient(cfg.ServerAddress, key.GetID())
						if err != nil {
							log.Println(err.Error())
						}
					}
					setPSK(wireguard, key.GetKey(), cfg, MASTERPREFIX)
				}
				<-ticker.C
			}
		}()
		<-done
		break
	}
}
