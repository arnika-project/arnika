package main

import (
	"bufio"
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
			// expected
			// fmt.Println("Failed to read from connection:", errRead)
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
				log.Println(err.Error())
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

func setPSK(wireguard *wg.WireGuardHandler, psk string, cfg *config.Config, logPrefix string) error {
	if cfg.UsePQC() {
		log.Println(logPrefix + " key derivation with PQC key enabled")
		pQCKey, err := getPQCKey(cfg.PQCPSKFile)
		if err != nil {
			if cfg.IsPQCRequired() {
				if err2 := wireguard.SetRandomPSK(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey); err2 != nil {
					err = fmt.Errorf("%w, failed to set random PSK: %w", err, err2)
				}
				return fmt.Errorf("%s failed to read PQC key from file: %w, configure random PSK since mode is set to %s", logPrefix, err, cfg.Mode)
			}
			log.Println(logPrefix + " failed to read PQC key from file, using only KMS key since mode is set to " + cfg.Mode)
		} else {
			if pQCKey != "" {
				psk, err = kdf.DeriveKey(psk, pQCKey)
				if err != nil {
					return err
				}
			}
		}
	}
	if psk == "" {
		if err := wireguard.SetRandomPSK(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey); err != nil {
			return fmt.Errorf("%s failed to set random PSK: %w", logPrefix, err)
		}
		return fmt.Errorf("%s no keys left, configure random PSK", logPrefix)
	}
	log.Println(logPrefix + " configure wireguard interface")
	return wireguard.SetKey(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey, psk)
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
				log.Println("<-- BACKUP: received key_id " + r)
				log.Printf("<-- BACKUP: fetch key_id from %s\n", cfg.KMSURL)
				// to stuff with key
				key, err := kmsServer.GetKeyByID(r)
				if err != nil {
					log.Printf("<-- BACKUP: failed to get qkd from kms: %v", err)
					if cfg.IsQKDRequired() {
						log.Printf("<-- BACKUP: mode set to %s, configure random PSK", cfg.Mode)
						err = wireguard.SetRandomPSK(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey)
						if err != nil {
							log.Println(err.Error())
						}
						time.Sleep(time.Millisecond * 100)
						continue
					}
					log.Printf("<-- BACKUP: proceeding since mode set to \"%s\"\n", cfg.Mode)
				}
				err = setPSK(wireguard, key.GetKey(), cfg, "<-- BACKUP:")
				if err != nil {
					log.Printf("<-- BACKUP: unable to set random PSK: %v", err)
				}
			}
		}()
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-skip:
				default:
					// get key_id and send
					log.Printf("--> MASTER: fetch qkd key from %s\n", cfg.KMSURL)
					key, err := kmsServer.GetNewKey()
					if err != nil {
						log.Printf("--> MASTER: failed to get qkd from kms: %v", err)
						if cfg.IsQKDRequired() {
							log.Printf("--> MASTER: mode set to %s, configure random PSK", cfg.Mode)
							err = wireguard.SetRandomPSK(cfg.WireGuardInterface, cfg.WireguardPeerPublicKey)
							if err != nil {
								log.Printf("--> MASTER: unable to set random PSK: %v", err)
							}
							time.Sleep(cfg.KMSRetryInterval)
							continue
						}
						log.Printf("--> MASTER: proceeding since mode set to \"%s\"\n", cfg.Mode)
					} else {
						log.Printf("--> MASTER: send key_id %s to %s\n", key.GetID(), cfg.ServerAddress)
						err = tcpClient(cfg.ServerAddress, key.GetID())
						if err != nil {
							log.Println(err.Error())
						}
					}
					err = setPSK(wireguard, key.GetKey(), cfg, "--> MASTER:")
					if err != nil {
						log.Println(err.Error())
					}
				}
				<-ticker.C
			}
		}()
		<-done
		break
	}
}
