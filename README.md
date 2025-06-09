# GoLang C2 Framework

This project contains a simple command-and-control (C2) server and implant written in Go. It is intended for **authorized red team activities and educational use only**.

## Disclaimer
Using this code on networks or hosts without explicit permission may violate laws and regulations. The authors and contributors take no responsibility for any misuse. Always obtain proper authorization before deploying these tools.

## Requirements
- Go 1.22 or newer
- A MySQL instance for the server

## Setup
1. Generate or supply TLS certificates inside the `certs/` directory.
2. Build the server and implant:
   ```bash
   go build ./server
   go build ./implant
   ```
3. Start the server:
   ```bash
   ./server
   ```
4. Run the implant on the target system. It connects to `127.0.0.1:5000` by default.

## Server CLI Usage
The attacker CLI supports the following commands:
- `list` &ndash; display connected implants
- `send <IP> <command>` &ndash; run a command on a specific implant
- `broadcast <command>` &ndash; run a command on all implants
- `remove <IP>` &ndash; remove an implant from the list
- `help` &ndash; show available commands
- `exit` &ndash; terminate the server

## Implant Features
- Connects to the C2 server over TLS and validates the server certificate
- Executes shell commands received from the server
- Encrypts command output using RSA OAEP and sends it back
- Built‑in commands:
  - `sleep <seconds>` &ndash; change the delay between command fetches
  - `sysinfo` &ndash; return basic host and OS information

Use these tools responsibly and only in environments where you have permission.
