# kali-mcp-go

Go reimplementation of [MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server), built to eliminate the bottlenecks encountered when running multiple AI agents simultaneously.

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/found-cake/kali-mcp-go)](https://goreportcard.com/report/github.com/found-cake/kali-mcp-go)
[![Release](https://img.shields.io/github/v/release/found-cake/kali-mcp-go)](https://github.com/found-cake/kali-mcp-go/releases/latest)

---

## Background

[MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server) by [@Wh0am123](https://github.com/Wh0am123) was the project that first proved connecting AI agents to Kali Linux tools over MCP works — it's even shipped as an official Kali package. This project owes a lot to that work.

The rewrite was motivated by running into real bottlenecks when spinning up multiple AI agents in parallel against CTF challenges:

| | MCP-Kali-Server (Python) | kali-mcp-go (Go) |
|---|---|---|
| Concurrency | Flask single-worker — agents block each other | Fiber v3 / fasthttp — fully concurrent |
| Output delivery | Buffered: full output returned when process exits | SSE streaming: output delivered line by line |
| Authentication | None | Bearer token (SHA-256 constant-time comparison) |
| Metasploit temp files | Hardcoded `/tmp/mks_msf_resource.rc` | `os.CreateTemp` — race-free, unique filenames |
| Prompt injection defense | — | Safety instructions baked into MCP server |

---

## Architecture

```
  [AI Client]
  (Claude / Claude Code / Codex / OpenCode / ...)
        │  MCP stdio
        ▼
  [mcp-client]  ← runs on your local machine
        │  HTTP + Bearer token
        ▼
  [kali-server]  ← runs where security tools are installed
        │  exec
        ▼
  [nmap · gobuster · sqlmap · msfconsole · ...]
```

---

## Prerequisites

| Component | Requirement |
|---|---|
| `kali-server` host | Any environment with the required security tools installed (Kali Linux, other Linux distros, macOS, etc.) |
| `mcp-client` host | Linux, Windows, or macOS |
| Build from source | Go 1.26+ |

Required tools: `nmap`, `gobuster`, `dirb`, `nikto`, `tshark`, `sqlmap`, `msfconsole`, `hydra`, `john`, `wpscan`, `enum4linux`

---

## Installation

### Option A — Pre-built binaries (recommended)

Download the latest binaries from the [Releases page](https://github.com/found-cake/kali-mcp-go/releases/latest).

**kali-server:**

```bash
# x86_64
curl -L https://github.com/found-cake/kali-mcp-go/releases/latest/download/kali-server_linux_amd64 \
  -o kali-server && chmod +x kali-server

# arm64
curl -L https://github.com/found-cake/kali-mcp-go/releases/latest/download/kali-server_linux_arm64 \
  -o kali-server && chmod +x kali-server
```

**mcp-client:**

```bash
# Linux x64
curl -L https://github.com/found-cake/kali-mcp-go/releases/latest/download/mcp-client_linux_amd64 \
  -o mcp-client && chmod +x mcp-client

# Linux arm64
curl -L https://github.com/found-cake/kali-mcp-go/releases/latest/download/mcp-client_linux_arm64 \
  -o mcp-client && chmod +x mcp-client

# macOS Apple Silicon
curl -L https://github.com/found-cake/kali-mcp-go/releases/latest/download/mcp-client_darwin_arm64 \
  -o mcp-client && chmod +x mcp-client

# macOS Intel
curl -L https://github.com/found-cake/kali-mcp-go/releases/latest/download/mcp-client_darwin_amd64 \
  -o mcp-client && chmod +x mcp-client

# Windows x64
curl -L https://github.com/found-cake/kali-mcp-go/releases/latest/download/mcp-client_windows_amd64.exe -o mcp-client.exe

# Windows arm64
curl -L https://github.com/found-cake/kali-mcp-go/releases/latest/download/mcp-client_windows_arm64.exe -o mcp-client.exe
```

Verify integrity with `checksums.txt` from the same release:

```bash
sha256sum -c checksums.txt
```

### Option B — Build from source

```bash
git clone https://github.com/found-cake/kali-mcp-go.git
cd kali-mcp-go

# kali-server (Linux target)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o kali-server ./cmd/kali-server

# mcp-client (native OS)
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mcp-client ./cmd/mcp-client
```

---

## Usage

### 1. Start kali-server

Set a strong API token and start the server on the machine where your security tools are installed. The default port is **5000**.

```bash
export KALI_MCP_API_TOKEN="your-secret-token"

./kali-server                           # binds to 127.0.0.1:5000
./kali-server --ip 0.0.0.0 --port 5000  # expose on all interfaces
./kali-server --debug                   # verbose logging
```

> **Tip:** Use an SSH tunnel instead of exposing `kali-server` directly on the network — it's simpler and more secure:
> ```bash
> # On your local machine: forward localhost:5000 → remote:5000
> ssh -L 5000:127.0.0.1:5000 user@kali-host -N
> ```
> Then point `mcp-client` at `http://127.0.0.1:5000` as usual.

### 2. Connect your AI client

Set the same token in your local environment, then add `mcp-client` to your AI client's MCP configuration.

#### Claude Desktop

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "/path/to/mcp-client",
      "args": ["--server", "http://127.0.0.1:5000"],
      "env": {
        "KALI_MCP_API_TOKEN": "your-secret-token"
      }
    }
  }
}
```

#### Claude Code

```bash
claude mcp add kali-mcp \
  -e KALI_MCP_API_TOKEN=your-secret-token \
  -- /path/to/mcp-client --server http://127.0.0.1:5000
```

#### OpenAI Codex / OpenCode

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "/path/to/mcp-client",
      "args": ["--server", "http://127.0.0.1:5000"],
      "env": {
        "KALI_MCP_API_TOKEN": "your-secret-token"
      }
    }
  }
}
```

### mcp-client flags

| Flag | Default | Description |
|---|---|---|
| `--server` | `http://127.0.0.1:5000` | kali-server URL |
| `--timeout` | `300` | Base request timeout in seconds |
| `--debug` | `false` | Verbose stderr logging |

### kali-server flags

| Flag | Default | Description |
|---|---|---|
| `--ip` | `127.0.0.1` | Bind address |
| `--port` | `5000` | Listen port |
| `--debug` | `false` | Verbose request logging |

### Environment variables

| Variable | Component | Description |
|---|---|---|
| `KALI_MCP_API_TOKEN` | both | **Required.** Bearer token for API authentication |
| `KALI_MCP_DIR_WORDLIST` | kali-server | Override default dir wordlist (default: `/usr/share/wordlists/dirb/common.txt`) |
| `KALI_MCP_JOHN_WORDLIST` | kali-server | Override default John wordlist (default: `/usr/share/wordlists/rockyou.txt`) |

---

## Available Tools

| MCP tool | Description |
|---|---|
| `server_health` | Check server status and tool availability |
| `execute_command` | Execute an arbitrary shell command (SSE streaming) |
| `nmap_scan` | Nmap port and service scan (SSE streaming) |
| `gobuster_scan` | Directory / DNS / vhost brute-force (POST result) |
| `dirb_scan` | Web content scanner (SSE streaming) |
| `nikto_scan` | Web server vulnerability scanner (SSE streaming) |
| `tshark_capture` | Packet capture and analysis (SSE streaming) |
| `sqlmap_scan` | SQL injection scanner (SSE streaming) |
| `metasploit_run` | Execute a Metasploit module via msfconsole |
| `hydra_attack` | Password brute-force for quick single-credential checks (POST result) |
| `hydra_attack_stream` | Password brute-force for long-running or file-based jobs with streaming progress |
| `john_crack` | Password hash cracker |
| `wpscan_analyze` | WordPress vulnerability scanner (SSE streaming) |
| `enum4linux_scan` | Windows / Samba enumeration (SSE streaming) |

### SSE support summary

These MCP tools now stream incremental output over SSE instead of waiting for a buffered final result:

- `execute_command`
- `nmap_scan`
- `dirb_scan`
- `nikto_scan`
- `wpscan_analyze`
- `enum4linux_scan`
- `sqlmap_scan`
- `tshark_capture`

These tools still use a normal POST request/response flow:

- `gobuster_scan`
- `metasploit_run`
- `john_crack`
- `server_health`

### Choosing between `hydra_attack` and `hydra_attack_stream`

- Use `hydra_attack` for quick checks such as a single username/password attempt or other short runs where a buffered final result is sufficient.
- Use `hydra_attack_stream` for long-running Hydra jobs when you want progress as it happens, especially with `username_file` and/or `password_file` inputs.

---

## Project Structure

```
kali-mcp-go/
├── cmd/
│   ├── kali-server/      # HTTP API server
│   └── mcp-client/       # MCP stdio bridge
├── internal/
│   ├── executor/         # Command execution + SSE streaming
│   ├── kaliclient/       # HTTP client for kali-server
│   └── tools/            # Tool argument builders + validation
└── pkg/
    └── dto/              # Shared request/response types
```

---

## Security Notice

> ⚠️ Only target systems you own or have explicit written permission to test.
>
> `execute_command` runs arbitrary shell commands as the server process user — restrict network access appropriately and prefer an SSH tunnel over direct exposure.

---

## Acknowledgments

This project exists because [MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server) by [@Wh0am123](https://github.com/Wh0am123) proved the concept and shaped the two-tier architecture. Full credit to the original for pioneering AI-assisted pentesting over MCP.
