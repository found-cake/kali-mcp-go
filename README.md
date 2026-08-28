# kali-mcp-go

Go reimplementation of [MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server), built to eliminate the bottlenecks encountered when running multiple AI agents simultaneously.

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)](https://go.dev/)
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
| Build from source | Go 1.27+ |

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

### Option C — Docker (single-command MCP setup)

The published image contains `mcp-client`, `kali-server`, and the required Kali security tools. The container starts `kali-server` internally and exposes the MCP client's stdio transport, so no separate server process or port mapping is required.

No API token configuration is required in Docker mode. When `KALI_MCP_API_TOKEN` is not provided, the container generates an ephemeral token and shares it only between its internal `kali-server` and `mcp-client` processes.

#### Faster startup with a persistent container

If starting a fresh container whenever the MCP host opens is too slow, keep `kali-server` running and have the host start only `mcp-client` with `docker exec`. The image is pulled and initialized once, and no host port is exposed.

Start the server container:

```bash
docker run -d \
  --name kali-mcp \
  --restart unless-stopped \
  --entrypoint kali-server \
  -e KALI_MCP_API_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/found-cake/kali-mcp-go:latest \
  --ip 127.0.0.1 --port 5000
```

The token is generated once and stored in the container configuration so `docker exec` processes receive the same value. It does not need to be copied into the MCP host configuration.

##### Claude Code

```bash
claude mcp add kali-mcp -- \
  docker exec -i kali-mcp mcp-client \
  --server http://127.0.0.1:5000 --timeout 3600
```

##### OpenAI Codex

```bash
codex mcp add kali-mcp -- \
  docker exec -i kali-mcp mcp-client \
  --server http://127.0.0.1:5000 --timeout 3600
```

Run `codex mcp list` to verify the registration, or `/mcp` inside Codex to inspect the connected server.

For longer scans, the equivalent `~/.codex/config.toml` configuration is:

```toml
[mcp_servers.kali-mcp]
command = "docker"
args = ["exec", "-i", "kali-mcp", "mcp-client", "--server", "http://127.0.0.1:5000", "--timeout", "3600"]
startup_timeout_sec = 30
tool_timeout_sec = 3600
```

##### OpenCode v1

Add the following local STDIO server to `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "kali-mcp": {
      "type": "local",
      "command": [
        "docker", "exec", "-i", "kali-mcp", "mcp-client",
        "--server", "http://127.0.0.1:5000",
        "--timeout", "3600"
      ],
      "enabled": true,
      "timeout": 3600000
    }
  }
}
```

Check the persistent server independently at any time:

```bash
docker exec kali-mcp curl -fsS http://127.0.0.1:5000/health
```

This mode intentionally does not check for a new image whenever the MCP host starts. To upgrade, pull the desired tag and recreate the `kali-mcp` container. Add networking capabilities and mounts to the initial `docker run` command when needed.

#### One-shot container

The following setup is simpler and automatically removes the container when the MCP host exits, but Docker checks the image and initializes a new container each time.

##### Claude Code

```bash
claude mcp add kali-mcp -- docker run --pull=always --rm -i ghcr.io/found-cake/kali-mcp-go:latest
```

##### OpenAI Codex

Register the container as a local STDIO MCP server:

```bash
codex mcp add kali-mcp -- docker run --pull=always --rm -i ghcr.io/found-cake/kali-mcp-go:latest
```

Run `codex mcp list` to verify the registration, or `/mcp` inside Codex to inspect the connected server. Codex CLI, the IDE extension, and the ChatGPT desktop app share the same MCP configuration.

For longer scans, configure the server directly in `~/.codex/config.toml`:

```toml
[mcp_servers.kali-mcp]
command = "docker"
args = ["run", "--pull=always", "--rm", "-i", "ghcr.io/found-cake/kali-mcp-go:latest", "--timeout", "3600"]
startup_timeout_sec = 300
tool_timeout_sec = 3600
```

##### OpenCode v1

Add the following local STDIO server to `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "kali-mcp": {
      "type": "local",
      "command": [
        "docker", "run", "--pull=always", "--rm", "-i",
        "ghcr.io/found-cake/kali-mcp-go:latest",
        "--timeout", "3600"
      ],
      "enabled": true,
      "timeout": 3600000
    }
  }
}
```

OpenCode's `timeout` is milliseconds, while the container's `--timeout` value is seconds. The longer OpenCode timeout also gives Docker enough time to pull the image on its first run.

The examples above use the stable `latest` channel. Replace `:latest` with `:rolling` in any command or configuration to use the biweekly Kali Rolling image.

##### Other MCP hosts

Use this as the local STDIO MCP server command:

```bash
docker run --pull=always --rm -i ghcr.io/found-cake/kali-mcp-go:latest
```

To build and run the image locally instead of pulling from GHCR:

```bash
docker build -t kali-mcp-go:local . && docker run --rm -i kali-mcp-go:local
```

To use a fixed token instead of the generated one, pass it explicitly with `-e KALI_MCP_API_TOKEN=your-secret-token`. This is optional in Docker mode but remains required when running `kali-server` and `mcp-client` as separate processes.

The `latest` and versioned images are built from Kali's last release when a project release tag is published. The `rolling` image is rebuilt from Kali Rolling every two weeks and whenever a project release tag is published. `--pull=always` checks the registry whenever the MCP server starts, but Docker downloads image layers only when the published digest has changed. Use a version tag such as `:v1.2.3` and omit `--pull=always` if you prefer a fixed image.

The container uses Docker's default network. For Linux host networking, localhost targets, or packet capture, add `--network host --cap-add NET_ADMIN --cap-add NET_RAW` when your Docker environment supports it. Mount host files explicitly when a tool needs them, for example `-v "$PWD:/workspace:ro"`, and use the resulting `/workspace/...` path in the tool request.

> **Security:** The image intentionally includes `execute_command` and runs Kali tools inside the container. The generated token protects the container's internal API but does not restrict what the container can reach. Restrict its network access where practical, and only test systems you own or have explicit written permission to assess.

---

## Usage

### 1. Start kali-server

Set a strong API token and start the server on the machine where your security tools are installed. The default port is **5000**.

```bash
export KALI_MCP_API_TOKEN="your-secret-token"

./kali-server                           # binds to 127.0.0.1:5000
./kali-server --ip 0.0.0.0 --port 5000  # expose on all interfaces
./kali-server --debug                   # verbose logging
./kali-server --max-concurrent 30       # allow up to 30 concurrent execution requests
```

`kali-server` limits concurrent execution requests to protect server resources. When the limit is exceeded, the server returns `503 Service Unavailable`.

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

#### OpenAI Codex

```bash
codex mcp add kali-mcp \
  --env KALI_MCP_API_TOKEN=your-secret-token \
  -- /path/to/mcp-client --server http://127.0.0.1:5000 --timeout 3600
```

Equivalent `~/.codex/config.toml` configuration:

```toml
[mcp_servers.kali-mcp]
command = "/path/to/mcp-client"
args = ["--server", "http://127.0.0.1:5000", "--timeout", "3600"]
env = { KALI_MCP_API_TOKEN = "your-secret-token" }
tool_timeout_sec = 3600
```

#### OpenCode

For long-running scans, raise both:

- the **host-side MCP execution timeout**
- the **mcp-client base request timeout** via `--timeout`

This is the recommended setup for long-running tools such as `dirb_scan`, `nikto_scan`, `sqlmap_scan`, and long `execute_command` sessions.

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "kali-mcp": {
      "type": "local",
      "command": [
        "/path/to/mcp-client",
        "--server", "http://127.0.0.1:5000",
        "--timeout", "3600"
      ],
      "environment": {
        "KALI_MCP_API_TOKEN": "your-secret-token"
      },
      "enabled": true,
      "timeout": 3600000
    }
  }
}
```

Notes:

- `mcp.kali-mcp.timeout` controls the OpenCode-side MCP request timeout in milliseconds.
- `--timeout` controls the `mcp-client` base request timeout in seconds.
- For long-running scans, set **both**. Raising only one layer may still leave the other layer timing out early.

### mcp-client flags

| Flag | Default | Description |
|---|---|---|
| `--server` | `http://127.0.0.1:5000` | kali-server URL |
| `--timeout` | `300` | Base request timeout in seconds; individual streaming tools can raise this per request with their `timeout` field |
| `--debug` | `false` | Verbose stderr logging |

### kali-server flags

| Flag | Default | Description |
|---|---|---|
| `--ip` | `127.0.0.1` | Bind address |
| `--port` | `5000` | Listen port |
| `--debug` | `false` | Verbose request logging |
| `--max-concurrent` | `10` | Maximum number of concurrent execution requests before the server returns `503 Service Unavailable` |

### Environment variables

| Variable | Component | Description |
|---|---|---|
| `KALI_MCP_API_TOKEN` | both | Bearer token for API authentication; required for separate processes, optional in Docker mode because the entrypoint generates one when omitted |
| `KALI_MCP_DIR_WORDLIST` | kali-server | Override default dir wordlist (default: `/usr/share/wordlists/dirb/common.txt`) |
| `KALI_MCP_JOHN_WORDLIST` | kali-server | Override default John wordlist (default: `/usr/share/wordlists/rockyou.txt`) |

> `ReadTimeout` is enforced for incoming request bodies, while streaming responses remain unrestricted by `WriteTimeout`.

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

Streaming requests support an optional `timeout` field (seconds) to override the default 300-second request limit for that specific run. For `tshark_capture`, this request `timeout` is distinct from the capture `duration` field.

When using OpenCode, the per-tool request `timeout` is not enough by itself for long scans. You should also raise OpenCode's MCP execution timeout and the local `mcp-client --timeout` value as shown above.

For Codex and other MCP hosts, you may still want a larger `mcp-client --timeout` value for long-running tools, but OpenCode's `mcp.<name>.timeout` setting does not apply there.

Quiet streams may also emit lightweight heartbeat SSE events to keep the connection active until the final `done` event arrives.

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
