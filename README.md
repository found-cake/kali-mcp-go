# kali-mcp-go

Concurrent, policy-aware MCP runtime for authorized security testing with Kali tooling. It connects AI clients to a provisioned security environment while keeping target selection, scan limits, execution evidence, and tool safety explicit.

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/found-cake/kali-mcp-go)](https://goreportcard.com/report/github.com/found-cake/kali-mcp-go)
[![Release](https://img.shields.io/github/v/release/found-cake/kali-mcp-go)](https://github.com/found-cake/kali-mcp-go/releases/latest)

## Contents

- [Highlights](#highlights) · [Architecture](#architecture)
- [Prerequisites](#prerequisites) · [Installation](#installation)
- [Usage](#usage): [Launch mode](#1-choose-a-launch-mode) · [Client registration](#2-register-the-launcher) · [First assessment](#3-start-an-assessment)
- [Configuration](#configuration)
- [Available tools](#available-tools)
- [Detailed reference](#detailed-reference)
- [Project structure](#project-structure) · [Security notice](#security-notice)

## Highlights

| Area | Behavior |
|---|---|
| Multi-agent execution | Concurrent Go server with global and per-target admission controls |
| Streaming | Incremental stdout, stderr, heartbeat, progress, and terminal metadata over SSE |
| Tool routing | Dedicated tools and descriptions for reconnaissance, web assessment, authentication checks, browser verification, and dependency analysis |
| Target safety | Explicit loopback resolution with signed, expiring target contexts; scan tools never silently rewrite targets |
| Scan controls | Profiles, explicit timeouts, rate limits, concurrency limits, health checks, and tool-declared 5xx circuit breaking where supported |
| Evidence | Structured findings, request counts, execution metadata, browser evidence, and paged result artifacts |
| Authentication | Bearer-token authentication with constant-time comparison between `mcp-client` and `kali-server` |
| Agent safety | Tool output is treated as untrusted data, and MCP instructions prohibit replacing the provisioned runtime during an assessment |
| Deployment | One persistent Docker runtime shared by MCP sessions, standalone binaries, VMs, and directly installed Linux hosts |
| Orchestration boundary | Short-lived scan jobs prevent abandoned processes; the MCP host still owns workflow state and credential management |

## Architecture

```
  [AI Client]
  (Claude / Claude Code / Codex / OpenCode / ...)
        │  MCP stdio
        ▼
  [mcp-client]  ← runs through docker exec or as a local binary
        │  HTTP + Bearer token
        ▼
  [kali-server]  ← runs where security tools are installed
        │  exec
        ▼
  [nmap · gobuster · sqlmap · msfconsole · ...]
```

## Prerequisites

| Component | Requirement |
|---|---|
| Persistent Docker | Docker with support for `--pull` and `host-gateway` |
| `kali-server` host | Linux with the required security tools installed (Kali Linux recommended; other Linux distributions are supported when dependencies are available) |
| `mcp-client` host | Linux, Windows, or macOS |
| Build from source | Go 1.27+ |

Core tools: `nmap`, `gobuster`, `dirb`, `nikto`, `tshark`, `sqlmap`, `msfconsole`, `hydra`, `john`, `wpscan`, `enum4linux`

The Docker image also includes `ffuf`, `feroxbuster`, `nuclei`, `whatweb`, `jwt_tool`, `dalfox`, Playwright with Chromium, `retire`, `osv-scanner`, `jq`, Node.js, and npm.

Docker image builds resolve the latest published Dalfox, jwt_tool, and OSV-Scanner releases and the npm `latest` tags for Playwright and Retire.js. Release checksums are verified when upstream publishes them. This keeps security tooling current but means rebuilding the same commit later can produce different tool versions.

## Installation

### Release binaries

Download the matching asset and `checksums.txt` from the [latest release](https://github.com/found-cake/kali-mcp-go/releases/latest).

| Component | Supported targets | Asset name |
|---|---|---|
| `kali-server` | Linux amd64 / arm64 | `kali-server_linux_<arch>` |
| `mcp-client` | Linux amd64 / arm64 | `mcp-client_linux_<arch>` |
| `mcp-client` | macOS amd64 / arm64 | `mcp-client_darwin_<arch>` |
| `mcp-client` | Windows amd64 / arm64 | `mcp-client_windows_<arch>.exe` |

On Linux or macOS, make each downloaded binary executable. Verify its SHA-256 digest against `checksums.txt` before use.

```bash
chmod +x <downloaded-file>
```

### Build from source

```bash
git clone https://github.com/found-cake/kali-mcp-go.git
cd kali-mcp-go

# kali-server (Linux target)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o kali-server ./cmd/kali-server

# mcp-client (native OS)
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mcp-client ./cmd/mcp-client
```

### Docker image (recommended)

The published image contains both binaries and the provisioned security tools. The Raw installer in the usage section pulls it automatically and creates one persistent runtime shared by MCP sessions. Pull it directly only when preparing a manual deployment.

```bash
docker pull ghcr.io/found-cake/kali-mcp-go:latest
```

Use `:rolling` for the biweekly Kali Rolling build, or a version tag such as `:v1.2.3` for a release-aligned deployment. Pin the resolved image digest (`image@sha256:...`) when byte-identical deployment inputs are required. To build locally:

```bash
docker build -t kali-mcp-go:local .
```

## Usage

### 1. Choose a launch mode

| Mode | Best for | MCP launcher |
|---|---|---|
| Persistent Docker | Local Docker with one runtime shared by MCP sessions | `docker exec ...` |
| Separate processes | A VM, remote Kali host, or existing Linux installation | `mcp-client --server ...` |

The **MCP launcher** is the local STDIO command registered with your AI client. Choose one mode below, then use its launcher in the host-specific examples.

#### Persistent Docker

Run the installer for your host directly from the repository's `master` branch. It verifies and caches the Chromium seccomp profile, generates the API token, creates the background `kali-mcp` container with the required runtime options, and checks its health. The script is not saved or used as the MCP launcher.

Linux and macOS:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/found-cake/kali-mcp-go/refs/heads/master/scripts/run-docker.sh \
  | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/found-cake/kali-mcp-go/refs/heads/master/scripts/run-docker.ps1 | iex
```

The installer reads these variables from the `sh` or PowerShell process that executes it:

| Variable | Default | Purpose |
|---|---|---|
| `KALI_MCP_DOCKER_IMAGE` | `ghcr.io/found-cake/kali-mcp-go:latest` | Image tag or digest to install |
| `KALI_MCP_DOCKER_PULL` | `always` | Docker pull policy: `always`, `missing`, or `never` |
| `KALI_MCP_CONTAINER_NAME` | `kali-mcp` | Persistent container name used by subsequent `docker exec` commands |
| `XDG_CACHE_HOME` | `$HOME/.cache` on Linux/macOS; `%LOCALAPPDATA%` on Windows | Parent directory for the verified Chromium seccomp profile |

For example, install a locally built image under a separate container name without pulling:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/found-cake/kali-mcp-go/refs/heads/master/scripts/run-docker.sh \
  | KALI_MCP_DOCKER_IMAGE=kali-mcp-go:local \
    KALI_MCP_DOCKER_PULL=never \
    KALI_MCP_CONTAINER_NAME=kali-mcp-dev \
    sh
```

The same overrides can be set in PowerShell before running its installer:

```powershell
$env:KALI_MCP_DOCKER_IMAGE = "kali-mcp-go:local"
$env:KALI_MCP_DOCKER_PULL = "never"
$env:KALI_MCP_CONTAINER_NAME = "kali-mcp-dev"
irm https://raw.githubusercontent.com/found-cake/kali-mcp-go/refs/heads/master/scripts/run-docker.ps1 | iex
```

Re-running the installer reuses a healthy managed container with the selected name. Remove that container before rerunning when changing its image or Docker options.

Each MCP session starts only the lightweight client process inside that container:

```bash
docker exec -i kali-mcp mcp-client \
  --server http://127.0.0.1:5000 \
  --timeout 3600
```

The token stays in the container configuration and is inherited by `docker exec`; it does not need to be copied into the MCP host configuration. Check readiness with:

```bash
docker exec kali-mcp curl -fsS http://127.0.0.1:5000/health
```

#### Separate server and client

On the machine that has the security tools, start `kali-server` with a shared token:

```bash
export KALI_MCP_API_TOKEN="your-secret-token"
./kali-server  # listens on 127.0.0.1:5000
```

On the MCP host, use the same token with this launcher:

```bash
KALI_MCP_API_TOKEN="your-secret-token" \
  /path/to/mcp-client \
  --server http://127.0.0.1:5000 \
  --timeout 3600
```

For a remote server, keep it bound to loopback and forward the port over SSH:

```bash
ssh -L 5000:127.0.0.1:5000 user@kali-host -N
```

The bearer token authenticates requests but does not encrypt them. Prefer an SSH tunnel or another encrypted private transport instead of exposing the HTTP server directly to an untrusted network.

### 2. Register the launcher

[Claude Code](#claude-code) · [Claude Desktop](#claude-desktop) · [Codex](#openai-codex) · [OpenCode](#opencode-v1)

The following examples use the persistent Docker runtime. For separate processes, register `/path/to/mcp-client` with its `--server` and `--timeout` arguments, then provide `KALI_MCP_API_TOKEN` through the host's MCP environment configuration.

#### Claude Code

```bash
claude mcp add kali-mcp -- \
  docker exec -i kali-mcp mcp-client \
  --server http://127.0.0.1:5000 --timeout 3600
```

#### Claude Desktop

Add a local STDIO server to the desktop configuration:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "docker",
      "args": [
        "exec", "-i", "kali-mcp", "mcp-client",
        "--server", "http://127.0.0.1:5000",
        "--timeout", "3600"
      ]
    }
  }
}
```

#### OpenAI Codex

```bash
codex mcp add kali-mcp -- \
  docker exec -i kali-mcp mcp-client \
  --server http://127.0.0.1:5000 --timeout 3600
```

For explicit startup and tool timeouts, use `~/.codex/config.toml` instead:

```toml
[mcp_servers.kali-mcp]
command = "docker"
args = ["exec", "-i", "kali-mcp", "mcp-client", "--server", "http://127.0.0.1:5000", "--timeout", "3600"]
startup_timeout_sec = 300
tool_timeout_sec = 3600
```

Run `codex mcp list` or `/mcp` inside Codex to verify the connection.

#### OpenCode v1

Add a local STDIO server to `opencode.jsonc`:

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

OpenCode's `timeout` is milliseconds; `mcp-client --timeout` is seconds.

### 3. Start an assessment

After registration:

1. Call `server_health` to confirm that the server and expected tools are available.
2. Call `resolve_target` before scanning `127.0.0.1`, `localhost`, or `[::1]`, including when the intended target runs inside the same environment as `kali-server`.
3. Explicitly select a reachable candidate and pass its signed `target_context` to subsequent tools while it remains valid. Each candidate reports `context_expires_at`; the caller decides when another connectivity check and fresh context are needed.

Loopback targets always refer to the runtime where `kali-server` is running. `resolve_target` reports the runtime address, `host.docker.internal` when available, and the Linux default gateway without silently changing the target. A user can request Kali tools or a black-box assessment without mentioning MCP; the server instructions route the request to the provisioned tools.

For image updates, host networking, file mounts, Chromium sandbox settings, and Nmap capabilities, see [Docker operation](docs/reference.md#docker-operation).

## Configuration

For synchronous long scans, configure the MCP host timeout above `mcp-client --timeout`. When the host propagates its deadline, the client reserves five seconds to cancel the remote process and return accumulated output. A host that forcibly terminates the STDIO process cannot receive a final partial-result envelope. Individual tool requests can still set tighter limits. Use `run_tool_async` when the agent expects a tool to exceed that host deadline or wants to start a new run after a synchronous timeout.

### mcp-client flags

| Flag | Default | Description |
|---|---|---|
| `--server` | `http://127.0.0.1:5000` | kali-server URL |
| `--timeout` | `300` | Base request timeout in seconds; individual tool calls that expose `timeout` can raise it for that request |
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
| `KALI_MCP_SMALL_DIR_WORDLIST` | kali-server | Override the selectable small dir wordlist (default: `/usr/share/wordlists/dirb/small.txt`) |
| `KALI_MCP_JOHN_WORDLIST` | kali-server | Override default John wordlist (default: `/usr/share/wordlists/rockyou.txt`) |
| `KALI_MCP_NUCLEI_TEMPLATES` | kali-server | Nuclei template directory checked by `server_health` (Docker default: `/root/.local/nuclei-templates`) |
| `KALI_MCP_BROWSER_OUTPUT_DIR` | kali-server | Browser handoff directory for request context and screenshots; empty uses the OS temporary directory (Docker default: `/var/lib/kali-mcp/browser`) |

> `ReadTimeout` is enforced for incoming request bodies, while streaming responses remain unrestricted by `WriteTimeout`.

## Available Tools

All 31 registered MCP tools are listed below. **SSE** streams incremental output; **GET** and **POST** use ordinary request/response. Executable tools are synchronous by default; [background jobs](docs/reference.md#background-jobs) provide asynchronous execution.

### Runtime and evidence

| MCP tool | Description | Transport |
|---|---|---|
| `server_health` | Check server status and tool availability | GET |
| `get_scan_capabilities` | Inspect profile compatibility, target formats, supported controls, exact registered input schemas, effective default wordlists, and runtime plugin inventories | GET |
| `resolve_target` | Inspect runtime, resolvable Docker-host, and gateway candidates without rewriting the target | POST |
| `result_artifact_read` | Read a retained artifact completely through bounded byte pages or UTF-8 line ranges, including extracted tool stdout/stderr sections | GET |
| `execute_command` | Execute an arbitrary shell command | SSE |

### Background jobs

See [background job execution and lifecycle](docs/reference.md#background-jobs) for arguments, timeouts, and result expiry.

| MCP tool | Description |
|---|---|
| `run_tool_async` | Start any executable MCP tool as a new background run using that tool's unchanged argument object |
| `scan_job_status` | Read pending progress or terminal state for an asynchronous tool run |
| `scan_job_result` | Read an asynchronous tool run's existing terminal result |
| `scan_job_cancel` | Request cancellation of a pending asynchronous tool run |

### Network and service discovery

| MCP tool | Description | Transport |
|---|---|---|
| `nmap_scan` | Nmap port and service scan | SSE |
| `tshark_capture` | Packet capture and analysis | SSE |
| `enum4linux_scan` | Windows / Samba enumeration | SSE |
| `whatweb_scan` | Web technology and framework fingerprinting | SSE |

### Web assessment and browser verification

| MCP tool | Description | Transport |
|---|---|---|
| `http_request` | Send one bounded HTTP request with structured status, headers, optional target-bound virtual host, body preview, provenance, and artifact output | POST |
| `gobuster_scan` | Directory / DNS / vhost brute-force | SSE |
| `dirb_scan` | Quiet web content scan without request-rate control; use FFUF or Feroxbuster for low-rate discovery | SSE |
| `nikto_scan` | Web server vulnerability scanner with caller-selected installed plugins | SSE |
| `wpscan_analyze` | WordPress vulnerability scanner | SSE |
| `ffuf_scan` | Web content discovery with automatic calibration, size filtering, and optional recursion | SSE |
| `feroxbuster_scan` | Recursive web content discovery with automatic tuning | SSE |
| `nuclei_scan` | Nuclei scan with local template-selection preview; DoS, fuzz, DAST, OAST, and interactsh behavior is excluded unless explicitly enabled | SSE |
| `sqlmap_scan` | SQL injection scanner | SSE |
| `dalfox_scan` | XSS candidate scanning with JSON findings | SSE |
| `browser_check` | Headless Chromium verification with per-call headers, cookies, origin-scoped `local_storage`, dialogs, console output, page errors, and optional rendered DOM | SSE |

### Authentication and exploitation tools

| MCP tool | Description | Transport |
|---|---|---|
| `jwt_analyze` | JWT decoding and optional live playbook/forced-error/all-tests assessment | SSE |
| `hydra_attack` | Password brute-force for quick single-credential checks | POST |
| `hydra_attack_stream` | Password brute-force for long-running or file-based jobs with streaming progress | SSE |
| `john_crack` | Password hash cracker | POST |
| `metasploit_run` | Execute a Metasploit module via msfconsole | POST |

### Dependency analysis

| MCP tool | Description | Transport |
|---|---|---|
| `retirejs_scan` | Vulnerable JavaScript dependency scan from a local path or public bundles downloaded from a page URL | SSE |
| `osv_scan` | OSV dependency scan for mounted source trees and lockfiles | SSE |

## Detailed reference

The [reference guide](docs/reference.md) preserves the operational details and tool-specific behavior:

| Topic | Reference |
|---|---|
| Docker deployment | [Images, networking, files, Chromium sandbox, and Nmap capabilities](docs/reference.md#docker-operation) |
| Execution lifecycle | [Streaming and timeouts](docs/reference.md#streaming-and-timeouts), [background jobs](docs/reference.md#background-jobs), and [cancellation](docs/reference.md#cancellation-and-heartbeats) |
| Results and evidence | [Structured results](docs/reference.md#structured-results), [artifact paging](docs/reference.md#artifact-paging), and [retention and redaction](docs/reference.md#artifact-retention-and-redaction) |
| Targets and controls | [Explicit target resolution](docs/reference.md#explicit-target-resolution), [safety profiles](docs/reference.md#safety-profiles-and-controls), and [credential management](docs/reference.md#credential-management) |
| Tool behavior | [Natural-language routing](docs/reference.md#natural-language-tool-routing), [SQLmap inputs](docs/reference.md#sqlmap-json-and-raw-requests), [manual HTTP](docs/reference.md#bounded-manual-http-requests), and [discovery baselines](docs/reference.md#scan-load-and-spa-baselines) |
| Browser and authentication | [Browser local storage](docs/reference.md#browser-local-storage), [John and JWT workspaces](docs/reference.md#john-and-jwt-workspaces), and [Hydra modes](docs/reference.md#choosing-between-hydra_attack-and-hydra_attack_stream) |

## Project Structure

```
kali-mcp-go/
├── cmd/
│   ├── kali-server/            # HTTP/SSE execution server
│   │   └── internal/
│   │       ├── server/         # process lifecycle and composition
│   │       ├── httpapi/        # Fiber transport adapters
│   │       └── toolapi/        # tool routes, validation, and execution plans
│   └── mcp-client/             # MCP stdio bridge and tool registration
├── internal/
│   ├── admission/              # global and per-target execution limits
│   ├── artifacts/              # bounded evidence storage and paging
│   ├── executor/               # command execution and process streaming
│   ├── httpexec/               # bounded manual HTTP requests
│   ├── jobs/                   # short-lived asynchronous process lifecycle
│   ├── kaliclient/             # authenticated HTTP/SSE client
│   ├── results/                # result normalization and evidence protection
│   ├── streaming/              # progress, heartbeat, and terminal events
│   ├── targeting/              # target contexts, receipts, and provenance
│   └── tools/                  # registry, policies, and argument builders
├── scripts/                    # persistent Docker installers and platform tests
└── pkg/
    └── dto/                    # shared request and result contracts
```

## Security Notice

> ⚠️ Only target systems you own or have explicit written permission to test.
>
> `execute_command` runs arbitrary shell commands as the server process user — restrict network access appropriately and prefer an SSH tunnel over direct exposure.
