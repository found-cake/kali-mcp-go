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

Core tools: `nmap`, `gobuster`, `dirb`, `nikto`, `tshark`, `sqlmap`, `msfconsole`, `hydra`, `john`, `wpscan`, `enum4linux`

The Docker image also includes `ffuf`, `feroxbuster`, `nuclei`, `whatweb`, `jwt_tool`, `dalfox`, Playwright with Chromium, `retire`, `osv-scanner`, `jq`, Node.js, and npm.

Source builds resolve the latest published Dalfox, jwt_tool, and OSV-Scanner releases and the npm `latest` tags for Playwright and Retire.js at image build time. Release checksums are verified when upstream publishes them. This keeps security tooling current but means rebuilding the same commit later can produce different tool versions.

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

Once registered, prompts that ask for Kali tools or a black-box assessment should call the relevant tools from this existing MCP runtime directly. Call `resolve_target` before scanning a loopback target. MCP instructions prohibit checking the host for Kali binaries or installing, pulling, building, or starting a second Kali environment.

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

The container uses Docker's default network. Scan tools never rewrite loopback targets: `127.0.0.1`, `localhost`, and `[::1]` always refer to the runtime where `kali-server` is running. Call `resolve_target` once to inspect the Kali runtime, `host.docker.internal` when it resolves, and the Linux default gateway. Each candidate includes a `browser_target` URL when the input was a URL, a `network_target` hostname or IP for tools such as Nmap, the probed port, and a signed `target_context`. Select one candidate explicitly and reuse its context until `context_expires_at`; re-resolve only after expiry, connectivity failure, or an environment change. The context is self-contained and server-side target sessions are not stored. On Linux, persistent containers may need `--add-host host.docker.internal:host-gateway`.

Nmap's packaged file capability is removed during image construction because Docker rejects execution when that capability exceeds the container bounding set. TCP connect scans such as `-sT -Pn` work with Docker's default capabilities. Add `--cap-add NET_RAW --cap-add NET_ADMIN` only when a scan that actually opens raw sockets requires them. For troubleshooting, check the Nmap binary permissions and file capabilities, mount options, and seccomp/AppArmor policy before adding capabilities.

Mount host files explicitly when a tool needs them, for example `-v "$PWD:/workspace:ro"`, and use the resulting `/workspace/...` path in the tool request.

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
| `get_scan_capabilities` | Inspect profile compatibility, target formats, supported controls, and effective default wordlists |
| `resolve_target` | Inspect runtime, resolvable Docker-host, and gateway candidates without rewriting the target |
| `result_artifact_read` | Read a bearer-protected JSON result retained for one hour after a scan |
| `http_request` | Send one bounded HTTP request with structured status, headers, body preview, provenance, and artifact output |
| `execute_command` | Execute an arbitrary shell command (SSE streaming) |
| `nmap_scan` | Nmap port and service scan (SSE streaming) |
| `gobuster_scan` | Directory / DNS / vhost brute-force (SSE streaming) |
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
| `ffuf_scan` | Web content discovery with automatic calibration, size filtering, and optional recursion |
| `feroxbuster_scan` | Recursive web content discovery with automatic tuning |
| `nuclei_scan` | Nuclei scan; DoS, fuzz, and OAST templates are excluded unless explicitly enabled |
| `whatweb_scan` | Web technology and framework fingerprinting |
| `jwt_analyze` | JWT decoding and optional live playbook/forced-error/all-tests assessment |
| `dalfox_scan` | XSS candidate scanning with JSON findings |
| `browser_check` | Headless Chromium verification of dialogs, console output, page errors, and optional rendered DOM |
| `retirejs_scan` | Vulnerable JavaScript dependency scan from a local path or public bundles downloaded from a page URL |
| `osv_scan` | OSV dependency scan for mounted source trees and lockfiles |

### SSE support summary

These MCP tools now stream incremental output over SSE instead of waiting for a buffered final result:

- `execute_command`
- `nmap_scan`
- `gobuster_scan`
- `dirb_scan`
- `nikto_scan`
- `wpscan_analyze`
- `enum4linux_scan`
- `sqlmap_scan`
- `tshark_capture`
- `ffuf_scan`
- `feroxbuster_scan`
- `nuclei_scan`
- `whatweb_scan`
- `jwt_analyze`
- `dalfox_scan`
- `browser_check`
- `retirejs_scan`
- `osv_scan`

Streaming requests support an optional `timeout` field (seconds) to override the default 300-second request limit for that specific run. For `tshark_capture`, this request `timeout` is distinct from the capture `duration` field.

When using OpenCode, the per-tool request `timeout` is not enough by itself for long scans. You should also raise OpenCode's MCP execution timeout and the local `mcp-client --timeout` value as shown above.

For Codex and other MCP hosts, you may still want a larger `mcp-client --timeout` value for long-running tools, but OpenCode's `mcp.<name>.timeout` setting does not apply there.

Quiet streams may also emit lightweight heartbeat SSE events to keep the connection active until the final `done` event arrives.

These tools still use a normal POST request/response flow:

- `metasploit_run`
- `john_crack`
- `server_health`

### Structured results

Every tool exposes an MCP output schema and returns both readable text and structured content. The structured result separates:

- `status`: `completed`, `failed`, `timeout`, or `cancelled`
- `success`: derived from `status`; a timeout or cancellation is never reported as successful
- `execution_status`: the detailed process state retained for existing clients
- `finding_status`: `detected`, `not_detected`, or `unknown`
- `partial_results`, `http_requests`, `duration_ms`, original stdout/stderr byte counts, and `output_truncated`
- `target`: original target, explicitly selected target, resolution ID, and selection basis
- `execution`: redacted argv, tool version, start time, timeout, profile, rate, concurrency, request budget, health URL, and 5xx threshold
- `failure`: reason, retryability, resume support, and the bounded cost of a fresh retry
- `artifacts`: opaque IDs and bearer-protected locations for JSON results retained for one hour

Tool process failures and timeouts set MCP `isError`; a successful scan with no finding does not.

`http_requests` is `null` when a tool cannot report an exact request count. A failure with output sets `partial_results`. Inline stdout and stderr are UTF-8-safe previews capped at 8 KiB each; `stdout_bytes` and `stderr_bytes` report the original redacted sizes. Use `result_artifact_read` with offset 0, then continue with `next_offset` while `has_more` is true.

### Explicit target resolution

Scan tools never silently rewrite a target. `127.0.0.1`, `localhost`, and `[::1]` refer to the machine or container running `kali-server`, whether that runtime is Docker, a VM, or a directly installed Linux host.

For a loopback target, call `resolve_target`, choose one returned candidate, and pass its `target_context` to subsequent scan tools. Network tools derive the candidate's explicit network host, while web tools use its browser URL and may accept a same-origin path extension. Contexts are signed, default to ten minutes, and may request up to one hour with `valid_for_seconds`; they are never renewed without another connectivity check. The older target plus `resolution_receipt` form remains supported. Loopback scans without either proof are rejected. Non-loopback targets remain usable directly, but their results carry an unverified-target warning.

### Safety profiles and budgets

Dedicated scan requests accept a `profile` plus optional `max_requests`, `rate_limit`, `concurrency`, `health_url`, and `max_5xx_responses` controls. Available profiles are:

Call `get_scan_capabilities` before composing a scan when profile compatibility or a wordlist path is uncertain. Its response uses MCP-facing tool names, reports the effective environment-configured defaults, and marks missing wordlist files unavailable. An explicitly supplied missing wordlist remains an error and is never silently replaced.

| Profile | Intended use |
|---|---|
| `safe-recon` | Low-impact service and technology reconnaissance |
| `web-discovery-low-rate` | Bounded path discovery with conservative concurrency |
| `sqli-verify-low-risk` | Targeted SQL injection verification with a low request rate |
| `browser-xss-confirm` | Browser-backed confirmation of a specific XSS candidate |
| `explicit-custom` | Explicit caller-supplied controls within hard server limits |

The server limits total work and weighted work per target. Heavy tools cannot run concurrently against the same target. Supported tools receive native rate, concurrency, and request-limit flags; the outer timeout also shrinks to the request/rate budget. When `health_url` is present, the server probes it before and after the run. JSON-producing scanners are cancelled when `max_5xx_responses` is reached. Nuclei DoS, fuzz, and interactsh selectors remain blocked unless `allow_unsafe` is explicitly enabled.

### Credential management

`kali-server` does not store or manage authentication tokens and cookies. Manage them directly using safeguards appropriate to your environment, and pass them only in request-scoped fields supported by the selected tool. The server does not create, list, retain, or reuse credential sessions across calls, and sensitive command arguments remain redacted from execution metadata.

### Natural-language tool routing

The MCP server instructions and tool descriptions identify authorized black-box penetration testing, security assessment, reconnaissance, enumeration, and requests to use Kali tools as intended use cases. Users do not need to say `MCP` or `kali-mcp`. Include an explicit authorized target and scope, for example: `Run an authorized black-box assessment of http://127.0.0.1:3000 with Kali tools; resolve the target first, then enumerate ports, services, and web technologies.`

### SQLmap JSON and raw requests

`sqlmap_scan` accepts exactly one of `url`, `request_file`, or `raw_request`. It supports JSON bodies with SQLmap's `*` injection marker, named test parameters, headers, cookies, content type, and expected error codes. Raw requests, traffic logs, and SQLmap output are kept in a mode-restricted temporary workspace and deleted after completion. `--ignore-stdin` is applied automatically so MCP's non-TTY process input cannot override a supplied raw request.

### Bounded manual HTTP requests

Use `http_request` instead of `execute_command` with curl for one-off validation. It accepts HTTP(S) only, one request per call, an optional arbitrary `json_body`, bounded raw bodies and responses, a maximum 300-second timeout, and at most five same-origin redirects. Loopback targets require a selected `target_context` or the legacy explicit URL plus receipt. Authorization, Cookie, and Set-Cookie values are masked before inline output or artifact storage.

### Scan load, SPA baselines, and artifacts

Nikto supports `pause_seconds`, `max_time`, and `tuning`, disables interactive/update checks, and still obeys the outer request timeout. Before FFUF starts, the server samples random missing paths and compares status, length, and normalized body hashes. A stable successful fallback is excluded by size, and every result includes the measured baseline plus `false_positive_risk`. An unstable fallback remains visible with a warning.

John accepts either `hash_file` or an inline `hash`. Inline hashes and John state live under a temporary HOME that is deleted after the run. Set `mask_plaintext` to redact recovered plaintext from returned output. JWT Tool likewise starts from a clean temporary HOME seeded with its packaged configuration, then removes that workspace after each call.

Completed, failed, timed-out, and cancelled tool calls write a mode-`0600` JSON result into a private server directory before the MCP response is compacted. The result contains an opaque artifact ID and `/api/artifacts/...` location, both protected by the same bearer token. Artifacts expire after one hour and are removed when the server shuts down. Known Authorization, Cookie, password, hash, and JWT values are replaced before streaming or storage; callers can add exact values through `redact_values`, subject to bounded count and size limits.

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
