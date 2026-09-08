# kali-mcp-go

Concurrent, policy-aware MCP runtime for authorized security testing with Kali tooling. It connects AI clients to a provisioned security environment while keeping target selection, scan limits, execution evidence, and tool safety explicit.

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/found-cake/kali-mcp-go)](https://goreportcard.com/report/github.com/found-cake/kali-mcp-go)
[![Release](https://img.shields.io/github/v/release/found-cake/kali-mcp-go)](https://github.com/found-cake/kali-mcp-go/releases/latest)

---

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
| Deployment | One-shot or persistent Docker operation, standalone binaries, VMs, and directly installed Linux hosts |
| Orchestration boundary | Short-lived scan jobs prevent abandoned processes; the MCP host still owns workflow state and credential management |

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
| `kali-server` host | Linux with the required security tools installed (Kali Linux recommended; other Linux distributions are supported when dependencies are available) |
| `mcp-client` host | Linux, Windows, or macOS |
| Build from source | Go 1.27+ |

Core tools: `nmap`, `gobuster`, `dirb`, `nikto`, `tshark`, `sqlmap`, `msfconsole`, `hydra`, `john`, `wpscan`, `enum4linux`

The Docker image also includes `ffuf`, `feroxbuster`, `nuclei`, `whatweb`, `jwt_tool`, `dalfox`, Playwright with Chromium, `retire`, `osv-scanner`, `jq`, Node.js, and npm.

Docker image builds resolve the latest published Dalfox, jwt_tool, and OSV-Scanner releases and the npm `latest` tags for Playwright and Retire.js. Release checksums are verified when upstream publishes them. This keeps security tooling current but means rebuilding the same commit later can produce different tool versions.

---

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

The published image contains both binaries and the provisioned security tools. Pull the stable image once; the usage section explains one-shot and persistent launch modes.

```bash
docker pull ghcr.io/found-cake/kali-mcp-go:latest
```

Use `:rolling` for the biweekly Kali Rolling build, or a version tag such as `:v1.2.3` for a release-aligned deployment. Pin the resolved image digest (`image@sha256:...`) when byte-identical deployment inputs are required. To build locally:

```bash
docker build -t kali-mcp-go:local .
```

---

## Usage

### 1. Choose a launch mode

| Mode | Best for | MCP launcher |
|---|---|---|
| One-shot Docker | Fastest setup and automatic image updates | `/path/to/kali-mcp-docker ...` |
| Persistent Docker | Repeated use without container startup time | `docker exec ...` |
| Separate processes | A VM, remote Kali host, or existing Linux installation | `mcp-client --server ...` |

The **MCP launcher** is the local STDIO command registered with your AI client. Choose one mode below, then use its launcher in the host-specific examples.

#### One-shot Docker

This is the simplest setup. Download the launcher once; it verifies and caches the Chromium seccomp profile, applies the required Docker isolation options, starts both services, and removes the container when the MCP session closes. No host port is exposed.

```bash
curl -fsSLo kali-mcp-docker \
  https://raw.githubusercontent.com/found-cake/kali-mcp-go/master/scripts/run-docker.sh
chmod +x kali-mcp-docker
./kali-mcp-docker --timeout 3600
```

When running from a repository checkout, use `./scripts/run-docker.sh` instead. Set `KALI_MCP_DOCKER_IMAGE` to select a different image tag. For a locally built image, also set `KALI_MCP_DOCKER_PULL=never`.

#### Persistent Docker

Start one background server container. The launcher can prepare and print the verified seccomp profile path for the direct Docker command:

```bash
seccomp_profile="$(/absolute/path/to/kali-mcp-docker --print-seccomp-profile)"
docker run -d \
  --name kali-mcp \
  --restart unless-stopped \
  --init \
  --ipc=host \
  --security-opt "seccomp=$seccomp_profile" \
  --entrypoint kali-server \
  -e KALI_MCP_API_TOKEN="$(openssl rand -hex 32)" \
  ghcr.io/found-cake/kali-mcp-go:latest \
  --ip 127.0.0.1 --port 5000
```

Register this launcher with the MCP host:

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

The following examples use one-shot Docker. To use persistent Docker, replace the command and arguments with the `docker exec` launcher above. For separate processes, register `/path/to/mcp-client` with its `--server` and `--timeout` arguments, then provide `KALI_MCP_API_TOKEN` through the host's MCP environment configuration.

#### Claude Code

```bash
claude mcp add kali-mcp -- \
  /absolute/path/to/kali-mcp-docker \
  --timeout 3600
```

#### Claude Desktop

Add a local STDIO server to the desktop configuration:

```json
{
  "mcpServers": {
    "kali-mcp": {
      "command": "/absolute/path/to/kali-mcp-docker",
      "args": [
        "--timeout", "3600"
      ]
    }
  }
}
```

#### OpenAI Codex

```bash
codex mcp add kali-mcp -- \
  /absolute/path/to/kali-mcp-docker \
  --timeout 3600
```

For explicit startup and tool timeouts, use `~/.codex/config.toml` instead:

```toml
[mcp_servers.kali-mcp]
command = "/absolute/path/to/kali-mcp-docker"
args = ["--timeout", "3600"]
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
        "/absolute/path/to/kali-mcp-docker",
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
2. Call `resolve_target` before scanning `127.0.0.1`, `localhost`, or `[::1]` unless the intended target runs inside the same environment as `kali-server`.
3. Explicitly select a reachable candidate and pass its signed `target_context` to subsequent tools until it expires.

Loopback targets always refer to the runtime where `kali-server` is running. `resolve_target` reports the runtime address, `host.docker.internal` when available, and the Linux default gateway without silently changing the target. A user can request Kali tools or a black-box assessment without mentioning MCP; the server instructions route the request to the provisioned tools.

### 4. Docker operation

#### Images and updates

- `latest` and version tags use Kali's last release and are published with project releases.
- `rolling` uses Kali Rolling and is rebuilt every two weeks and with project releases.
- `--pull=always` checks the registry at startup but downloads layers only when the digest changes.
- Persistent containers do not update automatically. Pull the desired tag and recreate the container.

#### Networking and files

On Linux, add `--add-host host.docker.internal:host-gateway` to the initial `docker run` command when the Docker host alias is unavailable. Mount host files explicitly, for example:

```bash
docker run --rm -i \
  -v "$PWD:/workspace:ro" \
  ghcr.io/found-cake/kali-mcp-go:latest
```

Use `/workspace/...` in tool requests. Add the same host mapping, mount, or network options when creating a persistent container.

#### Chromium sandbox

`browser_check` always launches Chromium as the dedicated `kali-browser` user with the browser sandbox enabled. Docker must therefore allow Chromium's user-namespace syscalls. The repository includes Playwright's Docker seccomp profile as `chromium-seccomp.json`.

The image entrypoint already uses `tini` to reap browser subprocesses. Persistent mode keeps Docker's `--init` because its `--entrypoint` option replaces the image entrypoint.

The one-shot launcher applies the profile and shared IPC option automatically. For direct `docker run` commands, add them explicitly:

```bash
docker run --pull=always --rm -i \
  --ipc=host \
  --security-opt "seccomp=$PWD/chromium-seccomp.json" \
  ghcr.io/found-cake/kali-mcp-go:latest \
  --timeout 3600
```

If you use the published image without the launcher or a repository checkout, download the matching profile first:

```bash
curl -fsSLo chromium-seccomp.json \
  https://raw.githubusercontent.com/found-cake/kali-mcp-go/master/chromium-seccomp.json
```

Use an absolute profile path in JSON/TOML MCP host configurations because shell variables such as `$PWD` are not expanded there. Without the namespace-enabled profile, `browser_check` fails closed instead of disabling the Chromium sandbox. Other tools remain available.

#### Nmap capabilities

TCP connect scans such as `-sT -Pn` work with Docker's default capabilities. Add `--cap-add NET_RAW --cap-add NET_ADMIN` only when a scan actually needs raw sockets. If Nmap cannot start, first check its binary permissions and file capabilities, mount options, and seccomp/AppArmor policy.

> **Security:** The image includes `execute_command` and can reach networks available to the container. Restrict that access where practical, and only test systems you own or have explicit written permission to assess.

### 5. Configuration reference

For synchronous long scans, configure the MCP host timeout above `mcp-client --timeout`. When the host propagates its deadline, the client reserves five seconds to cancel the remote process and return accumulated output. A host that forcibly terminates the STDIO process cannot receive a final partial-result envelope. Individual tool requests can still set tighter limits. Use `run_tool_async` when the agent expects a tool to exceed that host deadline or wants to start a new run after a synchronous timeout.

#### mcp-client flags

| Flag | Default | Description |
|---|---|---|
| `--server` | `http://127.0.0.1:5000` | kali-server URL |
| `--timeout` | `300` | Base request timeout in seconds; individual tool calls that expose `timeout` can raise it for that request |
| `--debug` | `false` | Verbose stderr logging |

#### kali-server flags

| Flag | Default | Description |
|---|---|---|
| `--ip` | `127.0.0.1` | Bind address |
| `--port` | `5000` | Listen port |
| `--debug` | `false` | Verbose request logging |
| `--max-concurrent` | `10` | Maximum number of concurrent execution requests before the server returns `503 Service Unavailable` |

#### Environment variables

| Variable | Component | Description |
|---|---|---|
| `KALI_MCP_API_TOKEN` | both | Bearer token for API authentication; required for separate processes, optional in Docker mode because the entrypoint generates one when omitted |
| `KALI_MCP_DIR_WORDLIST` | kali-server | Override default dir wordlist (default: `/usr/share/wordlists/dirb/common.txt`) |
| `KALI_MCP_SMALL_DIR_WORDLIST` | kali-server | Override the selectable small dir wordlist (default: `/usr/share/wordlists/dirb/small.txt`) |
| `KALI_MCP_JOHN_WORDLIST` | kali-server | Override default John wordlist (default: `/usr/share/wordlists/rockyou.txt`) |
| `KALI_MCP_NUCLEI_TEMPLATES` | kali-server | Nuclei template directory checked by `server_health` (Docker default: `/root/.local/nuclei-templates`) |

> `ReadTimeout` is enforced for incoming request bodies, while streaming responses remain unrestricted by `WriteTimeout`.

---

## Available Tools

| MCP tool | Description |
|---|---|
| `server_health` | Check server status and tool availability |
| `get_scan_capabilities` | Inspect profile compatibility, target formats, supported controls, exact registered input schemas, and effective default wordlists |
| `resolve_target` | Inspect runtime, resolvable Docker-host, and gateway candidates without rewriting the target |
| `result_artifact_read` | Read a retained artifact completely through bounded byte pages or UTF-8 line ranges, including extracted tool stdout/stderr sections |
| `run_tool_async` | Start any executable MCP tool as a new background run using that tool's unchanged argument object |
| `scan_job_status` | Read pending progress or terminal state for an asynchronous tool run |
| `scan_job_result` | Read an asynchronous tool run's existing terminal result |
| `scan_job_cancel` | Request cancellation of a pending asynchronous tool run |
| `http_request` | Send one bounded HTTP request with structured status, headers, optional target-bound virtual host, body preview, provenance, and artifact output |
| `execute_command` | Execute an arbitrary shell command (SSE streaming) |
| `nmap_scan` | Nmap port and service scan (SSE streaming) |
| `gobuster_scan` | Directory / DNS / vhost brute-force (SSE streaming) |
| `dirb_scan` | Quiet web content scan with structured discovered paths (SSE streaming) |
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
| `nuclei_scan` | Nuclei scan with local template-selection preview; DoS, fuzz, DAST, OAST, and interactsh behavior is excluded unless explicitly enabled |
| `whatweb_scan` | Web technology and framework fingerprinting |
| `jwt_analyze` | JWT decoding and optional live playbook/forced-error/all-tests assessment |
| `dalfox_scan` | XSS candidate scanning with JSON findings |
| `browser_check` | Headless Chromium verification with per-call headers, cookies, origin-scoped `local_storage`, dialogs, console output, page errors, and optional rendered DOM |
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
- `hydra_attack_stream`
- `ffuf_scan`
- `feroxbuster_scan`
- `nuclei_scan`
- `whatweb_scan`
- `jwt_analyze`
- `dalfox_scan`
- `browser_check`
- `retirejs_scan`
- `osv_scan`

Streaming requests support an optional `timeout` field for the outer tool-process deadline. `0` uses 300 seconds. This wall-clock budget is separate from rate and concurrency, so increasing it for a broad low-rate scan does not increase instantaneous scan intensity. Set enough time for the intended bounded scope to complete or reduce that scope; a timed-out result represents incomplete coverage. For `tshark_capture`, this request `timeout` is distinct from the capture `duration` field.

Executable tools remain synchronous by default and do not expose per-tool `async` fields. To run one in the background, call `run_tool_async` with its MCP `tool_name` and the exact `arguments` object accepted by the dedicated tool. Async avoids the MCP host deadline but preserves `arguments.timeout`; after a process timeout, start a new run with a longer timeout or narrower scope. It does not reattach to or resume the abandoned call. The response contains `{job_id,status,data}` with `status: pending`; use `scan_job_status`, `scan_job_result`, or `scan_job_cancel` with that ID. Terminal jobs use `completed` when execution succeeded and `error` for failed, timed-out, or cancelled execution, while `data` contains the same tool result contract used synchronously. Terminal lookup expires 30 seconds after the process exits, so retrieve the result promptly. Result artifacts retain their independent one-hour lifetime. Jobs are in-memory process-control state, not durable workflow or credential sessions, and server shutdown cancels pending processes.

When using OpenCode, the per-tool request `timeout` is not enough by itself for long scans. You should also raise OpenCode's MCP execution timeout and the local `mcp-client --timeout` value as shown above.

For Codex and other MCP hosts, you may still want a larger `mcp-client --timeout` value for long-running tools, but OpenCode's `mcp.<name>.timeout` setting does not apply there.

Quiet streams may also emit lightweight heartbeat SSE events to keep the connection active until the final `done` event arrives.
The bundled MCP client assigns the stream `call_id` before execution and sends an authenticated cancellation request if its caller context ends or the SSE stream becomes unreadable. On Unix servers, that cancellation stops the complete spawned process group after a short graceful-stop window and releases its execution slot. SSE flush failures provide a transport-level fallback, but custom HTTP consumers should explicitly call `POST /api/calls/{call_id}/cancel` when abandoning a stream. Keep the MCP host timeout at least as large as the client and request timeouts so an intermediary does not abandon useful work prematurely.

These tools use ordinary request/response rather than SSE. `metasploit_run`, `hydra_attack`, `john_crack`, `http_request`, and `resolve_target` use POST; `get_scan_capabilities`, `result_artifact_read`, and `server_health` use GET:

- `get_scan_capabilities`
- `resolve_target`
- `result_artifact_read`
- `http_request`
- `metasploit_run`
- `hydra_attack`
- `john_crack`
- `server_health`

### Structured results

Every tool exposes an MCP output schema and returns both readable text and structured content. The structured result separates:

- `call_id`: a per-call identifier shared by JSON results, every SSE event, the `X-Kali-MCP-Call-ID` response header, and server telemetry logs
- `status`: `completed`, `failed`, `timeout`, or `cancelled`
- `success`: derived from `status`; a timeout or cancellation is never reported as successful
- `execution_status`: the detailed process state retained for existing clients
- `finding_status`: `detected`, `not_detected`, `inconclusive`, or `unknown`
- `finding_types`: the kind of observation evaluated, such as `service`, `technology`, `content`, `vulnerability`, or `misconfiguration`
- `partial_results`, `http_requests`, `duration_ms`, original stdout/stderr byte counts, and `output_truncated`
- `stdout_truncated` and `stderr_truncated`: which inline channel was shortened
- `finding_output_truncated`: whether the primary finding-bearing stdout was shortened
- `artifact_complete`: whether the complete retained tool-result artifact is available despite inline truncation
- `progress`: phase, observed output item count, last retained output item, exact HTTP request count when known, and a stateless checkpoint
- `target`: original target, explicitly selected target, resolution ID, and selection basis
- `execution`: redacted argv, tool version, start/end time, timeout, profile, rate, concurrency, health URL, and any applied 5xx threshold
- `failure`: reason, retryability, and resume support
- `artifacts`: opaque IDs and bearer-protected locations for retained tool-result JSON and related UTF-8 or base64 evidence artifacts

Tool process failures and timeouts set MCP `isError`; a successful scan with no finding does not.

Every HTTP call also emits one JSON telemetry record containing its `call_id`, MCP operation, path, start/end time, duration, and HTTP status. Target and credential values remain in the protected structured result rather than server logs.

`http_requests` is populated only from a measured or parsed counter whose meaning is suitable for the completed result; `request_count_source` distinguishes `measured`, `parsed`, and `unknown`, and the count remains `null` rather than being estimated. Nuclei's runtime `requests` counter is retained separately with `requests_semantics: scheduled_or_generated`; timed-out and otherwise partial Nuclei runs do not expose that counter as delivered HTTP requests. Its `reported_rps` is the scanner's own runtime statistic, separate from the applied native limiter. Nikto's own maximum-execution-time termination is normalized to `timed_out`, with progress set to the same phase, even when Nikto exits with code zero. Findings remain independently `detected` when partial evidence exists. A failure with output sets `partial_results`. Inline stdout and stderr are UTF-8-safe previews capped at 8 KiB each; Nuclei uses a 2 KiB cap and returns only complete lines so a large JSONL record is never presented as parseable partial JSON. `stdout_bytes` and `stderr_bytes` report the original output sizes. HTTP response metadata, SQLMap differential analysis, JWT structural analysis, and Nuclei preview metadata are also appended as one compact JSON summary for MCP hosts that do not surface structured content.

### Artifact paging

`result_artifact_read` never searches, summarizes, or filters evidence. It only returns the requested section and range, so the orchestrator retains control over what it inspects:

- Byte mode uses `offset` plus `limit` and works for every artifact. The default page is 16 KiB and each call may request 256 bytes through 64 KiB. Continue with `next_offset` while `has_more` is true; there is no cumulative read cap, so the complete artifact remains readable.
- Line mode uses the 1-based `start_line` plus `line_count` for UTF-8 artifacts. It defaults to 100 lines and accepts at most 500 lines per call, while the returned content remains capped at 64 KiB. Continue with `next_line` unless `line_truncated` is true.
- `section` defaults to `raw`. `stdout` and `stderr` decode those fields only from a `tool-result-json` artifact. Their offsets and byte/line totals are relative to the selected section.
- If a single line exceeds 64 KiB, the response sets `line_truncated`. Continue that selected section in byte mode from `next_offset`; this preserves access to the remainder without silently dropping data.
- Byte and line range parameters are mutually exclusive. Binary/base64 artifacts support byte mode only.
- The returned `call_id` identifies the current `result_artifact_read` operation. `source_call_id` identifies the original tool call that produced the artifact, so repeated reads have different `call_id` values while retaining the same evidence provenance.

The authenticated raw HTTP endpoint `GET /api/artifacts/:id` also remains available for consumers that intentionally retrieve the entire artifact in one response.

Executable tools share one compact top-level MCP output contract. Detailed nested evidence remains in structured content and artifacts, while the common schema keeps status, classification, request-count provenance, target provenance, and artifact fields discoverable without repeating the full nested schema for every tool.

Progress checkpoints describe already observed output. Asynchronous jobs preserve process state only while running and expose their terminal result for 30 seconds; they do not add scanner-native checkpoints or continuation. `resume_supported` remains false unless a tool can guarantee native continuation, so the orchestrator decides whether to retry and how to exclude previously observed work without durable shared MCP session memory.
### Explicit target resolution

Scan tools never silently rewrite a target. `127.0.0.1`, `localhost`, and `[::1]` refer to the machine or container running `kali-server`, whether that runtime is Docker, a VM, or a directly installed Linux host.

For a loopback target, call `resolve_target`, choose one returned candidate, and pass its `target_context` to subsequent scan tools. Network tools derive the candidate's explicit network host and signed port, while web tools use its browser URL and may accept a same-origin path extension. Nmap, Hydra, and Metasploit bind their effective port to the signed candidate. Generic Host-header overrides, alternate target/port, additional scope, cross-host redirect, and proxy/replay destinations are rejected for resolved targets so the executed service matches the reported provenance. The bounded `http_request.virtual_host` field is the sole exception: it changes only the HTTP Host value while the signed URL continues to control the network connection. Contexts are signed, default to ten minutes, and may request up to one hour with `valid_for_seconds`; they are never renewed without another connectivity check. The older target plus `resolution_receipt` form remains supported without virtual-host overrides. Loopback scans without either proof are rejected. Non-loopback targets remain usable directly, but their results carry an unverified-target warning.

### Safety profiles and controls

Dedicated scan requests accept a `profile` plus optional `timeout`, `rate_limit`, `concurrency`, `health_url`, and `max_5xx_responses` controls when supported by that tool. Profile limits are ceilings rather than guaranteed defaults; the selected tool's `supported_controls` and the result's `execution.controls` identify actual applicability. The MCP server executes the selected scope and reports actual duration and observed request counts; it does not predict scan duration or derive timeout values from estimated request counts. Available profiles are:

Call `get_scan_capabilities` before composing a scan when profile compatibility, exact input fields, or a wordlist path is uncertain. Its response uses MCP-facing tool names, includes each tool's registered schema as `input_schema_json`, reports the effective environment-configured defaults, and marks missing wordlist files unavailable. An explicitly supplied missing wordlist remains an error and is never silently replaced.

| Profile | Intended use |
|---|---|
| `safe-recon` | Low-impact service and technology reconnaissance |
| `web-discovery-low-rate` | Bounded path discovery with conservative concurrency |
| `sqli-verify-low-risk` | Targeted SQL injection verification with a low request rate |
| `browser-xss-confirm` | Browser-backed confirmation of a specific XSS candidate |
| `explicit-custom` | Explicit caller-supplied controls within hard server limits |

Safety profiles bound impact and request behavior; they are not completeness claims. Excluded higher-impact techniques, timed-out or partial tools, and untested authenticated or input-specific routes must remain explicit report limitations.

The server limits total work and weighted work per target service, canonicalized across web URLs, network hosts, paths, and explicitly selected resolver candidates. Heavy tools cannot run concurrently against that service. Supported tools receive native rate and concurrency flags. Nuclei's capability reports `native_cli_average_bursty` for `rate_limit`: the value is passed to its global native limiter, but it is an average throttle rather than a hard rolling-one-second ceiling. The applied value remains in `execution.controls`, while the scanner-observed statistic is returned separately as `nuclei_runtime.reported_rps`. An omitted `timeout` uses the documented 300-second default; the caller or orchestrator chooses any other execution timeout. A short timeout is not the primary service-protection control: bound impact with scope, rate, concurrency, supported failure controls, and health checks, while allowing broad low-rate scans enough wall-clock time to complete. When `health_url` is present, it must identify the selected target service; the server rejects cross-origin redirects and probes it before and after the run, except for local-only `dry_run` previews. A 5xx circuit breaker is applied only when the selected tool lists `max_5xx_responses` in `supported_controls`; an effective value of `0` makes no 5xx cancellation claim. Safety profiles also constrain impact: discovery tools retain read-only methods and cannot enable cross-host redirects or auxiliary proxy/replay destinations, Nmap rejects spoofing and accepts only passive built-in script selectors without script arguments, Nikto rejects explicit DoS and command-execution tuning, Dalfox rejects blind/OOB and remote payload sources, SQLmap pins conservative verification settings and ignores redirects, and manual `http_request` calls permit only GET, HEAD, and OPTIONS. In Nuclei safe mode, selection and safety-override flags supplied through `additional_args` are rejected while the typed severity, tag, and template selectors remain available; the final DoS, fuzz, DAST, OAST, and interactsh exclusions cannot be overridden. `allow_unsafe` requires `explicit-custom` or an omitted profile to leave that boundary.

### Credential management

`kali-server` does not create or manage authentication-token and cookie sessions. Manage credentials directly using safeguards appropriate to your environment, and pass them only in request-scoped fields supported by the selected tool. Tool output and artifacts preserve raw credential-like values by default, including one-hour result-artifact retention; the server does not create, list, or reuse credential sessions across calls. Temporary implementation paths remain hidden from execution metadata, while `redact_values` provides explicit exact-value replacement when the caller chooses it.

### Natural-language tool routing

The server instructions and tool descriptions recognize authorized black-box penetration testing, security assessment, reconnaissance, enumeration, and requests to use Kali tools as intended use cases. No product-specific keyword is required. Include an explicit authorized target and scope, for example: `Run an authorized black-box assessment of http://127.0.0.1:3000 with Kali tools; resolve the target first, then enumerate ports, services, and web technologies.`

A root URL is a starting point, not the full application scope. The orchestrator should use path discovery, browser and network evidence, and JavaScript analysis to build its own endpoint inventory, then invoke relevant tools for selected authenticated routes and input points with caller-managed request-scoped credentials. The MCP server does not infer completion from a root-only scan or maintain that inventory itself.

### SQLmap JSON and raw requests

`sqlmap_scan` accepts exactly one of `url`, `request_file`, or `raw_request`. It supports JSON bodies with SQLmap's `*` injection marker, named test parameters, headers, cookies, content type, expected error codes, and explicit `abort_codes` passed to SQLmap's native `--abort-code` option. Native comparison fields map `true_string`, `false_string`, `true_regexp`, and `true_status_code` to SQLmap's `--string`, `--not-string`, `--regexp`, and `--code`; `payload_prefix`, `payload_suffix`, and `test_filter` map to `--prefix`, `--suffix`, and `--test-filter`. The corresponding flags are rejected in `additional_args` so structured input remains authoritative. A status code cannot be both ignored and configured to abort. Absolute raw-request targets must match their `Host` header, and selected resolution additionally rejects Host, proxy, redirect, scheme, port, and DNS-OOB overrides while binding the raw destination to the signed service. Raw requests, traffic logs, and SQLmap output are kept in a mode-restricted temporary workspace and deleted after completion. `--ignore-stdin` is applied automatically so MCP's non-TTY process input cannot override a supplied raw request.

### Bounded manual HTTP requests

Use `http_request` instead of `execute_command` with curl for one-off validation. It accepts HTTP(S) only, one request per call, an optional arbitrary `json_body`, bounded raw bodies and responses, a maximum 300-second timeout, and at most five same-origin redirects. `safe-recon` is limited to GET, HEAD, and OPTIONS; state-changing methods require `explicit-custom`. Loopback targets require a selected `target_context` or the legacy explicit URL plus receipt. Context-bound requests reject generic `Host` headers, while `virtual_host` is allowed only with `target_context` and cannot change the signed connection URL. Request headers, response headers, URLs, and bodies are preserved verbatim unless the caller supplies exact `redact_values`. Browser network evidence follows the same rule, retaining query and fragment values for reproduction until explicit redaction is requested.

### Scan load, SPA baselines, and artifacts

Nikto supports `pause_seconds`, `max_time`, and `tuning`, disables interactive/update checks, and still obeys the outer request timeout. Dirb runs in silent terminal mode and returns parsed URLs, status codes, response sizes, and directory markers through `discovered_paths` while retaining its raw output artifact. FFUF supports `request_timeout` for each HTTP request and `filter_status_codes` for explicit response filtering; these are separate from the outer scan `timeout`. `get_scan_capabilities` exposes both the common and small directory wordlists so the caller can select scan breadth explicitly. Before FFUF, Gobuster directory mode, or Feroxbuster starts, the server samples random missing paths and compares status, length, and normalized body hashes without following cross-origin redirects. A stable successful fallback is excluded by size, and every result includes the measured baseline plus `false_positive_risk`. An unstable fallback remains visible with a warning. Nuclei templates are installed when the Docker image is built, and `server_health` reports Nuclei unavailable if their checksum is missing without downloading anything. Normal Nuclei runs execute directly without a template-count or duration-estimation preflight. Set `dry_run: true` to list the matching local template count without contacting the target; this count is not converted into a request or duration estimate because templates and workflows can issue variable traffic. Page the full Nuclei JSONL with `result_artifact_read` using `section: "stdout"`, `start_line`, and `line_count`; there is no cumulative read limit. Nuclei never silently reduces the selected scope.

`browser_check.local_storage` accepts a string map that is installed before application scripts execute. Values are injected only when the document origin matches the selected URL, are not copied into cross-origin frames or redirects, and disappear when the isolated browser context closes. This is per-call input like `headers`, not a reusable credential session.

John accepts either `hash_file` or an inline `hash`. Inline hashes and John state live under a temporary HOME that is deleted after the run. Set `mask_plaintext` to redact recovered plaintext from returned output. JWT Tool likewise starts from a clean temporary HOME seeded with its packaged configuration, then removes that workspace after each call.

Completed, failed, timed-out, and cancelled tool calls write a mode-`0600` JSON result into a private server directory before the MCP response is compacted. The result contains an opaque artifact ID and `/api/artifacts/...` location, both protected by the same bearer token. Artifacts expire after one hour and are removed when the server shuts down. Results are retained verbatim by default and carry `redaction_state: sensitive_unredacted`; callers can opt into exact-value replacement through `redact_values`, subject to bounded count and size limits, which marks affected result artifacts as `redacted`. Credential and privacy handling remains the caller or orchestrator's responsibility.

### Choosing between `hydra_attack` and `hydra_attack_stream`

- Use `hydra_attack` for quick checks such as a single username/password attempt or other short runs where a buffered final result is sufficient.
- Use `hydra_attack_stream` for long-running Hydra jobs when you want progress as it happens, especially with `username_file` and/or `password_file` inputs.

---

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
└── pkg/
    └── dto/                    # shared request and result contracts
```

---

## Security Notice

> ⚠️ Only target systems you own or have explicit written permission to test.
>
> `execute_command` runs arbitrary shell commands as the server process user — restrict network access appropriately and prefer an SSH tunnel over direct exposure.
