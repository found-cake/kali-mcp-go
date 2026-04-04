# kali-mcp-go

Go reimplementation of [MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server), built to eliminate the bottlenecks we hit while running multiple AI agents against CTF challenges simultaneously.

## Why rewrite?

The original Python MCP-Kali-Server is a great project — it pioneered the idea of connecting AI agents to Kali Linux via MCP, and it's even shipped as an official Kali package. But when you spin up several agents in parallel (each with its own MCP client talking to the same Kali server), things break down fast:

- **Flask's single-worker model serializes everything.** One agent kicks off an `nmap -sCV` that takes two minutes; every other agent blocks until it finishes. In a CTF setting where you want recon, enumeration, and exploitation running concurrently, this is a dealbreaker.
- **No streaming.** The Python server buffers the entire command output and returns it as one JSON blob when the process exits. A long-running scan gives the AI nothing to work with until it's completely done — no intermediate results, no ability to pivot early.
- **No authentication on the API.** Anyone who can reach port 5000 can execute arbitrary commands. Fine for a quick local test, not fine when the server is accessible over a network.

kali-mcp-go keeps the same two-tier architecture (Kali API server ↔ MCP stdio client) and API-compatible tool set, but rebuilds both components in Go to remove these constraints.

## What's different

### Concurrent request handling

The API server runs on [Fiber v3](https://github.com/gofiber/fiber) (built on fasthttp). Each incoming request gets its own goroutine, so multiple agents can run tools in parallel without blocking each other.

### Real-time streaming

The `/api/command/stream` endpoint delivers output via Server-Sent Events as it happens:

```
data: {"stream":"stdout","line":"Nmap scan report for 10.10.11.100"}
data: {"stream":"stdout","line":"PORT   STATE SERVICE VERSION"}
data: {"stream":"stdout","line":"22/tcp open  ssh     OpenSSH 8.9"}
data: {"stream":"stderr","line":"Service detection performed."}
data: {"done":true,"return_code":0,"timed_out":false}
```

The AI sees results line by line and can decide to start a follow-up scan before the current one finishes.

### Bearer token authentication

All `/api/*` endpoints require a token set via the `KALI_MCP_API_TOKEN` environment variable. Tokens are compared using constant-time SHA-256 comparison to prevent timing attacks.

### Per-request timeout control

The default timeout is 300 seconds. Clients can override it per request via the `timeout` field in the JSON body. The MCP client automatically adds a 5-second grace period on top of whatever the server-side timeout is, so the server always finishes first.

### Safer Metasploit execution

- Temp files use `os.CreateTemp` (unique filenames, no race conditions) instead of a hardcoded `/tmp/mks_msf_resource.rc`
- Module names and option keys/values are validated to reject line-break injection

### Prompt injection defense

The MCP client includes safety instructions that tell the AI model to treat all tool output as untrusted data and never execute commands derived from scan results without explicit user approval.

### Test coverage

992 lines of tests across all packages — server handlers, executor, HTTP client, tool argument builders, and DTO serialization.

## Supported tools

Same 11 tools as the original, with identical API contracts:

| Tool | Endpoint | MCP tool name |
|------|----------|---------------|
| Arbitrary command | `/api/command` | `execute_command` |
| Nmap | `/api/tools/nmap` | `nmap_scan` |
| Gobuster | `/api/tools/gobuster` | `gobuster_scan` |
| Dirb | `/api/tools/dirb` | `dirb_scan` |
| Nikto | `/api/tools/nikto` | `nikto_scan` |
| Tshark | `/api/tools/tshark` | `tshark_capture` |
| SQLMap | `/api/tools/sqlmap` | `sqlmap_scan` |
| Metasploit | `/api/tools/metasploit` | `metasploit_run` |
| Hydra | `/api/tools/hydra` | `hydra_attack` |
| John the Ripper | `/api/tools/john` | `john_crack` |
| WPScan | `/api/tools/wpscan` | `wpscan_analyze` |
| Enum4linux | `/api/tools/enum4linux` | `enum4linux_scan` |
| Health check | `/health` | `server_health` |

## Project structure

```
kali-mcp-go/
├── cmd/
│   ├── kali-server/     # API server (runs on Kali)
│   └── mcp-client/      # MCP stdio client (runs on host)
├── internal/
│   ├── executor/        # Command execution + streaming
│   ├── kaliclient/      # HTTP client for kali-server
│   └── tools/           # Tool argument builders + validation
└── pkg/
    └── dto/             # Shared request/response types
```

## Status

> **Work in progress.** The core is functional and tested, but installation docs, CI/CD, and release binaries are not yet available. Check back soon.

## Acknowledgments

This project exists because [MCP-Kali-Server](https://github.com/Wh0am123/MCP-Kali-Server) by [@Wh0am123](https://github.com/Wh0am123) proved the concept works. Full credit to the original for pioneering AI-assisted pentesting over MCP.
