# Operational and Tool Reference

[Back to README](../README.md) · [Setup and usage](../README.md#usage) · [Configuration](../README.md#configuration) · [All MCP tools](../README.md#available-tools)

Detailed Docker operation, execution contracts, evidence handling, and tool-specific behavior.

## Contents

- [Docker operation](#docker-operation)
- [Streaming and timeouts](#streaming-and-timeouts) · [Background jobs](#background-jobs) · [Cancellation and heartbeats](#cancellation-and-heartbeats)
- [Structured results](#structured-results) · [Artifact paging](#artifact-paging) · [Retention and redaction](#artifact-retention-and-redaction)
- [Target resolution](#explicit-target-resolution) · [Safety profiles and controls](#safety-profiles-and-controls) · [Credentials](#credential-management)
- [Natural-language routing](#natural-language-tool-routing)
- [SQLmap](#sqlmap-json-and-raw-requests) · [Manual HTTP](#bounded-manual-http-requests) · [Scan load and SPA baselines](#scan-load-and-spa-baselines)
- [Browser local storage](#browser-local-storage) · [John and JWT workspaces](#john-and-jwt-workspaces) · [Hydra modes](#choosing-between-hydra_attack-and-hydra_attack_stream)

## Docker operation

### Images and updates

- `latest` and version tags use Kali's last release and are published with project releases.
- `rolling` uses Kali Rolling and is rebuilt every two weeks and with project releases.
- `--pull=always` checks the registry at startup but downloads layers only when the digest changes.
- Persistent containers do not update automatically. Pull the desired tag and recreate the container.

### Networking and files

On Linux, add `--add-host host.docker.internal:host-gateway` to the initial `docker run` command when the Docker host alias is unavailable. Mount host files explicitly, for example:

```bash
docker run --rm -i \
  -v "$PWD:/workspace:ro" \
  ghcr.io/found-cake/kali-mcp-go:latest
```

Use `/workspace/...` in tool requests. Add the same host mapping, mount, or network options when creating a persistent container.

### Chromium sandbox

`browser_check` always launches Chromium as the dedicated `kali-browser` user with the browser sandbox enabled. Docker must therefore allow Chromium's user-namespace syscalls. The repository includes Playwright's Docker seccomp profile as `chromium-seccomp.json`.

The Docker image sets `KALI_MCP_BROWSER_OUTPUT_DIR=/var/lib/kali-mcp/browser` for temporary headers, local-storage data, and screenshots passed between the server and the browser user. The directory is root-owned, restricted to the `kali-browser` group, and its handoff files are removed after each call. A custom directory must preserve equivalent server-write and browser-user access.

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
  https://raw.githubusercontent.com/found-cake/kali-mcp-go/8184dde5d042919d42da7fb2204624d4984f6321/chromium-seccomp.json
```

Use an absolute profile path in JSON/TOML MCP host configurations because shell variables such as `$PWD` are not expanded there. Without the namespace-enabled profile, `browser_check` fails closed instead of disabling the Chromium sandbox. Other tools remain available.

### Nmap capabilities

TCP connect scans such as `-sT -Pn` work with Docker's default capabilities. Add `--cap-add NET_RAW --cap-add NET_ADMIN` only when a scan actually needs raw sockets. If Nmap cannot start, first check its binary permissions and file capabilities, mount options, and seccomp/AppArmor policy.

> **Security:** The image includes `execute_command` and can reach networks available to the container. Restrict that access where practical, and only test systems you own or have explicit written permission to assess.

## Streaming and timeouts

See the [tool catalog](../README.md#available-tools) for each tool’s SSE or ordinary request/response transport.

Streaming requests support an optional `timeout` field for the outer tool-process deadline. `0` uses 300 seconds. This wall-clock budget is separate from rate and concurrency, so increasing it for a broad low-rate scan does not increase instantaneous scan intensity. Set enough time for the intended bounded scope to complete or reduce that scope; a timed-out result represents incomplete coverage. For `tshark_capture`, this request `timeout` is distinct from the capture `duration` field.

When using OpenCode, the per-tool request `timeout` is not enough by itself for long scans. You should also raise OpenCode's MCP execution timeout and the local `mcp-client --timeout` value as shown in the [client registration examples](../README.md#2-register-the-launcher).

For Codex and other MCP hosts, you may still want a larger `mcp-client --timeout` value for long-running tools, but OpenCode's `mcp.<name>.timeout` setting does not apply there.

## Background jobs

Executable tools remain synchronous by default and do not expose per-tool `async` fields. To run one in the background, call `run_tool_async` with its MCP `tool_name` and the exact `arguments` object accepted by the dedicated tool. Async avoids the MCP host deadline but preserves `arguments.timeout`; after a process timeout, start a new run with a longer timeout or narrower scope. It does not reattach to or resume the abandoned call. The response contains `{job_id,status,data}` with `status: pending`; use `scan_job_status`, `scan_job_result`, or `scan_job_cancel` with that ID.

Terminal jobs use `completed` when execution succeeded and `error` for failed, timed-out, or cancelled execution, while `data` contains the same tool result contract used synchronously. Terminal lookup expires 30 seconds after the process exits, so retrieve the result promptly. Result artifacts retain their independent one-hour lifetime. Jobs are in-memory process-control state, not durable workflow or credential sessions, and server shutdown cancels pending processes.

## Cancellation and heartbeats

Quiet streams may also emit lightweight heartbeat SSE events to keep the connection active until the final `done` event arrives.
The bundled MCP client assigns the stream `call_id` before execution and sends an authenticated cancellation request if its caller context ends or the SSE stream becomes unreadable. On Unix servers, that cancellation stops the complete spawned process group after a short graceful-stop window and releases its execution slot. SSE flush failures provide a transport-level fallback, but custom HTTP consumers should explicitly call `POST /api/calls/{call_id}/cancel` when abandoning a stream. Keep the MCP host timeout at least as large as the client and request timeouts so an intermediary does not abandon useful work prematurely.

## Structured results

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
- `execution`: redacted argv, tool version, selected plugins where applicable, start/end time, timeout, profile, rate, concurrency, health URL, and any applied 5xx threshold
- `failure`: reason, retryability, and resume support
- `artifacts`: opaque IDs and bearer-protected locations for retained tool-result JSON and related UTF-8 or base64 evidence artifacts

Tool process failures and timeouts set MCP `isError`; a successful scan with no finding does not.

Every HTTP call also emits one JSON telemetry record containing its `call_id`, MCP operation, path, start/end time, duration, and HTTP status. Target and credential values remain in the protected structured result rather than server logs.

`http_requests` is populated only from a measured or parsed counter whose meaning is suitable for the completed result; `request_count_source` distinguishes `measured`, `parsed`, and `unknown`, and the count remains `null` rather than being estimated. Nuclei's runtime `requests` counter is retained separately with `requests_semantics: scheduled_or_generated`; timed-out and otherwise partial Nuclei runs do not expose that counter as delivered HTTP requests. Its `reported_rps` is the scanner's own runtime statistic, separate from the applied native limiter. Nikto's own maximum-execution-time termination is normalized to `timed_out`, with progress set to the same phase, even when Nikto exits with code zero. Findings remain independently `detected` when partial evidence exists. A failure with output sets `partial_results`.

Inline stdout and stderr are UTF-8-safe previews capped at 8 KiB each; Nuclei uses a 2 KiB cap and returns only complete lines so a large JSONL record is never presented as parseable partial JSON. `stdout_bytes` and `stderr_bytes` report the original output sizes. HTTP response metadata, SQLMap differential analysis, JWT structural analysis, and Nuclei preview metadata are also appended as one compact JSON summary for MCP hosts that do not surface structured content.

Discovery results use `discovered_paths[].response_bytes` for the response size reported by that scanner's own request. It is distinct from the scanner output size in `stdout_bytes`, the HTTP `Content-Length` in `http_response.content_length`, and the retained response body size in `http_response.body_bytes`; compression, chunked transfer, dynamic content, redirects, or different request headers can make those values differ.

## Artifact paging

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

## Explicit target resolution

Scan tools never silently rewrite a target. `127.0.0.1`, `localhost`, and `[::1]` refer to the machine or container running `kali-server`, whether that runtime is Docker, a VM, or a directly installed Linux host.

For a loopback target, call `resolve_target`, choose one returned candidate, and pass its `target_context` to subsequent scan tools while it remains valid. Network tools derive the candidate's explicit network host and signed port, while web tools use its browser URL and may accept a same-origin path extension. Nmap, Hydra, and Metasploit bind their effective port to the signed candidate. Generic Host-header overrides, alternate target/port, additional scope, cross-host redirect, and proxy/replay destinations are rejected for resolved targets so the executed service matches the reported provenance. The bounded `http_request.virtual_host` field is the sole exception: it changes only the HTTP Host value while the signed URL continues to control the network connection.

Contexts are signed, default to ten minutes, and may request up to one hour with `valid_for_seconds`. Each candidate reports `context_expires_at`, and the caller decides when to perform another connectivity check; contexts are never renewed silently. The older target plus `resolution_receipt` form remains supported without virtual-host overrides. Loopback scans without either proof are rejected. Non-loopback targets remain usable directly, but their results carry an unverified-target warning.

## Safety profiles and controls

Dedicated scan requests accept a `profile` plus optional `timeout`, `rate_limit`, `concurrency`, `health_url`, and `max_5xx_responses` controls when supported by that tool. Profile limits are ceilings rather than guaranteed defaults; the selected tool's `supported_controls` and the result's `execution.controls` identify actual applicability. The MCP server executes the selected scope and reports actual duration and observed request counts; it does not predict scan duration or derive timeout values from estimated request counts. Call `get_scan_capabilities` before composing a scan when profile compatibility, exact input fields, a runtime plugin, or a wordlist path is uncertain. Pass `tool_name` to return one compact tool capability or omit it for the complete registry. Its response uses MCP-facing tool names, includes each returned tool's registered schema as `input_schema_json`, reports the effective environment-configured defaults, and marks missing wordlist files unavailable. For `nikto_scan`, `plugin_inventory` reports the installed runtime version, plugin names and descriptions, and non-exhaustive `risk_hints`; `risk_hints_complete: false` means an unlisted risk must not be interpreted as proof of safety. An explicitly supplied missing plugin or wordlist remains an error and is never silently replaced.

Available profiles are:

| Profile | Intended use |
|---|---|
| `safe-recon` | Low-impact service and technology reconnaissance |
| `web-discovery-low-rate` | Bounded path discovery with conservative concurrency |
| `sqli-verify-low-risk` | Targeted SQL injection verification with a low request rate |
| `browser-xss-confirm` | Browser-backed confirmation of a specific XSS candidate |
| `explicit-custom` | Explicit caller-supplied controls within hard server limits |

Safety profiles bound impact and request behavior; they are not completeness claims. Excluded higher-impact techniques, timed-out or partial tools, and untested authenticated or input-specific routes must remain explicit report limitations.

The server limits total work and weighted work per target service, canonicalized across web URLs, network hosts, paths, and explicitly selected resolver candidates. Heavy tools cannot run concurrently against that service. Supported tools receive native rate and concurrency flags. Nuclei's capability reports `native_cli_average_bursty` for `rate_limit`: the value is passed to its global native limiter, but it is an average throttle rather than a hard rolling-one-second ceiling. The applied value remains in `execution.controls`, while the scanner-observed statistic is returned separately as `nuclei_runtime.reported_rps`.

An omitted `timeout` uses the documented 300-second default; the caller or orchestrator chooses any other execution timeout. A short timeout is not the primary service-protection control: bound impact with scope, rate, concurrency, supported failure controls, and health checks, while allowing broad low-rate scans enough wall-clock time to complete. When `health_url` is present, it must identify the selected target service; the server rejects cross-origin redirects and probes it before and after the run, except for local-only `dry_run` previews. A 5xx circuit breaker is applied only when the selected tool lists `max_5xx_responses` in `supported_controls`; an effective value of `0` makes no 5xx cancellation claim.

Safety profiles also constrain impact: discovery tools retain read-only methods and cannot enable cross-host redirects or auxiliary proxy/replay destinations, Nmap rejects spoofing and accepts only passive built-in script selectors without script arguments, Nikto rejects explicit DoS and command-execution tuning and requires `explicit-custom` for the state-changing `put_del_test` plugin, Dalfox rejects blind/OOB and remote payload sources, SQLmap pins conservative verification settings and ignores redirects, and manual `http_request` calls under `safe-recon` permit only GET, HEAD, and OPTIONS.

In Nuclei safe mode, selection and safety-override flags supplied through `additional_args` are rejected while the typed severity, tag, and template selectors remain available; the final DoS, fuzz, DAST, OAST, and interactsh exclusions cannot be overridden. `allow_unsafe` requires `explicit-custom` or an omitted profile to leave that boundary.

## Credential management

`kali-server` does not create or manage authentication-token and cookie sessions. Manage credentials directly using safeguards appropriate to your environment, and pass them only in request-scoped fields supported by the selected tool. Tool output and artifacts preserve raw credential-like values by default, including one-hour result-artifact retention; the server does not create, list, or reuse credential sessions across calls. Temporary implementation paths remain hidden from execution metadata, while `redact_values` provides explicit exact-value replacement when the caller chooses it.

## Natural-language tool routing

The server instructions and tool descriptions recognize authorized black-box penetration testing, security assessment, reconnaissance, enumeration, and requests to use Kali tools as intended use cases. No product-specific keyword is required. Include an explicit authorized target and scope, for example: `Run an authorized black-box assessment of http://127.0.0.1:3000 with Kali tools; resolve the target first, then enumerate ports, services, and web technologies.`

A root URL is a starting point, not the full application scope. The orchestrator should use path discovery, browser and network evidence, and JavaScript analysis to build its own endpoint inventory, then invoke relevant tools for selected authenticated routes and input points with caller-managed request-scoped credentials. The MCP server does not infer completion from a root-only scan or maintain that inventory itself.

## SQLmap JSON and raw requests

`sqlmap_scan` accepts exactly one of `url`, `request_file`, or `raw_request`. It supports JSON bodies with SQLmap's `*` injection marker, named test parameters, headers, cookies, content type, expected error codes, and explicit `abort_codes` passed to SQLmap's native `--abort-code` option.

Native comparison fields map `true_string`, `false_string`, `true_regexp`, and `true_status_code` to SQLmap's `--string`, `--not-string`, `--regexp`, and `--code`; `payload_prefix`, `payload_suffix`, and `test_filter` map to `--prefix`, `--suffix`, and `--test-filter`. The corresponding flags are rejected in `additional_args` so structured input remains authoritative. A status code cannot be both ignored and configured to abort.

Absolute raw-request targets must match their `Host` header, and selected resolution additionally rejects Host, proxy, redirect, scheme, port, and DNS-OOB overrides while binding the raw destination to the signed service.

Raw requests, traffic logs, and SQLmap output are kept in a mode-restricted temporary workspace and deleted after completion. `--ignore-stdin` is applied automatically so MCP's non-TTY process input cannot override a supplied raw request.

## Bounded manual HTTP requests

Use `http_request` instead of `execute_command` with curl for one-off validation. It accepts HTTP(S) only, one request per call, an optional arbitrary `json_body`, bounded raw bodies and responses, a maximum 300-second timeout, and at most five same-origin redirects. The `safe-recon` profile limits methods to GET, HEAD, and OPTIONS.

Loopback targets require a selected `target_context` or the legacy explicit URL plus receipt. Context-bound requests reject generic `Host` headers, while `virtual_host` is allowed only with `target_context` and cannot change the signed connection URL.

Request headers, response headers, URLs, and bodies are preserved verbatim unless the caller supplies exact `redact_values`. Browser network evidence follows the same rule, retaining query and fragment values for reproduction until explicit redaction is requested.

## Scan load and SPA baselines

Nikto requires the caller to select one or more installed names through `plugins`; the server does not choose an implicit plugin set. `get_scan_capabilities` with `tool_name: "nikto_scan"` exposes the current image's plugin inventory before execution, and each result records the exact selection in `execution.plugins` alongside the Nikto version. Plugin installation remains part of the Docker image rather than an MCP operation. Nikto also supports `pause_seconds`, `max_time`, `request_timeout`, `failure_limit`, and `tuning`, disables interactive/update checks, and still obeys the outer request timeout. Dirb runs in silent terminal mode and returns parsed URLs, status codes, response sizes, and directory markers through `discovered_paths` while retaining its raw output artifact. Feroxbuster also returns deduplicated response events through `discovered_paths` while retaining complete raw JSONL in the artifact. FFUF supports `request_timeout` for each HTTP request and `filter_status_codes` for explicit response filtering; these are separate from the outer scan `timeout`. `get_scan_capabilities` exposes both the common and small directory wordlists so the caller can select scan breadth explicitly.

Before FFUF, Gobuster directory mode, or Feroxbuster starts, the server samples random missing paths and compares status, length, and normalized body hashes without following cross-origin redirects. A stable successful fallback is excluded by size, and every result includes the measured baseline plus `false_positive_risk`. An unstable fallback remains visible with a warning.

Nuclei templates are installed when the Docker image is built, and `server_health` reports Nuclei unavailable if their checksum is missing without downloading anything. Normal Nuclei runs execute directly without a template-count or duration-estimation preflight. Set `dry_run: true` to list the matching local template count without contacting the target; this count is not converted into a request or duration estimate because templates and workflows can issue variable traffic.

Page the full Nuclei JSONL with `result_artifact_read` using `section: "stdout"`, `start_line`, and `line_count`; there is no cumulative read limit. Nuclei never silently reduces the selected scope.

## Browser local storage

`browser_check.local_storage` accepts a string map that is installed before application scripts execute. Values are injected only when the document origin matches the selected URL, are not copied into cross-origin frames or redirects, and disappear when the isolated browser context closes. This is per-call input like `headers`, not a reusable credential session.

## John and JWT workspaces

John accepts either `hash_file` or an inline `hash`. Inline hashes and John state live under a temporary HOME that is deleted after the run. Set `mask_plaintext` to redact recovered plaintext from returned output. JWT Tool likewise starts from a clean temporary HOME seeded with its packaged configuration, then removes that workspace after each call.

## Artifact retention and redaction

Completed, failed, timed-out, and cancelled tool calls write a mode-`0600` JSON result into a private server directory before the MCP response is compacted. The result contains an opaque artifact ID and `/api/artifacts/...` location, both protected by the same bearer token. Artifacts expire after one hour and are removed when the server shuts down.

Results are retained verbatim by default and carry `redaction_state: sensitive_unredacted`; callers can opt into exact-value replacement through `redact_values`, subject to bounded count and size limits, which marks affected result artifacts as `redacted`. Credential and privacy handling remains the caller or orchestrator's responsibility.

## Choosing between `hydra_attack` and `hydra_attack_stream`

- Use `hydra_attack` for quick checks such as a single username/password attempt or other short runs where a buffered final result is sufficient.
- Use `hydra_attack_stream` for long-running Hydra jobs when you want progress as it happens, especially with `username_file` and/or `password_file` inputs.
