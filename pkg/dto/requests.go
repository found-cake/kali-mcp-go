package dto

import "encoding/json"

type TimeoutRequest interface {
	GetRequestTimeout() int
}

type CommandRequest struct {
	Command      string   `json:"command" jsonschema:"required,the shell command to run on Kali"`
	Timeout      int      `json:"timeout,omitempty" jsonschema:"timeout in seconds (0 = default 300s)"`
	RedactValues []string `json:"redact_values,omitempty" jsonschema:"optional exact values to replace in output and artifacts; all other content is preserved verbatim"`
}

func (r CommandRequest) GetRequestTimeout() int { return r.Timeout }

type NmapRequest struct {
	ScanOptions
	Target         string `json:"target,omitempty" jsonschema:"IP address or hostname to scan; omit when target_context is supplied"`
	ScanType       string `json:"scan_type,omitempty" jsonschema:"nmap scan flags only (default: -sCV); positional targets, input lists, resume files, idle-scan zombies, and FTP relays are rejected"`
	Ports          string `json:"ports,omitempty" jsonschema:"port list or range e.g. 80,443,8000-8080; target_context fills the signed candidate port and rejects any different selection"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra target-neutral nmap options (default: -T4 -Pn); positional targets are rejected, option values must use attached --flag=value syntax, and safe-recon permits only passive script selectors without script arguments"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r NmapRequest) GetRequestTimeout() int { return r.Timeout }

type GobusterRequest struct {
	ScanOptions
	URL            string `json:"url,omitempty" jsonschema:"target URL; omit when target_context is supplied"`
	Mode           string `json:"mode,omitempty" jsonschema:"dir|dns|fuzz|vhost (default: dir)"`
	Wordlist       string `json:"wordlist,omitempty" jsonschema:"path to wordlist file"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra Gobuster arguments excluding target URL overrides; safety profiles forbid HTTP method overrides"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r GobusterRequest) GetRequestTimeout() int { return r.Timeout }

type DirbRequest struct {
	ScanOptions
	URL            string `json:"url,omitempty" jsonschema:"target URL; omit when target_context is supplied"`
	Wordlist       string `json:"wordlist,omitempty" jsonschema:"path to wordlist file"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra dirb arguments"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r DirbRequest) GetRequestTimeout() int { return r.Timeout }

type NiktoRequest struct {
	ScanOptions
	Target         string  `json:"target,omitempty" jsonschema:"target URL or IP; omit when target_context is supplied"`
	PauseSeconds   float64 `json:"pause_seconds,omitempty" jsonschema:"delay between requests in seconds"`
	MaxTime        string  `json:"max_time,omitempty" jsonschema:"maximum Nikto scan duration e.g. 120s or 10m"`
	Tuning         string  `json:"tuning,omitempty" jsonschema:"Nikto tuning selectors e.g. 123; web-discovery-low-rate rejects DoS category 6 and command-execution category 8 unless excluded with x"`
	AdditionalArgs string  `json:"additional_args,omitempty" jsonschema:"extra Nikto arguments excluding host and config overrides"`
	Timeout        int     `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r NiktoRequest) GetRequestTimeout() int { return r.Timeout }

type TsharkRequest struct {
	Interface      string `json:"interface,omitempty" jsonschema:"network interface for live capture e.g. eth0; mutually exclusive with read_file; provide exactly one of interface or read_file"`
	CaptureFilter  string `json:"capture_filter,omitempty" jsonschema:"BPF capture filter e.g. tcp port 80"`
	DisplayFilter  string `json:"display_filter,omitempty" jsonschema:"Wireshark display filter"`
	PacketCount    string `json:"packet_count,omitempty" jsonschema:"number of packets to capture (positive integer)"`
	Duration       string `json:"duration,omitempty" jsonschema:"capture duration in seconds (positive integer)"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the overall stream (0 = default 300s); distinct from duration"`
	ReadFile       string `json:"read_file,omitempty" jsonschema:"pcap file path to read from; mutually exclusive with interface; provide exactly one of interface or read_file"`
	OutputFields   string `json:"output_fields,omitempty" jsonschema:"comma-separated fields to extract"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra tshark arguments"`
}

func (r TsharkRequest) GetRequestTimeout() int { return r.Timeout }

type SQLMapRequest struct {
	ScanOptions
	URL            string            `json:"url,omitempty" jsonschema:"target URL; provide exactly one of url, request_file, or raw_request"`
	RequestFile    string            `json:"request_file,omitempty" jsonschema:"path to a raw HTTP request file; mutually exclusive with url and raw_request"`
	RawRequest     string            `json:"raw_request,omitempty" jsonschema:"inline raw HTTP request; stored in a mode-0600 temporary file and deleted after the scan"`
	Data           string            `json:"data,omitempty" jsonschema:"POST body; place an asterisk after a JSON field value to mark its injection point"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"HTTP headers such as Authorization; Host overrides are rejected with target_context"`
	Cookie         string            `json:"cookie,omitempty" jsonschema:"Cookie header value"`
	ContentType    string            `json:"content_type,omitempty" jsonschema:"Content-Type header value e.g. application/json"`
	IgnoreCodes    string            `json:"ignore_codes,omitempty" jsonschema:"comma-separated expected HTTP error codes to ignore e.g. 401,500"`
	TestParameters string            `json:"test_parameters,omitempty" jsonschema:"comma-separated parameters or JSON fields to test"`
	AdditionalArgs string            `json:"additional_args,omitempty" jsonschema:"extra SQLmap arguments excluding alternate sources; sqli-verify-low-risk pins risk 1, level 1, techniques BEU and forbids takeover, write, broad extraction, tamper, and hook options"`
	Timeout        int               `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r SQLMapRequest) GetRequestTimeout() int { return r.Timeout }

type WPScanRequest struct {
	ScanOptions
	URL            string `json:"url,omitempty" jsonschema:"target WordPress URL; omit when target_context is supplied"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra WPScan arguments excluding URL and config overrides"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r WPScanRequest) GetRequestTimeout() int { return r.Timeout }

type Enum4linuxRequest struct {
	ScanOptions
	Target         string `json:"target,omitempty" jsonschema:"target IP or hostname; omit when target_context is supplied"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra target-neutral Enum4linux options (default: -a); positional arguments are rejected and option values must use attached --flag=value syntax"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r Enum4linuxRequest) GetRequestTimeout() int { return r.Timeout }

type FFUFRequest struct {
	ScanOptions
	URL            string `json:"url,omitempty" jsonschema:"target URL containing FUZZ; may extend the browser origin from target_context"`
	Wordlist       string `json:"wordlist,omitempty" jsonschema:"path to wordlist file"`
	FilterSize     string `json:"filter_size,omitempty" jsonschema:"response size or comma-separated sizes to exclude"`
	RequestTimeout int    `json:"request_timeout,omitempty" jsonschema:"per-request HTTP timeout in seconds (default 10, maximum 300); distinct from the outer timeout"`
	FilterStatuses string `json:"filter_status_codes,omitempty" jsonschema:"HTTP status codes or ranges to omit from findings, e.g. 404,500-599"`
	Recursion      bool   `json:"recursion,omitempty" jsonschema:"enable recursive discovery"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra FFUF arguments excluding URL, raw-request, and config source overrides; safety profiles forbid request method, body, and command-input overrides"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r FFUFRequest) GetRequestTimeout() int { return r.Timeout }

type FeroxbusterRequest struct {
	ScanOptions
	URL            string `json:"url,omitempty" jsonschema:"target base URL; omit when target_context is supplied"`
	Wordlist       string `json:"wordlist,omitempty" jsonschema:"path to wordlist file"`
	FilterSize     string `json:"filter_size,omitempty" jsonschema:"response size or comma-separated sizes to exclude"`
	Depth          int    `json:"depth,omitempty" jsonschema:"maximum recursion depth (0 = tool default)"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra Feroxbuster arguments excluding URL, stdin, resume, request-file, and config source overrides; safety profiles forbid request method and body overrides"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r FeroxbusterRequest) GetRequestTimeout() int { return r.Timeout }

type NucleiRequest struct {
	ScanOptions
	Target         string   `json:"target,omitempty" jsonschema:"target URL or host; omit when target_context is supplied"`
	Severity       string   `json:"severity,omitempty" jsonschema:"comma-separated severities"`
	Tags           string   `json:"tags,omitempty" jsonschema:"comma-separated template tags to include"`
	Templates      []string `json:"templates,omitempty" jsonschema:"specific template paths or IDs"`
	AllowUnsafe    bool     `json:"allow_unsafe,omitempty" jsonschema:"allow DoS, fuzz, DAST, OAST, and interactsh behavior; false excludes these behaviors"`
	DryRun         bool     `json:"dry_run,omitempty" jsonschema:"enumerate matching local templates and preview the command without contacting the target"`
	AdditionalArgs string   `json:"additional_args,omitempty" jsonschema:"extra Nuclei arguments excluding target, target-list, and resume source overrides"`
	Timeout        int      `json:"timeout,omitempty" jsonschema:"outer timeout in seconds; 0 derives it from request and rate budgets, while shorter explicit values are preserved with a warning"`
}

func (r NucleiRequest) GetRequestTimeout() int { return r.Timeout }
func (r NucleiRequest) GetDryRun() bool        { return r.DryRun }

type WhatWebRequest struct {
	ScanOptions
	Target         string `json:"target,omitempty" jsonschema:"target URL or host; omit when target_context is supplied"`
	Aggression     int    `json:"aggression,omitempty" jsonschema:"aggression level 1-4 (0 = tool default); safety profiles allow at most level 1"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra target-neutral WhatWeb options; positional targets are rejected and option values must use attached --flag=value syntax"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r WhatWebRequest) GetRequestTimeout() int { return r.Timeout }

type JWTRequest struct {
	ScanOptions
	Token          string `json:"token" jsonschema:"required,raw JWT that is always parsed for offline structure and metadata"`
	TargetURL      string `json:"target_url,omitempty" jsonschema:"optional application endpoint that enables live token acceptance verification"`
	RequestHeader  string `json:"request_header,omitempty" jsonschema:"full request header template containing the literal JWT_HERE placeholder; used only with target_url"`
	RequestCookie  string `json:"request_cookie,omitempty" jsonschema:"request cookie template containing the literal JWT_HERE placeholder; used only with target_url"`
	Canary         string `json:"canary,omitempty" jsonschema:"response text indicating an accepted token during live verification"`
	Mode           string `json:"mode,omitempty" jsonschema:"jwt_tool scan mode pb|er|at; defaults to at for live targets"`
	PublicKey      string `json:"public_key,omitempty" jsonschema:"public key path for RS/HS confusion testing"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra jwt_tool arguments excluding live-target overrides"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r JWTRequest) GetRequestTimeout() int { return r.Timeout }

type DalfoxRequest struct {
	ScanOptions
	Target         string `json:"target,omitempty" jsonschema:"target URL or raw HTTP file; omit only for a URL supplied through target_context"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra Dalfox arguments excluding positional and alternate request sources; option values must use attached --flag=value syntax, concurrency replaces worker flags, and browser-xss-confirm forbids method and body overrides"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r DalfoxRequest) GetRequestTimeout() int { return r.Timeout }

type BrowserRequest struct {
	ScanOptions
	URL               string `json:"url,omitempty" jsonschema:"full page URL including SPA path, hash route, fragment payload, or query payload; may extend the browser origin from target_context"`
	WaitMilliseconds  int    `json:"wait_milliseconds,omitempty" jsonschema:"time to observe dialogs and DOM changes after load"`
	IncludeDOM        bool   `json:"include_dom,omitempty" jsonschema:"include up to 200KB of rendered DOM in the result"`
	CaptureNetwork    bool   `json:"capture_network,omitempty" jsonschema:"capture a bounded raw network artifact whose script URLs can be passed to retirejs_scan"`
	CaptureScreenshot bool   `json:"capture_screenshot,omitempty" jsonschema:"capture a viewport screenshot as a sensitive related artifact"`
	Timeout           int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds (0 = default 300s)"`
}

func (r BrowserRequest) GetRequestTimeout() int { return r.Timeout }

type RetireRequest struct {
	ScanOptions
	Path           string   `json:"path,omitempty" jsonschema:"file or directory containing JavaScript bundles; mutually exclusive with url and script_urls"`
	URL            string   `json:"url,omitempty" jsonschema:"page URL whose same-origin public JavaScript bundles should be downloaded and scanned; mutually exclusive with path and script_urls"`
	ScriptURLs     []string `json:"script_urls,omitempty" jsonschema:"explicit same-origin public JavaScript bundle URLs observed by browser_check; requires target_context and is mutually exclusive with path and url"`
	AdditionalArgs string   `json:"additional_args,omitempty" jsonschema:"extra Retire.js arguments excluding path overrides"`
	Timeout        int      `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r RetireRequest) GetRequestTimeout() int { return r.Timeout }

type OSVRequest struct {
	Path           string `json:"path" jsonschema:"required,source directory to scan recursively"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra OSV-Scanner arguments"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the scan (0 = default 300s)"`
}

func (r OSVRequest) GetRequestTimeout() int { return r.Timeout }

type HTTPRequest struct {
	ScanOptions
	URL              string            `json:"url,omitempty" jsonschema:"HTTP or HTTPS URL; omit when target_context is supplied"`
	Method           string            `json:"method,omitempty" jsonschema:"GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS (default GET); safe-recon permits only GET, HEAD, and OPTIONS"`
	Headers          map[string]string `json:"headers,omitempty" jsonschema:"request headers; Host overrides are rejected with target_context and returned evidence preserves other values unless redact_values explicitly selects them"`
	Body             string            `json:"body,omitempty" jsonschema:"raw request body; mutually exclusive with json_body"`
	JSONBody         json.RawMessage   `json:"json_body,omitempty" jsonschema:"JSON request body; mutually exclusive with body"`
	FollowRedirects  bool              `json:"follow_redirects,omitempty" jsonschema:"follow at most five same-origin redirects"`
	MaxResponseBytes int               `json:"max_response_bytes,omitempty" jsonschema:"maximum response body bytes to retain (default 1048576, maximum 4194304)"`
	Timeout          int               `json:"timeout,omitempty" jsonschema:"request timeout in seconds (default 30, maximum 300)"`
}

func (r HTTPRequest) GetRequestTimeout() int { return r.Timeout }
