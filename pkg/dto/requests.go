package dto

type CommandRequest struct {
	Command string `json:"command" jsonschema:"required,the shell command to run on Kali"`
	Timeout int    `json:"timeout,omitempty" jsonschema:"timeout in seconds (0 = default 300s)"`
}

type NmapRequest struct {
	Target         string `json:"target" jsonschema:"required,IP address or hostname to scan"`
	ScanType       string `json:"scan_type" jsonschema:"nmap scan flags (default: -sCV)"`
	Ports          string `json:"ports" jsonschema:"port list or range e.g. 80,443,8000-8080"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra nmap arguments (default: -T4 -Pn)"`
}

type GobusterRequest struct {
	URL            string `json:"url" jsonschema:"required,target URL"`
	Mode           string `json:"mode" jsonschema:"dir|dns|fuzz|vhost (default: dir)"`
	Wordlist       string `json:"wordlist" jsonschema:"path to wordlist file"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra gobuster arguments"`
}

type DirbRequest struct {
	URL            string `json:"url" jsonschema:"required,target URL"`
	Wordlist       string `json:"wordlist" jsonschema:"path to wordlist file"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra dirb arguments"`
}

type NiktoRequest struct {
	Target         string `json:"target" jsonschema:"required,target URL or IP"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra nikto arguments"`
}

type TsharkRequest struct {
	Interface      string `json:"interface" jsonschema:"network interface for live capture e.g. eth0; mutually exclusive with read_file; provide exactly one of interface or read_file"`
	CaptureFilter  string `json:"capture_filter" jsonschema:"BPF capture filter e.g. tcp port 80"`
	DisplayFilter  string `json:"display_filter" jsonschema:"Wireshark display filter"`
	PacketCount    string `json:"packet_count" jsonschema:"number of packets to capture (positive integer)"`
	Duration       string `json:"duration" jsonschema:"capture duration in seconds (positive integer)"`
	ReadFile       string `json:"read_file" jsonschema:"pcap file path to read from; mutually exclusive with interface; provide exactly one of read_file or interface"`
	OutputFields   string `json:"output_fields" jsonschema:"comma-separated fields to extract"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra tshark arguments"`
}

type SQLMapRequest struct {
	URL            string `json:"url" jsonschema:"required,target URL"`
	Data           string `json:"data" jsonschema:"POST data string"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra sqlmap arguments"`
}

type MetasploitRequest struct {
	Module  string            `json:"module" jsonschema:"required,module path e.g. exploit/multi/handler"`
	Options map[string]string `json:"options" jsonschema:"module options as key-value pairs"`
}

type HydraRequest struct {
	Target         string `json:"target" jsonschema:"required,target IP or hostname"`
	Service        string `json:"service" jsonschema:"required,service e.g. ssh ftp http-post-form"`
	Username       string `json:"username" jsonschema:"single username; mutually exclusive with username_file; provide exactly one of username or username_file"`
	UsernameFile   string `json:"username_file" jsonschema:"path to username list; mutually exclusive with username"`
	Password       string `json:"password" jsonschema:"single password; mutually exclusive with password_file; provide exactly one of password or password_file"`
	PasswordFile   string `json:"password_file" jsonschema:"path to password list; mutually exclusive with password"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra hydra arguments"`
}

type JohnRequest struct {
	HashFile       string `json:"hash_file" jsonschema:"required,path to hash file"`
	Wordlist       string `json:"wordlist" jsonschema:"path to wordlist (default: rockyou.txt)"`
	Format         string `json:"format" jsonschema:"hash format e.g. md5crypt"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra john arguments"`
}

type WPScanRequest struct {
	URL            string `json:"url" jsonschema:"required,target WordPress URL"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra wpscan arguments"`
}

type Enum4linuxRequest struct {
	Target         string `json:"target" jsonschema:"required,target IP or hostname"`
	AdditionalArgs string `json:"additional_args" jsonschema:"extra enum4linux arguments (default: -a)"`
}
