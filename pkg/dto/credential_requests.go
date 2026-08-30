package dto

type DryRunRequest interface {
	GetDryRun() bool
}

type MetasploitRequest struct {
	ScanOptions
	Module       string            `json:"module" jsonschema:"required,module path e.g. auxiliary/scanner/http/title"`
	Target       string            `json:"target,omitempty" jsonschema:"target IP or hostname; omit when target_context is supplied"`
	Options      map[string]string `json:"options,omitempty" jsonschema:"module options excluding RHOST and RHOSTS, which are set from target or target_context"`
	DryRun       bool              `json:"dry_run,omitempty" jsonschema:"validate policy and return a redacted execution preview without running Metasploit"`
	RedactValues []string          `json:"redact_values,omitempty" jsonschema:"exact sensitive values to replace in output"`
	Timeout      int               `json:"timeout,omitempty" jsonschema:"request timeout in seconds (0 = default 300s)"`
}

func (r MetasploitRequest) GetRequestTimeout() int { return r.Timeout }
func (r MetasploitRequest) GetDryRun() bool        { return r.DryRun }

type HydraRequest struct {
	ScanOptions
	Target         string `json:"target,omitempty" jsonschema:"target IP or hostname; omit when target_context is supplied"`
	Service        string `json:"service" jsonschema:"required,service e.g. ssh ftp http-post-form"`
	Username       string `json:"username,omitempty" jsonschema:"single username; mutually exclusive with username_file; provide exactly one of username or username_file"`
	UsernameFile   string `json:"username_file,omitempty" jsonschema:"path to username list; mutually exclusive with username"`
	Password       string `json:"password,omitempty" jsonschema:"single password; mutually exclusive with password_file; provide exactly one of password or password_file"`
	PasswordFile   string `json:"password_file,omitempty" jsonschema:"path to password list; mutually exclusive with password"`
	AdditionalArgs string `json:"additional_args,omitempty" jsonschema:"extra hydra arguments"`
	DryRun         bool   `json:"dry_run,omitempty" jsonschema:"validate policy and return a redacted execution preview without running Hydra"`
	Timeout        int    `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the attack (0 = default 300s)"`
}

func (r HydraRequest) GetRequestTimeout() int { return r.Timeout }
func (r HydraRequest) GetDryRun() bool        { return r.DryRun }

type JohnRequest struct {
	HashFile       string   `json:"hash_file,omitempty" jsonschema:"path to hash file; mutually exclusive with hash"`
	Hash           string   `json:"hash,omitempty" jsonschema:"inline hash; stored in a mode-0600 temporary file and deleted after the run"`
	Wordlist       string   `json:"wordlist,omitempty" jsonschema:"path to wordlist (default: rockyou.txt)"`
	Format         string   `json:"format,omitempty" jsonschema:"hash format e.g. md5crypt"`
	MaskPlaintext  bool     `json:"mask_plaintext,omitempty" jsonschema:"mask recovered plaintext passwords in returned output"`
	RedactValues   []string `json:"redact_values,omitempty" jsonschema:"exact sensitive values to replace in output"`
	AdditionalArgs string   `json:"additional_args,omitempty" jsonschema:"extra john arguments"`
	Timeout        int      `json:"timeout,omitempty" jsonschema:"request timeout in seconds for the cracking run (0 = default 300s)"`
}

func (r JohnRequest) GetRequestTimeout() int { return r.Timeout }
