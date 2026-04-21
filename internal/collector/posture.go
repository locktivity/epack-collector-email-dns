package collector

import "time"

// Config is the input configuration for the email DNS collector.
type Config struct {
	// Domains is the list of email domains to scan.
	Domains []string

	// Callbacks for progress reporting
	OnStatus   func(string)
	OnProgress func(current int64, total int64, message string)
}

// EmailDNSPosture is the output schema for the email DNS collector.
type EmailDNSPosture struct {
	SchemaVersion string    `json:"schema_version"`
	CollectedAt   time.Time `json:"collected_at"`

	// Results per domain
	Domains []DomainResult `json:"domains"`

	// Summary statistics
	Summary Summary `json:"summary"`
}

// DomainResult contains all email DNS records for a single domain.
type DomainResult struct {
	Domain string `json:"domain"`

	// MX records
	MX []MXRecord `json:"mx"`

	// SPF record (TXT record starting with v=spf1)
	SPF *SPFRecord `json:"spf"`

	// DMARC record (_dmarc.domain TXT)
	DMARC *DMARCRecord `json:"dmarc"`

	// DKIM records (if selectors are known)
	DKIM []DKIMRecord `json:"dkim,omitempty"`

	// Assessment of email security posture
	Assessment Assessment `json:"assessment"`

	// Any errors encountered
	Errors []string `json:"errors,omitempty"`
}

// Assessment provides a pass/fail evaluation of email security.
type Assessment struct {
	// Enforced is true if DMARC policy is "reject"
	Enforced bool `json:"enforced"`
	// HasReporting is true if rua (aggregate reports) is configured
	HasReporting bool `json:"has_reporting"`
	// Issues lists any problems found
	Issues []string `json:"issues,omitempty"`
}

// MXRecord represents a mail exchange record.
type MXRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

// SPFRecord represents an SPF policy.
type SPFRecord struct {
	Record string `json:"record"`
	Valid  bool   `json:"valid"`
}

// DMARCRecord represents a DMARC policy.
type DMARCRecord struct {
	Record          string `json:"record"`
	Policy          string `json:"policy"`           // none, quarantine, reject
	SubdomainPolicy string `json:"subdomain_policy"` // sp= value, defaults to policy if not set
	Pct             int    `json:"pct"`              // percentage of messages to apply policy (default 100)
	RUA             string `json:"rua,omitempty"`    // aggregate report URI
	RUF             string `json:"ruf,omitempty"`    // forensic report URI
	Valid           bool   `json:"valid"`
}

// DKIMRecord represents a DKIM selector record.
type DKIMRecord struct {
	Selector string `json:"selector"`
	Record   string `json:"record"`
	Valid    bool   `json:"valid"`
}

// Summary contains aggregate statistics across all domains.
type Summary struct {
	TotalDomains int `json:"total_domains"`
	WithMX       int `json:"with_mx"`
	WithSPF      int `json:"with_spf"`
	WithDMARC    int `json:"with_dmarc"`
	WithDKIM     int `json:"with_dkim"`
	WithAllThree int `json:"with_all_three"` // MX + SPF + DMARC
	ErrorCount   int `json:"error_count"`

	// Enforcement metrics
	Enforced        int  `json:"enforced"`          // domains with DMARC p=reject
	WithReporting   int  `json:"with_reporting"`    // domains with rua configured
	AllEnforced     bool `json:"all_enforced"`      // true if all domains have p=reject
	EnforcedPct     int  `json:"enforced_pct"`      // percentage of domains enforced
	WithReportingPct int `json:"with_reporting_pct"` // percentage with reporting
}
