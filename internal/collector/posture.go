package collector

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// Config is the input configuration for the email DNS collector.
type Config struct {
	// Domains is the list of email domains to scan.
	Domains []string

	// Resolver makes the DNS lookups.
	Resolver Resolver

	// Recorder takes a gap for each value a failed lookup leaves out.
	Recorder *componentsdk.Recorder

	// Now stamps collected_at.
	Now func() time.Time

	// OnProgress reports each domain a step reaches. A step's title is the
	// run's status line, which componentsdk.StartStep prints.
	OnProgress func(current int64, total int64, message string)
}

// Resolver looks up DNS records. componentsdk.Resolver implements it, and so
// does net.Resolver.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// EmailDNSPosture is the output schema for the email DNS collector.
type EmailDNSPosture struct {
	SchemaVersion string    `json:"schema_version"`
	CollectedAt   time.Time `json:"collected_at"`

	// Results per domain
	Domains []DomainResult `json:"domains"`

	// Summary statistics
	Summary Summary `json:"summary"`

	// Diagnostics contains warnings and errors encountered during collection
	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`
}

// Diagnostics contains warnings and errors encountered during collection.
// This helps identify DNS resolution issues vs domains that genuinely lack records.
type Diagnostics struct {
	DomainErrors []string `json:"domain_errors,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// DomainResult contains all email DNS records for a single domain. A value
// whose lookup failed is left out, and the collector result records a gap
// for it.
type DomainResult struct {
	Domain string `json:"domain"`

	// MX records, empty when the domain has none
	MX []MXRecord `json:"mx,omitzero"`

	// SPF record (TXT record starting with v=spf1)
	SPF Lookup[SPFRecord] `json:"spf,omitzero"`

	// DMARC record (_dmarc.domain TXT)
	DMARC Lookup[DMARCRecord] `json:"dmarc,omitzero"`

	// DKIM records at the common selectors. When some selectors' lookups
	// failed it holds the records the others returned, and it is left out
	// when every lookup failed.
	DKIM []DKIMRecord `json:"dkim,omitzero"`

	// Assessment of email security posture
	Assessment Assessment `json:"assessment"`

	// Any errors encountered
	Errors []string `json:"errors,omitempty"`
}

// Lookup is a record the collector looked up. It marshals as the record, or
// as null when the domain publishes none. A failed lookup is not Read, which
// leaves the field out of the artifact.
type Lookup[T any] struct {
	Record *T
	Read   bool
}

// IsZero reports whether the lookup failed, for omitzero.
func (l Lookup[T]) IsZero() bool { return !l.Read }

// MarshalJSON writes the record, or null when the domain publishes none.
func (l Lookup[T]) MarshalJSON() ([]byte, error) { return json.Marshal(l.Record) }

// Assessment provides a pass/fail evaluation of email security. Enforced and
// HasReporting are left out when the DMARC lookup failed, and Issues when the
// SPF or DMARC lookup failed, or when a DKIM selector's lookup failed and no
// valid key was read.
type Assessment struct {
	// Enforced is true if DMARC policy is "reject"
	Enforced *bool `json:"enforced,omitempty"`
	// HasReporting is true if rua (aggregate reports) is configured
	HasReporting *bool `json:"has_reporting,omitempty"`
	// Issues lists any problems found
	Issues []string `json:"issues,omitzero"`
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

// Summary contains aggregate statistics across all domains. Each percentage
// is its count over total_domains, rounded down. A value is left out when a
// lookup it depends on failed for any domain.
type Summary struct {
	TotalDomains       int   `json:"total_domains"`
	WithMxCount        *int  `json:"with_mx_count,omitempty"`
	WithMxPct          *int  `json:"with_mx_pct,omitempty"`
	WithSpfCount       *int  `json:"with_spf_count,omitempty"`
	WithSpfPct         *int  `json:"with_spf_pct,omitempty"`
	WithDmarcCount     *int  `json:"with_dmarc_count,omitempty"`
	WithDmarcPct       *int  `json:"with_dmarc_pct,omitempty"`
	WithDkimCount      *int  `json:"with_dkim_count,omitempty"`
	WithDkimPct        *int  `json:"with_dkim_pct,omitempty"`
	WithAllThreeCount  *int  `json:"with_all_three_count,omitempty"` // MX + SPF + DMARC
	WithAllThreePct    *int  `json:"with_all_three_pct,omitempty"`
	EnforcedCount      *int  `json:"enforced_count,omitempty"` // DMARC p=reject at pct=100
	EnforcedPct        *int  `json:"enforced_pct,omitempty"`
	WithReportingCount *int  `json:"with_reporting_count,omitempty"` // rua configured
	WithReportingPct   *int  `json:"with_reporting_pct,omitempty"`
	AllEnforced        *bool `json:"all_enforced,omitempty"` // true if all domains have p=reject
}
