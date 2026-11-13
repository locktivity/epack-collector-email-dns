package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-email-dns/internal/dmarc"
	"github.com/locktivity/epack/componentsdk"
)

func read[T any](record *T) Lookup[T] {
	return Lookup[T]{Record: record, Read: true}
}

func show[T any](v *T) string {
	if v == nil {
		return "left out"
	}
	return fmt.Sprint(*v)
}

// parseDMARC describes record as the domain's own DMARC record.
func parseDMARC(record string) *DMARCRecord {
	r, _ := dmarc.Parse(record)
	return newDMARCRecord(record, r, false)
}

func TestParseDMARC(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		wantPolicy string
		wantSP     string
		wantPct    int
		wantRUA    string
	}{
		{
			name:       "full record",
			record:     "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@example.com",
			wantPolicy: "reject",
			wantSP:     "reject",
			wantPct:    100,
			wantRUA:    "mailto:dmarc@example.com",
		},
		{
			name:       "minimal record",
			record:     "v=DMARC1; p=none",
			wantPolicy: "none",
			wantSP:     "none", // inherits from policy
			wantPct:    100,    // default
			wantRUA:    "",
		},
		{
			name:       "quarantine with partial pct",
			record:     "v=DMARC1; p=quarantine; pct=50",
			wantPolicy: "quarantine",
			wantSP:     "quarantine",
			wantPct:    50,
			wantRUA:    "",
		},
		{
			name:       "different subdomain policy",
			record:     "v=DMARC1; p=reject; sp=none",
			wantPolicy: "reject",
			wantSP:     "none",
			wantPct:    100,
			wantRUA:    "",
		},
		{
			name:       "no p tag with a report URI is treated as p=none",
			record:     "v=DMARC1; rua=mailto:dmarc@example.com",
			wantPolicy: "none",
			wantSP:     "none",
			wantPct:    100,
			wantRUA:    "mailto:dmarc@example.com",
		},
		{
			name:       "no p tag and no report URI",
			record:     "v=DMARC1",
			wantPolicy: "unknown",
			wantSP:     "unknown",
			wantPct:    100,
		},
		{
			name:       "sp tag without a p tag",
			record:     "v=DMARC1; sp=reject",
			wantPolicy: "unknown",
			wantSP:     "unknown",
			wantPct:    100,
		},
		{
			name:       "invalid p tag",
			record:     "v=DMARC1; p=bogus",
			wantPolicy: "unknown",
			wantSP:     "unknown",
			wantPct:    100,
		},
		{
			name:       "policy in capitals",
			record:     "v=DMARC1; p=Quarantine",
			wantPolicy: "quarantine",
			wantSP:     "quarantine",
			wantPct:    100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDMARC(tt.record)
			if got.Policy != tt.wantPolicy {
				t.Errorf("Policy = %q, want %q", got.Policy, tt.wantPolicy)
			}
			if got.SubdomainPolicy != tt.wantSP {
				t.Errorf("SubdomainPolicy = %q, want %q", got.SubdomainPolicy, tt.wantSP)
			}
			if got.Pct != tt.wantPct {
				t.Errorf("Pct = %d, want %d", got.Pct, tt.wantPct)
			}
			if got.RUA != tt.wantRUA {
				t.Errorf("RUA = %q, want %q", got.RUA, tt.wantRUA)
			}
		})
	}
}

func TestValidateSPF(t *testing.T) {
	tests := []struct {
		record string
		valid  bool
	}{
		{"v=spf1 include:_spf.google.com ~all", true},
		{"v=spf1 -all", true},
		{"v=spf1 a mx -all", true},
		{"v=spf1 ip4:192.168.1.0/24 -all", true},
		{"v=spf1 +a +mx ~all", true},
		{"v=spf1 redirect=_spf.example.com", true},
		{"not an spf record", false},
		{"v=spf1", false},              // no mechanisms
		{"v=spf1 garbage", false},      // invalid term (not a mechanism or modifier)
		{"v=spf1 foo=bar", false},      // unknown modifier only, no valid mechanisms
		{"v=spf1 -all foo=bar", true},  // valid mechanism + unknown modifier per RFC 7208
		{"v=spf1 a foo=bar", true},     // valid mechanism + unknown modifier per RFC 7208
		{"v=spf1 -all garbage", false}, // valid mechanism + invalid term (not name=value)
		{"v=spf10 -all", false},        // wrong version number
		{"v=spf1x -all", false},        // version with extra chars
		{"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.com -all", true},
		{"v=spf1 a:mail.example.com/24 mx ~all", true},
		{"v=spf1 +a ?mx redirect=_spf.example.com", true},
		{"v=spf1 ipv4:192.0.2.10 -all", false},
		// Receivers return permerror for each of these, as RFC 7208 sections
		// 4.6, 5.2, and 5.6 define the grammar.
		{"v=spf1 ip4: -all", false},
		{"v=spf1 ip4:not-an-address -all", false},
		{"v=spf1 ip4:192.0.2.256 -all", false},
		{"v=spf1 ip4:192.0.2.1, include:_spf.example.com -all", false},
		{"v=spf1 ip4:192.0.2.0/33 -all", false},
		{"v=spf1 ip6:not-an-address -all", false},
		{"v=spf1 include: -all", false},
		{"v=spf1 ~-all", false},
		{"v=spf1 a mx ptr exists:x.example.com include:a.example include:b.example include:c.example include:d.example include:e.example include:f.example -all", true},                // 10 terms that cause lookups
		{"v=spf1 a mx ptr exists:x.example.com include:a.example include:b.example include:c.example include:d.example include:e.example include:f.example redirect=g.example", false}, // 11, over RFC 7208's limit
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			if got := validateSPF(tt.record); got != tt.valid {
				t.Errorf("validateSPF(%q) = %v, want %v", tt.record, got, tt.valid)
			}
		})
	}
}

func TestDMARCRecordValid(t *testing.T) {
	tests := []struct {
		record string
		valid  bool
	}{
		{"v=DMARC1; p=reject", true},
		{"v=DMARC1; p=none; rua=mailto:dmarc@example.com", true},
		{"v=DMARC1; p=quarantine; sp=reject", true},
		{"v=DMARC1", false}, // no policy
		{"p=reject", false}, // no version
		{"not a dmarc record", false},
		{"v=DMARC1; sp=reject", false},                         // sp= without p= or a report URI
		{"v=DMARC1; rua=mailto:x@y.com", true},                 // no p=, so the report URI makes it p=none per RFC 9989
		{"v=DMARC1; rua=x@y.com", false},                       // no p=, and the rua is not a URI
		{"v=DMARC1; rua=mailto:x@y.com mailto:z@y.com", false}, // no p=, and a URI holds no space
		{"v=DMARC1; p=bogus", false},                           // invalid policy value
		{"v=DMARC1; p=REJECT", true},                           // uppercase should work (case insensitive)
		{"v=DMARC1; p=invalid; rua=mailto:x", true},            // invalid policy with a report URI is treated as p=none
		{"v=DMARC10; p=reject", false},                         // wrong version number
		{"v=dmarc1x; p=reject", false},                         // version with extra chars
		{"v=dmarc1; p=reject", false},                          // the version is case-sensitive
		{"p=reject; v=DMARC1", false},                          // v= must be first tag per RFC 9989
		{"rua=mailto:x; v=DMARC1; p=reject", false},            // v= not first
		{"v=DMARC1; rua=mailto:x; p=reject", true},             // p= can appear after other tags (only v= must be first)
		{"v=DMARC1; p=reject; sp=bogus", false},                // an invalid sp= with no report URI leaves no DMARC policy
		{"v=DMARC1; p=reject; np=invalid", false},              // the same holds for np=
		{"v=DMARC1; p=reject; sp=bogus; rua=mailto:x", true},   // an invalid sp= with a report URI is treated as p=none
		{"v=DMARC1; p=reject; sp=none", true},                  // valid sp= value
		{"v=DMARC1; p=reject; sp=quarantine", true},            // valid sp= value
		{"v=DMARC1; p=reject; sp=reject", true},                // valid sp= value
		{"v = DMARC1; p = reject", true},                       // whitespace around = per RFC 7489 ABNF
		{"v= DMARC1; p= reject", true},                         // whitespace after = only
		{"v =DMARC1; p =reject", true},                         // whitespace before = only
		{"v=DMARC1;p=reject", true},                            // no whitespace around tags
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			r, isRecord := dmarc.Parse(tt.record)
			if got := isRecord && newDMARCRecord(tt.record, r, false).Valid; got != tt.valid {
				t.Errorf("valid for %q = %v, want %v", tt.record, got, tt.valid)
			}
		})
	}
}

func TestValidateDKIM(t *testing.T) {
	tests := []struct {
		record string
		valid  bool
	}{
		{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", true},
		{"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", true},
		{"v=DKIM1; p=;", false},          // empty key
		{"v=DKIM1; p= ", false},          // whitespace key
		{"v=DKIM1; k=rsa", false},        // no key
		{"sp=foo", false},                // not a DKIM record (would match old p= substring check)
		{"v=DKIM10; p=key", false},       // wrong version number
		{"k=rsa; v=DKIM1; p=key", false}, // v= must be first when present per RFC 6376
		{"p=key; v=DKIM1", false},        // v= not first

		{"v = DKIM1 ; k = rsa ; p = MIGfMA0GCSqGSIb3DQEBAQUAA4GN", true},     // whitespace around the equals signs
		{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3\r\n\tDQEBAQUAA4GN", true},       // a key folded across lines
		{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ==", true}, // a padded key
		{`v=DKIM1; k=rsa; p="MIGfMA0GCSqGSIb3DQEBAQUAA4GN\"`, false},         // quotes are not base64
		{"v=DKIM1; k=rsa; p=not-a-key", false},                               // hyphens are not base64
		{"v = DKIM2; p = MIGfMA0GCSqGSIb3DQEBAQUAA4GN", false},               // wrong version, with spaces
		{"k=rsa; v = DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", false},          // v= not first, with spaces

		{"V=DKIM1; K=rsa; P=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", false},                                 // tag names are case-sensitive, so there is no p tag
		{"v=dkim1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", false},                                 // the version is case-sensitive
		{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", false}, // a repeated tag makes the tag list invalid
		{"v=DKIM1; k=rsa; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", false},                          // the same holds for any tag
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			if got := validateDKIM(tt.record); got != tt.valid {
				t.Errorf("validateDKIM(%q) = %v, want %v", tt.record, got, tt.valid)
			}
		})
	}
}

func TestComputeAssessment(t *testing.T) {
	// above describes record as one the DNS tree walk found above the
	// domain.
	above := func(record string) *DMARCRecord {
		r, _ := dmarc.Parse(record)
		return newDMARCRecord(record, r, true)
	}
	enforcing := func() Lookup[DMARCRecord] {
		return read(parseDMARC("v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com"))
	}
	tests := []struct {
		name          string
		result        DomainResult
		dkimFailed    bool
		wantEnforced  *bool
		wantReporting *bool
		wantIssues    *int
	}{
		{
			name: "fully compliant",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: enforcing(),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(true),
			wantReporting: new(true),
			wantIssues:    new(0),
		},
		{
			name: "no records",
			result: DomainResult{
				SPF:   read[SPFRecord](nil),
				DMARC: read[DMARCRecord](nil),
				DKIM:  []DKIMRecord{},
			},
			wantEnforced:  new(false),
			wantReporting: new(false),
			wantIssues:    new(3), // no SPF, no DMARC, no DKIM
		},
		{
			name: "monitoring only",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: read(parseDMARC("v=DMARC1; p=none")),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(false),
			wantReporting: new(false),
			wantIssues:    new(3), // policy none, no reporting, subdomain not reject
		},
		{
			name: "reject with a legacy pct below 100",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: read(parseDMARC("v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com")),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(true),
			wantReporting: new(true),
			wantIssues:    new(0),
		},
		{
			name: "reject in testing mode",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: read(parseDMARC("v=DMARC1; p=reject; t=y; rua=mailto:dmarc@example.com")),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(false),
			wantReporting: new(true),
			wantIssues:    new(1), // testing mode
		},
		{
			name: "invalid sp with a report URI",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: read(parseDMARC("v=DMARC1; p=reject; sp=bogus; rua=mailto:x@example.com")),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(false),
			wantReporting: new(true),
			wantIssues:    new(3), // policy none, invalid sp=, subdomain not reject
		},
		{
			name: "invalid sp without a report URI",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: read(parseDMARC("v=DMARC1; p=reject; sp=bogus")),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(false),
			wantReporting: new(false),
			wantIssues:    new(1), // invalid DMARC record
		},
		{
			name: "rua without a URI scheme",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: read(parseDMARC("v=DMARC1; p=reject; sp=reject; rua=dmarc@example.com")),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(true),
			wantReporting: new(false),
			wantIssues:    new(2), // no reporting, an address that is not a URI
		},
		{
			name: "subdomain policy of reject on a record above the domain",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: read(above("v=DMARC1; p=none; sp=reject; rua=mailto:dmarc@example.com")),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(true),
			wantReporting: new(true),
			wantIssues:    new(0),
		},
		{
			name: "p=reject on a record above the domain with sp=none",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: read(above("v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com")),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(false),
			wantReporting: new(true),
			wantIssues:    new(2), // policy none, subdomain not reject
		},
		{
			name: "SPF lookup failed",
			result: DomainResult{
				DMARC: enforcing(),
				DKIM:  []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(true),
			wantReporting: new(true),
		},
		{
			name: "DMARC lookup failed",
			result: DomainResult{
				SPF:  read(&SPFRecord{Valid: true}),
				DKIM: []DKIMRecord{{Valid: true}},
			},
		},
		{
			name: "every DKIM lookup failed",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: enforcing(),
			},
			dkimFailed:    true,
			wantEnforced:  new(true),
			wantReporting: new(true),
		},
		{
			name: "a DKIM lookup failed and another returned a valid key",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: enforcing(),
				DKIM:  []DKIMRecord{{Valid: false}, {Valid: true}},
			},
			dkimFailed:    true,
			wantEnforced:  new(true),
			wantReporting: new(true),
			wantIssues:    new(0),
		},
		{
			name: "a DKIM lookup failed and another returned a revoked key",
			result: DomainResult{
				SPF:   read(&SPFRecord{Valid: true}),
				DMARC: enforcing(),
				DKIM:  []DKIMRecord{{Valid: false}},
			},
			dkimFailed:    true,
			wantEnforced:  new(true),
			wantReporting: new(true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeAssessment(&tt.result, !tt.dkimFailed)
			if !reflect.DeepEqual(got.Enforced, tt.wantEnforced) {
				t.Errorf("Enforced = %v, want %v", show(got.Enforced), show(tt.wantEnforced))
			}
			if !reflect.DeepEqual(got.HasReporting, tt.wantReporting) {
				t.Errorf("HasReporting = %v, want %v", show(got.HasReporting), show(tt.wantReporting))
			}
			switch {
			case tt.wantIssues == nil && got.Issues != nil:
				t.Errorf("Issues = %v, want them left out", got.Issues)
			case tt.wantIssues != nil && (got.Issues == nil || len(got.Issues) != *tt.wantIssues):
				t.Errorf("len(Issues) = %d, want %d; issues: %v", len(got.Issues), *tt.wantIssues, got.Issues)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	scans := []domainScan{
		{result: DomainResult{
			MX:         []MXRecord{{Host: "mail.example.com"}},
			SPF:        read(&SPFRecord{Valid: true}),
			DMARC:      read(&DMARCRecord{Policy: "reject", Pct: 100}),
			DKIM:       []DKIMRecord{{Valid: true}},
			Assessment: Assessment{Enforced: new(true), HasReporting: new(true)},
		}},
		{result: DomainResult{
			MX:         []MXRecord{},
			SPF:        read[SPFRecord](nil),
			DMARC:      read[DMARCRecord](nil),
			DKIM:       []DKIMRecord{},
			Assessment: Assessment{Enforced: new(false), HasReporting: new(false)},
		}},
	}

	rec := &componentsdk.Recorder{}
	s := scanner{rec: rec}
	summary := s.summarize(scans)

	want := Summary{
		TotalDomains:       2,
		WithMxCount:        new(1),
		WithMxPct:          new(50),
		WithSpfCount:       new(1),
		WithSpfPct:         new(50),
		WithDmarcCount:     new(1),
		WithDmarcPct:       new(50),
		WithDkimCount:      new(1),
		WithDkimPct:        new(50),
		WithAllThreeCount:  new(1),
		WithAllThreePct:    new(50),
		EnforcedCount:      new(1),
		EnforcedPct:        new(50),
		WithReportingCount: new(1),
		WithReportingPct:   new(50),
		AllEnforced:        new(false),
	}
	if !reflect.DeepEqual(summary, want) {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
	if gaps := rec.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none", gaps)
	}
}

func TestComputeDiagnostics(t *testing.T) {
	// No errors - should return nil
	domains := []DomainResult{
		{Domain: "example.com"},
	}
	diag := computeDiagnostics(domains)
	if diag != nil {
		t.Error("Expected nil diagnostics when no errors")
	}

	// With errors - should return diagnostics
	domainsWithErrors := []DomainResult{
		{Domain: "example.com", Errors: []string{"DNS timeout"}},
		{Domain: "test.com", Errors: []string{"NXDOMAIN"}},
	}
	diag = computeDiagnostics(domainsWithErrors)
	if diag == nil {
		t.Fatal("Expected non-nil diagnostics when errors present")
	}
	if len(diag.DomainErrors) != 2 {
		t.Errorf("DomainErrors count = %d, want 2", len(diag.DomainErrors))
	}
}

func TestDomainResultLeavesOutFailedLookups(t *testing.T) {
	tests := []struct {
		name   string
		result DomainResult
		want   string
	}{
		{
			name:   "every lookup failed",
			result: DomainResult{Domain: "example.com"},
			want:   `{"domain":"example.com","assessment":{}}`,
		},
		{
			name: "no records",
			result: DomainResult{
				Domain:     "example.com",
				MX:         []MXRecord{},
				SPF:        read[SPFRecord](nil),
				DMARC:      read[DMARCRecord](nil),
				DKIM:       []DKIMRecord{},
				Assessment: Assessment{Enforced: new(false), HasReporting: new(false), Issues: []string{}},
			},
			want: `{"domain":"example.com","mx":[],"spf":null,"dmarc":null,"dkim":[],"assessment":{"enforced":false,"has_reporting":false,"issues":[]}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.result)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("JSON = %s, want %s", got, tt.want)
			}
		})
	}
}

// expiredResolver fails each lookup the way net.Resolver does once the
// context's deadline has passed.
type expiredResolver struct{}

func (expiredResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true, UnwrapErr: ctx.Err()}
}

func (expiredResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true, UnwrapErr: ctx.Err()}
}

func TestCollectKeepsEveryDomainPastTheDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	rec := &componentsdk.Recorder{}

	posture := Collect(ctx, Config{
		Domains:  []string{"example.com", "example.org"},
		Resolver: expiredResolver{},
		Recorder: rec,
		Now:      time.Now,
	})

	if got := len(posture.Domains); got != 2 {
		t.Fatalf("got %d domains, want 2", got)
	}
	for _, d := range posture.Domains {
		if d.MX != nil || d.SPF.Read || d.DMARC.Read || d.DKIM != nil || d.Assessment.Enforced != nil || d.Assessment.Issues != nil {
			t.Errorf("%s kept a value it could not read: %+v", d.Domain, d)
		}
	}
	// Seven values per domain, and seven counts, seven percentages, and
	// all_enforced in the summary
	gaps := rec.Gaps()
	if len(gaps) != 29 {
		t.Errorf("got %d gaps, want 29", len(gaps))
	}
	for _, g := range gaps {
		if g.Code != componentsdk.CodeTimeout {
			t.Errorf("gap at %s has code %s, want timeout", g.Pointer, g.Code)
		}
	}
}

func TestSummaryGapsNameTheLineThatLeavesThemOut(t *testing.T) {
	// share records the gaps, so without Recorder.Helper every summary gap
	// would name the same line in share.
	rec := &componentsdk.Recorder{}
	Collect(context.Background(), Config{
		Domains:  []string{"example.com"},
		Resolver: expiredResolver{},
		Recorder: rec,
		Now:      time.Now,
	})

	sources := map[string]string{}
	for _, g := range rec.Gaps() {
		if strings.HasPrefix(g.Pointer, "/summary/") && strings.HasSuffix(g.Pointer, "_count") {
			sources[g.Source] = g.Pointer
		}
	}
	if len(sources) != 7 {
		t.Errorf("the seven count gaps name %d distinct lines, want one each: %v", len(sources), sources)
	}
	for source := range sources {
		if !strings.HasPrefix(source, "internal/collector/collector.go:") {
			t.Errorf("source %q is not a line in collector.go", source)
		}
	}
}

// zoneResolver answers from fixed TXT and MX tables. A name that is not in
// them does not exist.
type zoneResolver struct {
	txt map[string][]string
	mx  map[string][]*net.MX
}

func (r zoneResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := r.txt[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (r zoneResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if v, ok := r.mx[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// collectZone scans domains in res and fails the test on any gap.
func collectZone(t *testing.T, res zoneResolver, domains ...string) *EmailDNSPosture {
	t.Helper()
	rec := &componentsdk.Recorder{}
	p := Collect(context.Background(), Config{Domains: domains, Resolver: res, Recorder: rec, Now: time.Now})
	if gaps := rec.Gaps(); len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	return p
}

func TestCollectAppliesTheDMARCRecordAboveADomain(t *testing.T) {
	parent := "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com"
	res := zoneResolver{txt: map[string][]string{
		"_dmarc.example.com":     {parent},
		"_dmarc.own.example.com": {"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
		"_dmarc.example.org":     {"v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.org"},
	}}
	p := collectZone(t, res, "corp.example.com", "own.example.com", "corp.example.org", "corp.example.net")

	want := []struct {
		enforced, reporting bool
		record              string
	}{
		{true, true, parent},
		{true, true, "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
		{false, true, "v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.org"},
		{false, false, ""},
	}
	for i, w := range want {
		d := p.Domains[i]
		a := d.Assessment
		if a.Enforced == nil || *a.Enforced != w.enforced || a.HasReporting == nil || *a.HasReporting != w.reporting {
			t.Errorf("%s: enforced = %s, has_reporting = %s, want %v, %v; issues: %v",
				d.Domain, show(a.Enforced), show(a.HasReporting), w.enforced, w.reporting, a.Issues)
		}
		got := ""
		if d.DMARC.Record != nil {
			got = d.DMARC.Record.Record
		}
		if got != w.record {
			t.Errorf("%s: dmarc.record = %q, want %q", d.Domain, got, w.record)
		}
		if hasNoDMARC := slices.Contains(a.Issues, "No DMARC record"); hasNoDMARC != (w.record == "") {
			t.Errorf("%s: issues = %v", d.Domain, a.Issues)
		}
	}

	s := p.Summary
	for name, pair := range map[string][2]*int{
		"with_dmarc_count":     {s.WithDmarcCount, new(3)},
		"enforced_count":       {s.EnforcedCount, new(2)},
		"enforced_pct":         {s.EnforcedPct, new(50)},
		"with_reporting_count": {s.WithReportingCount, new(3)},
	} {
		if got, want := pair[0], pair[1]; got == nil || *got != *want {
			t.Errorf("summary %s = %s, want %d", name, show(got), *want)
		}
	}
}

func TestCollectCountsReportingOnlyForReportURIs(t *testing.T) {
	cases := []struct {
		domain, record string
		reporting      bool
	}{
		{"one.example", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com", true},
		{"many.example", "v=DMARC1; p=reject; rua=mailto:a@example.com, mailto:b@example.com!10m", true},
		{"none.example", "v=DMARC1; p=reject", false},
		{"bare.example", "v=DMARC1; p=reject; rua=dmarc@example.com", false},
		{"bare-list.example", "v=DMARC1; p=reject; rua=dmarc@example.com,reports@example.com", false},
		{"space-list.example", "v=DMARC1; p=reject; rua=mailto:a@example.com mailto:b@example.com", false},
		{"space-colon.example", "v=DMARC1; p=reject; rua=mailto: dmarc@example.com", false},
	}
	txt := map[string][]string{}
	var domains []string
	for _, c := range cases {
		txt["_dmarc."+c.domain] = []string{c.record}
		domains = append(domains, c.domain)
	}
	p := collectZone(t, zoneResolver{txt: txt}, domains...)
	for i, c := range cases {
		if hr := p.Domains[i].Assessment.HasReporting; hr == nil || *hr != c.reporting {
			t.Errorf("has_reporting for %q = %s, want %v", c.record, show(hr), c.reporting)
		}
	}
	if got := p.Summary.WithReportingPct; got == nil || *got != 28 {
		t.Errorf("summary.with_reporting_pct = %s, want 28", show(got))
	}
}

func TestCollectLooksUpAUnicodeDomainByItsALabel(t *testing.T) {
	res := zoneResolver{
		txt: map[string][]string{
			"xn--bcher-kva.example":        {"v=spf1 -all"},
			"_dmarc.xn--bcher-kva.example": {"v=DMARC1; p=reject; rua=mailto:dmarc@example.net"},
		},
		mx: map[string][]*net.MX{"xn--bcher-kva.example": {{Host: "mx.example.net.", Pref: 10}}},
	}
	p := collectZone(t, res, "bücher.example")
	d := p.Domains[0]
	if d.Domain != "bücher.example" {
		t.Errorf("domain = %q, want it as configured", d.Domain)
	}
	if len(d.MX) != 1 || d.SPF.Record == nil || d.DMARC.Record == nil {
		t.Errorf("mx = %v, spf = %s, dmarc = %s, want the records at xn--bcher-kva.example", d.MX, show(d.SPF.Record), show(d.DMARC.Record))
	}
	if e := d.Assessment.Enforced; e == nil || !*e {
		t.Errorf("enforced = %s, want true", show(e))
	}
}

func TestCollectListsADKIMRecordWithSpacesAroundEquals(t *testing.T) {
	const record = "v=DKIM1; k=rsa; p = MIGfMA0GCSqGSIb3DQEBAQUAA4GN"
	res := zoneResolver{txt: map[string][]string{"google._domainkey.spaced.example": {record}}}
	p := collectZone(t, res, "spaced.example")
	want := []DKIMRecord{{Selector: "google", Record: record, Valid: true}}
	if got := p.Domains[0].DKIM; !reflect.DeepEqual(got, want) {
		t.Errorf("dkim = %+v, want %+v", got, want)
	}
	if got := p.Summary.WithDkimCount; got == nil || *got != 1 {
		t.Errorf("summary.with_dkim_count = %s, want 1", show(got))
	}
}

func TestCollectListsADKIMRecordWithARepeatedTagAsInvalid(t *testing.T) {
	const repeated = "v=DKIM1; k=rsa; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN"
	res := zoneResolver{txt: map[string][]string{
		"google._domainkey.repeated.example":  {repeated},
		"default._domainkey.repeated.example": {"v=dkim1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN"},
	}}
	p := collectZone(t, res, "repeated.example")
	// A version other than DKIM1 leaves the default selector with no key
	// record.
	want := []DKIMRecord{{Selector: "google", Record: repeated, Valid: false}}
	if got := p.Domains[0].DKIM; !reflect.DeepEqual(got, want) {
		t.Errorf("dkim = %+v, want %+v", got, want)
	}
	if issues := p.Domains[0].Assessment.Issues; !slices.Contains(issues, "No valid DKIM records (all keys are malformed or revoked)") {
		t.Errorf("issues = %v, want the one for no valid DKIM key", issues)
	}
}
