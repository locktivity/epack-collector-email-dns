package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

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
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			if got := validateSPF(tt.record); got != tt.valid {
				t.Errorf("validateSPF(%q) = %v, want %v", tt.record, got, tt.valid)
			}
		})
	}
}

func TestValidateDMARC(t *testing.T) {
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
		{"v=DMARC1; sp=reject", false},               // sp= without p= is invalid
		{"v=DMARC1; rua=mailto:x@y.com", false},      // rua without p= is invalid
		{"v=DMARC1; p=bogus", false},                 // invalid policy value
		{"v=DMARC1; p=REJECT", true},                 // uppercase should work (case insensitive)
		{"v=DMARC1; p=invalid; rua=mailto:x", false}, // invalid policy with other valid tags
		{"v=DMARC10; p=reject", false},               // wrong version number
		{"v=dmarc1x; p=reject", false},               // version with extra chars
		{"p=reject; v=DMARC1", false},                // v= must be first tag per RFC 7489
		{"rua=mailto:x; v=DMARC1; p=reject", false},  // v= not first
		{"v=DMARC1; rua=mailto:x; p=reject", true},   // p= can appear after other tags (only v= must be first)
		{"v=DMARC1; p=reject; sp=bogus", true},       // invalid sp= is ignored per receiver behavior (record still valid)
		{"v=DMARC1; p=reject; sp=invalid", true},     // invalid sp= is ignored per receiver behavior (record still valid)
		{"v=DMARC1; p=reject; sp=none", true},        // valid sp= value
		{"v=DMARC1; p=reject; sp=quarantine", true},  // valid sp= value
		{"v=DMARC1; p=reject; sp=reject", true},      // valid sp= value
		{"v = DMARC1; p = reject", true},             // whitespace around = per RFC 7489 ABNF
		{"v= DMARC1; p= reject", true},               // whitespace after = only
		{"v =DMARC1; p =reject", true},               // whitespace before = only
		{"v=DMARC1;p=reject", true},                  // no whitespace around tags
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			if got := validateDMARC(tt.record); got != tt.valid {
				t.Errorf("validateDMARC(%q) = %v, want %v", tt.record, got, tt.valid)
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
	enforcing := func() Lookup[DMARCRecord] {
		return read(&DMARCRecord{
			Policy:          "reject",
			SubdomainPolicy: "reject",
			Pct:             100,
			RUA:             "mailto:dmarc@example.com",
			Valid:           true,
		})
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
				SPF: read(&SPFRecord{Valid: true}),
				DMARC: read(&DMARCRecord{
					Policy:          "none",
					SubdomainPolicy: "none",
					Pct:             100,
					Valid:           true,
				}),
				DKIM: []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(false),
			wantReporting: new(false),
			wantIssues:    new(3), // policy none, no reporting, subdomain not reject
		},
		{
			name: "enforced with invalid sp",
			result: DomainResult{
				SPF: read(&SPFRecord{Valid: true}),
				DMARC: read(&DMARCRecord{
					Record:          "v=DMARC1; p=reject; sp=bogus; rua=mailto:x@example.com",
					Policy:          "reject",
					SubdomainPolicy: "reject", // falls back to p= when sp= is invalid
					Pct:             100,
					RUA:             "mailto:x@example.com",
					Valid:           true,
				}),
				DKIM: []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  new(true),
			wantReporting: new(true),
			wantIssues:    new(1), // invalid sp= reported as issue
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
