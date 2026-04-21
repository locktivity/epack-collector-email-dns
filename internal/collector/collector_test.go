package collector

import (
	"testing"
)

func TestParseDMARC(t *testing.T) {
	tests := []struct {
		name     string
		record   string
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
		{"v=DMARC1", false},                       // no policy
		{"p=reject", false},                        // no version
		{"not a dmarc record", false},
		{"v=DMARC1; sp=reject", false},            // sp= without p= is invalid
		{"v=DMARC1; rua=mailto:x@y.com", false},   // rua without p= is invalid
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
		{"v=DKIM1; p=;", false},   // empty key
		{"v=DKIM1; p= ", false},   // whitespace key
		{"v=DKIM1; k=rsa", false}, // no key
		{"sp=foo", false},                    // not a DKIM record (would match old p= substring check)
		{"v=DKIM10; p=key", false},           // wrong version number
		{"k=rsa; v=DKIM1; p=key", false},     // v= must be first when present per RFC 6376
		{"p=key; v=DKIM1", false},            // v= not first
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
	tests := []struct {
		name         string
		result       DomainResult
		wantEnforced bool
		wantReporting bool
		wantIssues   int
	}{
		{
			name: "fully compliant",
			result: DomainResult{
				SPF: &SPFRecord{Valid: true},
				DMARC: &DMARCRecord{
					Policy:          "reject",
					SubdomainPolicy: "reject",
					Pct:             100,
					RUA:             "mailto:dmarc@example.com",
					Valid:           true,
				},
				DKIM: []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  true,
			wantReporting: true,
			wantIssues:    0,
		},
		{
			name: "no records",
			result: DomainResult{},
			wantEnforced:  false,
			wantReporting: false,
			wantIssues:    3, // no SPF, no DMARC, no DKIM
		},
		{
			name: "monitoring only",
			result: DomainResult{
				SPF: &SPFRecord{Valid: true},
				DMARC: &DMARCRecord{
					Policy:          "none",
					SubdomainPolicy: "none",
					Pct:             100,
					Valid:           true,
				},
				DKIM: []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  false,
			wantReporting: false,
			wantIssues:    3, // policy none, no reporting, subdomain not reject
		},
		{
			name: "enforced with invalid sp",
			result: DomainResult{
				SPF: &SPFRecord{Valid: true},
				DMARC: &DMARCRecord{
					Record:          "v=DMARC1; p=reject; sp=bogus; rua=mailto:x@example.com",
					Policy:          "reject",
					SubdomainPolicy: "reject", // falls back to p= when sp= is invalid
					Pct:             100,
					RUA:             "mailto:x@example.com",
					Valid:           true,
				},
				DKIM: []DKIMRecord{{Valid: true}},
			},
			wantEnforced:  true,
			wantReporting: true,
			wantIssues:    1, // invalid sp= reported as issue
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeAssessment(&tt.result)
			if got.Enforced != tt.wantEnforced {
				t.Errorf("Enforced = %v, want %v", got.Enforced, tt.wantEnforced)
			}
			if got.HasReporting != tt.wantReporting {
				t.Errorf("HasReporting = %v, want %v", got.HasReporting, tt.wantReporting)
			}
			if len(got.Issues) != tt.wantIssues {
				t.Errorf("len(Issues) = %d, want %d; issues: %v", len(got.Issues), tt.wantIssues, got.Issues)
			}
		})
	}
}

func TestComputeSummary(t *testing.T) {
	domains := []DomainResult{
		{
			MX:   []MXRecord{{Host: "mail.example.com"}},
			SPF:  &SPFRecord{Valid: true},
			DMARC: &DMARCRecord{Policy: "reject", Pct: 100},
			DKIM: []DKIMRecord{{Valid: true}},
			Assessment: Assessment{Enforced: true, HasReporting: true},
		},
		{
			MX:   []MXRecord{},
			SPF:  nil,
			DMARC: nil,
			DKIM: []DKIMRecord{},
			Assessment: Assessment{Enforced: false, HasReporting: false},
		},
	}

	summary := computeSummary(domains)

	if summary.TotalDomains != 2 {
		t.Errorf("TotalDomains = %d, want 2", summary.TotalDomains)
	}
	if summary.WithMX != 1 {
		t.Errorf("WithMX = %d, want 1", summary.WithMX)
	}
	if summary.Enforced != 1 {
		t.Errorf("Enforced = %d, want 1", summary.Enforced)
	}
	if summary.AllEnforced != false {
		t.Errorf("AllEnforced = %v, want false", summary.AllEnforced)
	}
	if summary.EnforcedPct != 50 {
		t.Errorf("EnforcedPct = %d, want 50", summary.EnforcedPct)
	}
}
