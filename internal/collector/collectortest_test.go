package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

const kitResultPath = "artifacts/email-dns.collector-result.json"

const noDKIMIssue = "No DKIM records found for common selectors (custom selectors not checked)"

// kitIgnore keeps the lookup errors readers parse out of the value
// comparison: a failed lookup adds one by design.
func kitIgnore() map[string][]string {
	prefixes := []string{"/diagnostics"}
	for i := range kitDomains {
		prefixes = append(prefixes, fmt.Sprintf("/domains/%d/errors", i))
	}
	return map[string][]string{ArtifactPath: prefixes}
}

func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:   Spec("test", "collectortest"),
		Run:    Run,
		Config: map[string]any{"domains": kitDomains},
		Scenarios: append([]collectortest.Scenario{
			{
				Name: "clean",
				DNS:  kitRecords(),
				Expect: map[string]map[string]any{
					ArtifactPath: {
						"/collected_at": "2026-01-01T00:00:00Z",
						"/domains/0/mx": []any{
							map[string]any{"host": "mx1.example.com", "priority": 10},
							map[string]any{"host": "mx2.example.com", "priority": 20},
						},
						"/domains/0/spf/valid":    true,
						"/domains/0/dmarc/policy": "reject",
						"/domains/0/dkim": []any{
							map[string]any{"selector": "selector1", "record": kitMicrosoftKey, "valid": true},
							map[string]any{"selector": "google", "record": kitGoogleKey, "valid": true},
						},
						"/domains/0/assessment": map[string]any{"enforced": true, "has_reporting": true, "issues": []any{}},
						"/domains/1/dmarc": map[string]any{
							"record":           "v=DMARC1; p=quarantine; pct=50; rua=mailto:reports@example.org",
							"policy":           "quarantine",
							"subdomain_policy": "quarantine",
							"pct":              50,
							"rua":              "mailto:reports@example.org",
							"valid":            true,
						},
						"/domains/1/dkim": []any{map[string]any{"selector": "s1", "record": "v=DKIM1; p=", "valid": false}},
						"/domains/1/assessment": map[string]any{"enforced": false, "has_reporting": true, "issues": []any{
							"DMARC policy is 'quarantine' (not reject)",
							"Subdomain policy is not 'reject'",
							"No valid DKIM records (all keys are malformed or revoked)",
						}},
						"/domains/2/mx":           []any{},
						"/domains/2/spf":          map[string]any{"record": "v=spf1 -all", "valid": false},
						"/domains/2/dmarc/policy": "none",
						"/domains/2/dkim":         []any{},
						"/domains/2/assessment/issues": []any{
							"Invalid SPF record",
							"DMARC policy is 'none' (monitoring only)",
							"No DMARC aggregate reporting (rua) configured",
							"Subdomain policy is not 'reject'",
							noDKIMIssue,
						},
						"/domains/3": map[string]any{
							"domain": "parked.example",
							"mx":     []any{},
							"spf":    nil,
							"dmarc":  nil,
							"dkim":   []any{},
							"assessment": map[string]any{"enforced": false, "has_reporting": false, "issues": []any{
								"No SPF record", "No DMARC record", noDKIMIssue,
							}},
						},
						"/summary": map[string]any{
							"total_domains":        4,
							"with_mx_count":        2,
							"with_mx_pct":          50,
							"with_spf_count":       3,
							"with_spf_pct":         75,
							"with_dmarc_count":     3,
							"with_dmarc_pct":       75,
							"with_dkim_count":      2,
							"with_dkim_pct":        50,
							"with_all_three_count": 2,
							"with_all_three_pct":   50,
							"enforced_count":       1,
							"enforced_pct":         25,
							"with_reporting_count": 2,
							"with_reporting_pct":   50,
							"all_enforced":         false,
						},
					},
					kitResultPath: merged(
						map[string]any{"/outcome": map[string]any{"status": "collected"}, "/gaps": []any{}},
						kitStepPins(),
					),
				},
			},
			{
				Name: "no records",
				DNS:  kitNoRecords(),
				Expect: map[string]map[string]any{
					ArtifactPath: {
						"/domains/2": map[string]any{
							"domain": "example.net",
							"mx":     []any{},
							"spf":    nil,
							"dmarc":  nil,
							"dkim":   []any{},
							"assessment": map[string]any{"enforced": false, "has_reporting": false, "issues": []any{
								"No SPF record", "No DMARC record", noDKIMIssue,
							}},
						},
						"/summary": map[string]any{
							"total_domains":        4,
							"with_mx_count":        0,
							"with_mx_pct":          0,
							"with_spf_count":       0,
							"with_spf_pct":         0,
							"with_dmarc_count":     0,
							"with_dmarc_pct":       0,
							"with_dkim_count":      0,
							"with_dkim_pct":        0,
							"with_all_three_count": 0,
							"with_all_three_pct":   0,
							"enforced_count":       0,
							"enforced_pct":         0,
							"with_reporting_count": 0,
							"with_reporting_pct":   0,
							"all_enforced":         false,
						},
					},
					kitResultPath: {
						"/outcome": map[string]any{"status": "collected"},
						"/gaps":    []any{},
						"/calls/operations": []any{
							map[string]any{"name": "dns.dkim.lookup", "calls": 36, "attempts": 36, "retries": 0, "statuses": map[string]any{"NXDOMAIN": 36}},
							map[string]any{"name": "dns.dmarc.lookup", "calls": 4, "attempts": 4, "retries": 0, "statuses": map[string]any{"NOERROR": 1, "NXDOMAIN": 3}},
							map[string]any{"name": "dns.mx.lookup", "calls": 4, "attempts": 4, "retries": 0, "statuses": map[string]any{"NXDOMAIN": 4}},
							map[string]any{"name": "dns.spf.lookup", "calls": 4, "attempts": 4, "retries": 0, "statuses": map[string]any{"NOERROR": 1, "NXDOMAIN": 3}},
						},
					},
				},
			},
			{
				Name: "SERVFAIL answers",
				DNS:  kitFailedLookups(),
				Expect: map[string]map[string]any{
					ArtifactPath: {
						"/domains/0/mx": []any{
							map[string]any{"host": "mx1.example.com", "priority": 10},
							map[string]any{"host": "mx2.example.com", "priority": 20},
						},
						"/domains/0/spf":        nil,
						"/domains/0/dmarc":      nil,
						"/domains/0/assessment": map[string]any{},
						"/domains/0/dkim/1":     map[string]any{"selector": "google", "record": kitGoogleKey, "valid": true},
						"/domains/2/dkim":       []any{},
						"/domains/2/assessment": map[string]any{"enforced": false, "has_reporting": false},
						"/summary":              map[string]any{"total_domains": 4, "with_mx_count": 2, "with_mx_pct": 50},
					},
					kitResultPath: merged(
						map[string]any{"/outcome": map[string]any{"status": "partial", "code": "vendor_error", "owner": "vendor"}},
						kitGapPins(slices.Concat(
							[]map[string]any{
								kitGap("/domains/0/assessment/enforced", "not_collected", 0),
								kitGap("/domains/0/assessment/has_reporting", "not_collected", 0),
								kitGap("/domains/0/assessment/issues", "not_collected", 0),
								kitGap("/domains/0/dmarc", "not_collected", 0),
								kitGap("/domains/0/spf", "not_collected", 0),
								kitGap("/domains/2/assessment/issues", "not_collected", 0),
								kitGap("/domains/2/dkim", "partial", 1),
								kitGap("/summary/all_enforced", "partial", 1),
							},
							kitShareGaps("enforced", 1),
							kitShareGaps("with_all_three", 1),
							kitShareGaps("with_dkim", 1),
							kitShareGaps("with_dmarc", 1),
							kitShareGaps("with_reporting", 1),
							kitShareGaps("with_spf", 1),
						)...),
					),
				},
			},
			{
				Name: "DKIM selector SERVFAIL",
				DNS:  kitFailedSelectors(),
				Expect: map[string]map[string]any{
					ArtifactPath: {
						"/domains/0/dkim": []any{
							map[string]any{"selector": "selector1", "record": kitMicrosoftKey, "valid": true},
							map[string]any{"selector": "google", "record": kitGoogleKey, "valid": true},
						},
						"/domains/0/assessment":    map[string]any{"enforced": true, "has_reporting": true, "issues": []any{}},
						"/domains/1/dkim":          []any{map[string]any{"selector": "s1", "record": "v=DKIM1; p=", "valid": false}},
						"/domains/1/assessment":    map[string]any{"enforced": false, "has_reporting": true},
						"/summary/with_dkim_count": 2,
						"/summary/with_dkim_pct":   50,
					},
					kitResultPath: merged(
						map[string]any{"/outcome": map[string]any{"status": "partial", "code": "vendor_error", "owner": "vendor"}},
						kitGapPins(
							kitGap("/domains/0/dkim", "partial", 1),
							kitGap("/domains/1/assessment/issues", "not_collected", 0),
							kitGap("/domains/1/dkim", "partial", 1),
						),
					),
				},
			},
		}, kitRecordings(t, "email-dns")...),
		Ignore:     kitIgnore(),
		Operations: []string{"dns.mx.lookup", "dns.spf.lookup", "dns.dmarc.lookup", "dns.dkim.lookup"},
	})
}

// merged returns the pins of each map in one.
func merged(pins ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, p := range pins {
		maps.Copy(out, p)
	}
	return out
}

// kitRecordings loads the scenarios TestRecord in record_test.go records
// from sandboxes, and logs each one not recorded yet.
func kitRecordings(t *testing.T, names ...string) []collectortest.Scenario {
	t.Helper()
	var out []collectortest.Scenario
	for _, name := range names {
		path := filepath.Join("testdata", "recordings", name+".json")
		sc, err := collectortest.LoadScenario(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			t.Logf("no recording at %s yet", path)
		case err != nil:
			t.Fatal(err)
		default:
			out = append(out, sc)
		}
	}
	return out
}
