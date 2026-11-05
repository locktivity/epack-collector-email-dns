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

// kitAudit is the config of the scenarios that pin call counts, or each
// gap's call number and unmeasured count. The collector result has these
// only at the audit level and above.
var kitAudit = map[string]any{"level": "audit"}

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
				Name:   "no records",
				DNS:    kitNoRecords(),
				Config: kitAudit,
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
							kitOperation("dns.dkim.lookup", 36, map[string]any{"NXDOMAIN": 36}),
							kitOperation("dns.dmarc.lookup", 8, map[string]any{"NOERROR": 1, "NXDOMAIN": 7}),
							kitOperation("dns.mx.lookup", 4, map[string]any{"NXDOMAIN": 4}),
							kitOperation("dns.spf.lookup", 4, map[string]any{"NOERROR": 1, "NXDOMAIN": 3}),
						},
					},
				},
			},
			{
				Name:   "SERVFAIL answers",
				DNS:    kitFailedLookups(),
				Config: kitAudit,
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
								kitGap("/domains/0/assessment/enforced", "not_collected", 0, "dns.dmarc.lookup", 9),
								kitGap("/domains/0/assessment/has_reporting", "not_collected", 0, "dns.dmarc.lookup", 9),
								kitGap("/domains/0/assessment/issues", "not_collected", 0, "dns.spf.lookup", 5),
								kitGap("/domains/0/dmarc", "not_collected", 0, "dns.dmarc.lookup", 9),
								kitGap("/domains/0/spf", "not_collected", 0, "dns.spf.lookup", 5),
								kitGap("/domains/2/assessment/issues", "not_collected", 0, "dns.dkim.lookup", 36),
								kitGap("/domains/2/dkim", "partial", 1, "dns.dkim.lookup", 36),
								kitGap("/summary/all_enforced", "partial", 1, "dns.dmarc.lookup", 9),
							},
							kitShareGaps("enforced", 1, "dns.dmarc.lookup", 9),
							kitShareGaps("with_all_three", 1, "dns.spf.lookup", 5),
							kitShareGaps("with_dkim", 1, "dns.dkim.lookup", 36),
							kitShareGaps("with_dmarc", 1, "dns.dmarc.lookup", 9),
							kitShareGaps("with_reporting", 1, "dns.dmarc.lookup", 9),
							kitShareGaps("with_spf", 1, "dns.spf.lookup", 5),
						)...),
					),
				},
			},
			{
				Name:   "DKIM selector SERVFAIL",
				DNS:    kitFailedSelectors(),
				Config: kitAudit,
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
							kitGap("/domains/0/dkim", "partial", 1, "dns.dkim.lookup", 14),
							kitGap("/domains/1/assessment/issues", "not_collected", 0, "dns.dkim.lookup", 29),
							kitGap("/domains/1/dkim", "partial", 1, "dns.dkim.lookup", 29),
						),
					),
				},
			},
		}, kitRecordings(t, "email-dns")...),
		Ignore:        kitIgnore(),
		Operations:    []string{"dns.mx.lookup", "dns.spf.lookup", "dns.dmarc.lookup", "dns.dkim.lookup"},
		GapOperations: true,
	})
}

// kitOperation is an operation's entry in the result of a run at the audit
// level, for an operation with no retries. statuses holds its call counts by
// DNS rcode.
func kitOperation(name string, calls int, statuses map[string]any) map[string]any {
	codes := slices.Sorted(maps.Keys(statuses))
	return map[string]any{
		"name": name, "calls": calls, "attempts": calls, "retries": 0, "statuses": statuses,
		"retried": false, "status_codes": codes,
	}
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
