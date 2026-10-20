package collector

import (
	"fmt"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitDomains are the domains every kit run scans.
var kitDomains = []string{"example.com", "example.org", "example.net", "parked.example"}

const (
	kitGoogleKey    = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
	kitMicrosoftKey = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
)

// kitRecords are the clean tenant's DNS records: example.com enforces DMARC
// and signs with two selectors, one through a CNAME; example.org quarantines
// and its only DKIM key is revoked; example.net only monitors, publishes two
// SPF records, and has no mail servers; parked.example has none of them.
func kitRecords() []collectortest.DNSRecord {
	return []collectortest.DNSRecord{
		{Name: "example.com", Type: "MX", Values: []string{"20 mx2.example.com.", "10 mx1.example.com."}},
		{Name: "example.com", Type: "TXT", Values: []string{"google-site-verification=kit123", "v=spf1 include:_spf.google.com -all"}},
		{Name: "_dmarc.example.com", Type: "TXT", Values: []string{"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@example.com"}},
		{Name: "selector1._domainkey.example.com", Type: "CNAME", Values: []string{"selector1-example-com._domainkey.example.onmicrosoft.com."}},
		{Name: "selector1-example-com._domainkey.example.onmicrosoft.com", Type: "TXT", Values: []string{kitMicrosoftKey}},
		{Name: "google._domainkey.example.com", Type: "TXT", Values: []string{kitGoogleKey}},

		{Name: "example.org", Type: "MX", Values: []string{"10 aspmx.l.google.com."}},
		{Name: "example.org", Type: "TXT", Values: []string{"v=spf1 include:_spf.google.com ~all"}},
		{Name: "_dmarc.example.org", Type: "TXT", Values: []string{"v=DMARC1; p=quarantine; pct=50; rua=mailto:reports@example.org"}},
		{Name: "s1._domainkey.example.org", Type: "TXT", Values: []string{"v=DKIM1; p="}},

		{Name: "example.net", Type: "TXT", Values: []string{"v=spf1 -all", "v=spf1 include:spf.protection.outlook.com -all"}},
		{Name: "_dmarc.example.net", Type: "TXT", Values: []string{"v=DMARC1; p=none"}},

		{Name: "parked.example", Type: "A", Values: []string{"192.0.2.10"}},
		{Name: "parked.example", Type: "MX", Rcode: "NXDOMAIN"},
		{Name: "_dmarc.parked.example", Type: "TXT", Rcode: "NXDOMAIN"},
	}
}

// kitNoRecords answers every lookup with NXDOMAIN or NODATA: names that do
// not exist, names that hold only other record types, and TXT records that
// hold no SPF or DMARC policy.
func kitNoRecords() []collectortest.DNSRecord {
	return []collectortest.DNSRecord{
		{Name: "example.com", Type: "A", Values: []string{"192.0.2.10"}},
		{Name: "_dmarc.example.com", Type: "TXT", Rcode: "NXDOMAIN"},
		{Name: "example.org", Type: "MX", Rcode: "NXDOMAIN"},
		{Name: "example.org", Type: "TXT", Rcode: "NXDOMAIN"},
		{Name: "example.net", Type: "TXT", Values: []string{"google-site-verification=kit123"}},
		{Name: "_dmarc.example.net", Type: "TXT", Values: []string{"not a dmarc policy"}},
	}
}

// kitFailedLookups is the clean tenant with SERVFAIL answers for
// example.com's SPF and DMARC lookups and for one of example.net's DKIM
// selectors. A record with an Rcode answers its name and type in place of
// the clean records.
func kitFailedLookups() []collectortest.DNSRecord {
	return append([]collectortest.DNSRecord{
		{Name: "example.com", Type: "TXT", Rcode: "SERVFAIL"},
		{Name: "_dmarc.example.com", Type: "TXT", Rcode: "SERVFAIL"},
		{Name: "k1._domainkey.example.net", Type: "TXT", Rcode: "SERVFAIL"},
	}, kitRecords()...)
}

// kitFailedSelectors is the clean tenant with a SERVFAIL answer for one DKIM
// selector at example.com, which has valid keys at two others, and one at
// example.org, whose only key is revoked.
func kitFailedSelectors() []collectortest.DNSRecord {
	return append([]collectortest.DNSRecord{
		{Name: "default._domainkey.example.com", Type: "TXT", Rcode: "SERVFAIL"},
		{Name: "s2._domainkey.example.org", Type: "TXT", Rcode: "SERVFAIL"},
	}, kitRecords()...)
}

// kitSteps are a run's steps in order, with their titles.
var kitSteps = [][2]string{
	{"mail_servers", "Mail servers"},
	{"spf", "SPF records"},
	{"dmarc", "DMARC policies"},
	{"dkim", "DKIM keys at common selectors"},
}

// kitStepPins pins the four steps in order, and that there are no more.
func kitStepPins() map[string]any {
	pins := map[string]any{}
	for i, s := range kitSteps {
		pins[fmt.Sprintf("/steps/%d/name", i)] = s[0]
		pins[fmt.Sprintf("/steps/%d/title", i)] = s[1]
	}
	pins[fmt.Sprintf("/steps/%d", len(kitSteps))] = collectortest.Absent
	return pins
}

// kitGapPins pins each gap's fields in order, and that there are no more. A
// gap's source is left unpinned, since it names a line of the collector.
func kitGapPins(gaps ...map[string]any) map[string]any {
	pins := map[string]any{}
	for i, g := range gaps {
		for key, value := range g {
			pins[fmt.Sprintf("/gaps/%d/%s", i, key)] = value
		}
	}
	pins[fmt.Sprintf("/gaps/%d", len(gaps))] = collectortest.Absent
	return pins
}

// kitShareGaps are the gaps a SERVFAIL leaves at a summary count and its
// percentage.
func kitShareGaps(name string, unmeasured int) []map[string]any {
	return []map[string]any{
		kitGap("/summary/"+name+"_count", "partial", unmeasured),
		kitGap("/summary/"+name+"_pct", "partial", unmeasured),
	}
}

// kitGap is the gap a SERVFAIL leaves at pointer in the posture artifact.
func kitGap(pointer, status string, unmeasured int) map[string]any {
	g := map[string]any{
		"schema":  "evidencepack/email-dns@v1",
		"path":    ArtifactPath,
		"pointer": pointer,
		"status":  status,
		"code":    "vendor_error",
		"owner":   "vendor",
	}
	if unmeasured > 0 {
		g["unmeasured"] = unmeasured
	}
	return g
}
