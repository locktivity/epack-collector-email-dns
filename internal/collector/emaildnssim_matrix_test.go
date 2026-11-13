package collector

import (
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated matrix varies one domain along the axes below. Each
// one-at-a-time row changes one setting, so a difference it shows belongs to
// that setting and is listed in simMatrixAlone. The pairwise rows put every
// two settings together at least once, and a difference none of a row's
// settings shows alone must be listed in simMatrixTogether.

const (
	simMatrixDomain = "matrix.example.com"
	simMatrixParent = "example.com"
)

// simMatrixKey is a DKIM key the checks take as valid: the sandbox's.
const simMatrixKey = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApowQ5IRn1YbYl89MPh/b5wb5NVR2qW9RO9xhcGDToZiqtUlA2o7vLt7dBE3kFuyEwo1eTgAJpYi4HSJMAbPzGmxau5r/NOnj3PQrKFn/lYZnUzLQa56QiT9nXtec0VDMbRNfRBjg3LAlLvRW47HooATEWajCkcOW3nML2+Cc21PQ+pDjBduZJm6TTIi5SwHuq7xbJYSw5r6D2L89YL+TSDhctf/rHyKcb65DTvner2a1190+O0LDPCZRxtvXBSrOKyqFnwCSct+NXRMEa+XD5TwB+4vLQNHmUeZhn8SHvJE5UZdTDC1dvrDJzE87Y2E46SMCJe6SUuIIq5GEZgeF9wIDAQAB"

// simMatrixBase is one domain that enforces everything: a mail server, an
// SPF record that fails other senders, a DMARC policy of reject with
// aggregate reports, and a valid key at a common DKIM selector. Its parent
// domain has no DMARC record until the DMARC axis gives it one.
func simMatrixBase(t testing.TB) *roster.Roster {
	t.Helper()
	r := simBase(t)
	r.MailDomains = &roster.MailDomains{
		Domains: []string{simMatrixDomain},
		Names: map[string]roster.MailRecords{
			simMatrixDomain: {
				MX:  []roster.MailExchanger{{Host: "mx1." + simMatrixDomain, Priority: 10}},
				TXT: []string{"v=spf1 mx -all"},
			},
			"_dmarc." + simMatrixDomain:        {TXT: []string{"v=DMARC1; p=reject; rua=mailto:dmarc@" + simMatrixDomain}},
			"s1._domainkey." + simMatrixDomain: {TXT: []string{simMatrixKey}},
		},
	}
	r.Terms.DKIMSelectors = map[string]string{"s1": roster.DKIMSelectorCommon, "selector1": roster.DKIMSelectorCommon, "custom": roster.DKIMSelectorOther}
	return r
}

// setRecords sets the records of one type at a name, and drops the name
// when it then has none.
func setRecords(name string, mx []roster.MailExchanger, txt ...string) func(*roster.Roster) {
	return func(r *roster.Roster) {
		records := r.MailDomains.Names[name]
		if mx != nil {
			records.MX = mx
		}
		if txt != nil {
			records.TXT = txt
		}
		if len(records.MX) == 0 && len(records.TXT) == 0 {
			delete(r.MailDomains.Names, name)
			return
		}
		r.MailDomains.Names[name] = records
	}
}

func setMX(mx ...roster.MailExchanger) func(*roster.Roster) {
	if mx == nil {
		mx = []roster.MailExchanger{}
	}
	return setRecords(simMatrixDomain, mx)
}

func setSPF(txt ...string) func(*roster.Roster) {
	if txt == nil {
		txt = []string{}
	}
	return setRecords(simMatrixDomain, nil, txt...)
}

func setTXT(name string, txt ...string) func(*roster.Roster) {
	if txt == nil {
		txt = []string{}
	}
	return setRecords(name, nil, txt...)
}

func both(changes ...func(*roster.Roster)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		for _, change := range changes {
			change(r)
		}
	}
}

var (
	simDMARC  = "_dmarc." + simMatrixDomain
	simParent = "_dmarc." + simMatrixParent
	simDKIM   = func(selector string) string { return selector + "._domainkey." + simMatrixDomain }
)

func simMatrixAxes() []roster.Axis {
	elevenIncludes := "v=spf1" + strings.Repeat(" include:spf.example.net", 11) + " -all"
	return []roster.Axis{
		{Name: "mx", Values: []roster.Value{
			{Name: "one"},
			{Name: "none", Change: setMX()},
			{Name: "two", Change: setMX(roster.MailExchanger{Host: "mx2." + simMatrixDomain, Priority: 20}, roster.MailExchanger{Host: "mx1." + simMatrixDomain, Priority: 10})},
		}},
		{Name: "spf", Values: []roster.Value{
			{Name: "fail"},
			{Name: "none", Change: setSPF()},
			{Name: "softfail", Change: setSPF("v=spf1 mx ~all")},
			{Name: "neutral", Change: setSPF("v=spf1 ?all")},
			{Name: "pass_all", Change: setSPF("v=spf1 +all")},
			{Name: "two", Change: setSPF("v=spf1 mx -all", "v=spf1 include:spf.example.net -all")},
			{Name: "too_many_lookups", Change: setSPF(elevenIncludes)},
			{Name: "malformed", Change: setSPF("v=spf1 ipv4:192.0.2.10 -all")},
			{Name: "upper_case", Change: setSPF("V=SPF1 MX -ALL")},
			{Name: "verification_only", Change: setSPF("google-site-verification=matrix")},
		}},
		{Name: "dmarc", Values: []roster.Value{
			{Name: "reject"},
			{Name: "none", Change: setTXT(simDMARC)},
			{Name: "quarantine_half", Change: setTXT(simDMARC, "v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@"+simMatrixDomain)},
			{Name: "monitor", Change: setTXT(simDMARC, "v=DMARC1; p=none")},
			{Name: "subdomains_none", Change: setTXT(simDMARC, "v=DMARC1; p=reject; sp=none")},
			{Name: "testing", Change: setTXT(simDMARC, "v=DMARC1; p=reject; t=y; rua=mailto:dmarc@"+simMatrixDomain)},
			{Name: "misspelled", Change: setTXT(simDMARC, "v=DMARC1; p=quarentine")},
			{Name: "two", Change: setTXT(simDMARC, "v=DMARC1; p=reject", "v=DMARC1; p=none")},
			{Name: "parent_only", Change: both(setTXT(simDMARC), setTXT(simParent, "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@"+simMatrixParent))},
			{Name: "parent_reject", Change: both(setTXT(simDMARC), setTXT(simParent, "v=DMARC1; p=quarantine; sp=reject"))},
		}},
		{Name: "dkim", Values: []roster.Value{
			{Name: "valid"},
			{Name: "none", Change: setTXT(simDKIM("s1"))},
			{Name: "revoked", Change: setTXT(simDKIM("s1"), "v=DKIM1; p=")},
			{Name: "custom_only", Change: both(setTXT(simDKIM("s1")), setTXT(simDKIM("custom"), simMatrixKey))},
			{Name: "two_at_one", Change: setTXT(simDKIM("s1"), simMatrixKey, simMatrixKey)},
			{Name: "second_selector", Change: setTXT(simDKIM("selector1"), simMatrixKey)},
			{Name: "garbled", Change: setTXT(simDKIM("s1"), "v=DKIM1; k=rsa; p=notbase64!")},
		}},
	}
}

// simMatrixAlone lists, by axis=value, the differences a setting shows on
// its own.
var simMatrixAlone = map[string]simulate.Differences{
	"mx=two": simulate.Same(simulate.Unmodeled,
		"Derive lists MX records in the roster's order. A resolver answers them by preference, and collectMX lists them by priority.",
		"/domains/0/mx/0/host", "/domains/0/mx/0/priority", "/domains/0/mx/1/host", "/domains/0/mx/1/priority"),
}

func TestSimulatedMatrix(t *testing.T) {
	simHarness(simStanding).Matrix(t, simMatrixBase(t), simMatrixAxes(), simMatrixAlone, nil)
}
