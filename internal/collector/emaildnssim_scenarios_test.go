package collector

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated domains are rosters the simulator answers for, each with
// the values roster.Derive computes from it. A value the collector reports
// otherwise is listed with a verdict and a note that says where in the
// collector's code it was checked, so a new difference fails, and so does a
// listed one that goes away.

// simStanding are the differences every roster shows.
var simStanding = simulate.Differences{}

// simUncompared are the fields the collector writes that no scenario's
// roster gives a value for.
var simUncompared = map[string]string{}

func simScenarios(t testing.TB) []simulate.Scenario {
	return []simulate.Scenario{
		{Name: "sandbox", Roster: simBase(t)},
		{Name: "matrix base", Roster: simMatrixBase(t)},
	}
}

func TestSimulatedDomains(t *testing.T) {
	simHarness(simStanding).Tenants(t, simScenarios(t))
}

// TestSimulatedDomainsKit runs the scenarios through the kit, which answers
// the roster's records from its own DNS server, so the simulator's resolver
// can't drift from it, and checks each run the way TestCollectorKit does.
func TestSimulatedDomainsKit(t *testing.T) {
	h := simHarness(simStanding)
	var scenarios []collectortest.Scenario
	most := 0
	for _, sc := range simScenarios(t) {
		scenarios = append(scenarios, collectortest.Scenario{
			Name:   sc.Name,
			DNS:    simRecords(sc.Roster),
			Config: simConfig(sc.Roster),
			Expect: h.Expect(t, sc),
		})
		most = max(most, len(sc.Roster.MailDomains.Domains))
	}
	collectortest.Run(t, collectortest.Suite{
		Name:          "email-dns-simulated",
		Spec:          Spec("test", "collectortest"),
		Run:           Run,
		Clock:         simClock,
		Scenarios:     scenarios,
		Ignore:        simIgnore(most),
		Operations:    []string{"dns.mx.lookup", "dns.spf.lookup", "dns.dmarc.lookup", "dns.dkim.lookup"},
		GapOperations: true,
	})
}

// simIgnore keeps the lookup errors of up to n domains out of the value
// comparison, as kitIgnore does for the kit's domains.
func simIgnore(n int) map[string][]string {
	prefixes := []string{"/diagnostics"}
	for i := range n {
		prefixes = append(prefixes, fmt.Sprintf("/domains/%d/errors", i))
	}
	return map[string][]string{ArtifactPath: prefixes}
}

// simContractKnown lists the ways the sandbox roster's records are known to
// differ from the recording, by name and type, with why.
var simContractKnown = map[string]string{
	"TXT _dmarc.enforced.email.example.com: values differ":        "Record replaces the aggregate report address with a fake one.",
	"TXT s1._domainkey.enforced.email.example.com: values differ": "Record scrubs the key as a token, and the roster's key stands in for the one Terraform generates, which stays in its state.",
}

// TestSimulatorMatchesRecording compares the records the simulator answers
// for the sandbox roster with a recording of the sandbox, so the roster
// can't drift from the sandbox's DNS unseen: an answer the recording holds
// that the simulator gives otherwise fails here, in the pull request that
// brings a new recording or roster. A record at a name the recording never
// looked up can't be checked.
func TestSimulatorMatchesRecording(t *testing.T) {
	recorded := kitRecordings(t, "email-dns")[0]
	type key struct{ name, rtype string }
	simulated := map[key][]string{}
	for _, rec := range simRecords(simBase(t)) {
		simulated[key{simName(rec.Name), rec.Type}] = rec.Values
	}
	var diffs []string
	for _, rec := range recorded.DNS {
		k := key{simName(rec.Name), rec.Type}
		values, ok := simulated[k]
		switch {
		case rec.Rcode != "" && rec.Rcode != "NOERROR":
			if ok {
				diffs = append(diffs, fmt.Sprintf("%s %s: recorded %s, simulated %d records", k.rtype, k.name, rec.Rcode, len(values)))
			}
		case !ok:
			diffs = append(diffs, fmt.Sprintf("%s %s: recorded %d records, simulated none", k.rtype, k.name, len(rec.Values)))
		case !slices.Equal(simSorted(rec.Values, k.rtype), simSorted(values, k.rtype)):
			diffs = append(diffs, fmt.Sprintf("%s %s: values differ", k.rtype, k.name))
		}
	}
	seen := map[string]bool{}
	for _, d := range diffs {
		seen[d] = true
		if why, known := simContractKnown[d]; known {
			t.Logf("known: %s (%s)", d, why)
			continue
		}
		t.Errorf("%s", d)
	}
	for _, d := range slices.Sorted(maps.Keys(simContractKnown)) {
		if !seen[d] {
			t.Errorf("listed as known, but the simulator now matches the recording: %s", d)
		}
	}
}

// simSorted puts a record set in a fixed order. MX hosts compare without
// their trailing dot.
func simSorted(values []string, rtype string) []string {
	out := slices.Clone(values)
	if rtype == "MX" {
		for i, v := range out {
			out[i] = strings.TrimSuffix(v, ".")
		}
	}
	slices.Sort(out)
	return out
}
