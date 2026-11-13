package collector

import (
	"context"
	"encoding/json"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// simRosterPath is the email-dns sandbox's roster in v1 form, which
// cmd/derive in epack-collector-sandboxes converts from
// sandboxes/email-dns/roster.json and the refresh workflow commits here.
const simRosterPath = "testdata/simulator/email-dns.roster.json"

// simClock is the time of every simulated run.
var simClock = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func simBase(t testing.TB) *roster.Roster {
	t.Helper()
	r, err := roster.Load(simRosterPath)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// simConfig checks a roster's domains at the audit level, as the sandbox
// does.
func simConfig(r *roster.Roster) map[string]any {
	return map[string]any{
		"level":   "audit",
		"domains": simulate.Each(r.MailDomains.Domains, func(d string) any { return d }),
	}
}

// simRecords are the DNS records a roster's email_dns block says the
// internet holds: each listed name's MX and TXT records. A name the roster
// doesn't list holds none.
func simRecords(r *roster.Roster) []collectortest.DNSRecord {
	var out []collectortest.DNSRecord
	for _, name := range slices.Sorted(maps.Keys(r.MailDomains.Names)) {
		records := r.MailDomains.Names[name]
		if len(records.MX) > 0 {
			var values []string
			for _, mx := range records.MX {
				values = append(values, strconv.Itoa(mx.Priority)+" "+simFQDN(mx.Host))
			}
			out = append(out, collectortest.DNSRecord{Name: name, Type: "MX", Values: values})
		}
		if len(records.TXT) > 0 {
			out = append(out, collectortest.DNSRecord{Name: name, Type: "TXT", Values: slices.Clone(records.TXT)})
		}
	}
	return out
}

// simResolver answers lookups from a roster's records as net.Resolver
// does: a name with no record of the type is not found. The collector looks
// up only MX and TXT records, so the other lookups find nothing.
type simResolver struct {
	mx  map[string][]*net.MX
	txt map[string][]string
}

func newSimResolver(r *roster.Roster) simResolver {
	s := simResolver{mx: map[string][]*net.MX{}, txt: map[string][]string{}}
	for name, records := range r.MailDomains.Names {
		for _, mx := range records.MX {
			s.mx[name] = append(s.mx[name], &net.MX{Host: simFQDN(mx.Host), Pref: uint16(mx.Priority)})
		}
		if len(records.TXT) > 0 {
			s.txt[name] = slices.Clone(records.TXT)
		}
	}
	return s
}

func (s simResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txt, ok := s.txt[simName(name)]; ok {
		return slices.Clone(txt), nil
	}
	return nil, simNotFound(name)
}

func (s simResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if mx, ok := s.mx[simName(name)]; ok {
		return slices.Clone(mx), nil
	}
	return nil, simNotFound(name)
}

func (simResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return nil, simNotFound(host)
}

func (simResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return nil, simNotFound(host)
}

func (simResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return "", simNotFound(host)
}

func (simResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	return nil, simNotFound(name)
}

func simName(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func simFQDN(host string) string { return strings.TrimSuffix(host, ".") + "." }

func simNotFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// simHarness runs the collector against the records of the roster
// Simulate last answered for. The collector reads DNS, not HTTP, so
// Simulate answers no requests and Collect gives the run a resolver.
func simHarness(standing simulate.Differences) simulate.Harness {
	var resolver simResolver
	var config map[string]any
	return simulate.Harness{
		Simulate: func(r *roster.Roster, _ int) []collectortest.Response {
			resolver, config = newSimResolver(r), simConfig(r)
			return nil
		},
		Collect: func(t *testing.T, responses []collectortest.Response) componentsdk.InProcessResult {
			res := simulate.InProcess(t, Spec("test", "simulator"), Run, componentsdk.InProcessOptions{
				Config:   config,
				Resolver: resolver,
				Clock:    func() time.Time { return simClock },
			}, responses)
			simDKIMOrder(t, res)
			return res
		},
		Artifacts:  []simulate.Artifact{{Schema: roster.EmailDNS, Path: ArtifactPath}},
		Standing:   standing,
		Coverage:   true,
		Uncompared: simUncompared,
	}
}

// simDKIMOrder lists each domain's DKIM keys by selector, the order Derive
// gives them in. The roster's terms give selectors no order, and the
// collector lists them in the order it checks them. Simulated lookups never
// fail, so no gap points into a list this reorders.
func simDKIMOrder(t *testing.T, res componentsdk.InProcessResult) {
	t.Helper()
	for i, a := range res.Artifacts {
		if a.Path != ArtifactPath {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(a.Data, &doc); err != nil {
			t.Fatal(err)
		}
		domains, _ := doc["domains"].([]any)
		for _, d := range domains {
			domain, _ := d.(map[string]any)
			keys, _ := domain["dkim"].([]any)
			slices.SortStableFunc(keys, func(x, y any) int { return strings.Compare(simSelector(x), simSelector(y)) })
		}
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		res.Artifacts[i].Data = data
	}
}

func simSelector(key any) string {
	k, _ := key.(map[string]any)
	s, _ := k["selector"].(string)
	return s
}
