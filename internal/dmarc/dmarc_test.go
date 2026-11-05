package dmarc

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	r, ok := Parse("v=DMARC1; p=reject; sp=quarantine; np=reject; t=y; psd=n; adkim=s; aspf=r; fo=1:d:s; rua=mailto:agg@example.com, https://reports.example.com/dmarc!10m; ruf=mailto:fail@example.com")
	if !ok {
		t.Fatal("a full record should parse")
	}
	want := Record{P: Reject, SP: Quarantine, NP: Reject, Testing: true, PSD: 'n', ADKIM: 's', ASPF: 'r', FO: "1:d:s",
		RUA: []string{"mailto:agg@example.com", "https://reports.example.com/dmarc!10m"}, RUF: []string{"mailto:fail@example.com"}}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("Parse = %+v\nwant %+v", r, want)
	}

	notRecords := []string{"", "p=reject; v=DMARC1", "v=dmarc1; p=reject", "v=DMARC2; p=reject", "v = DMARC10; p=none", "spf1 include:x"}
	for _, txt := range notRecords {
		if _, ok := Parse(txt); ok {
			t.Errorf("Parse(%q) should not be a DMARC record", txt)
		}
	}
	if _, ok := Parse("V = DMARC1 ;p=none;"); !ok {
		t.Error("the tag name is not case-sensitive and whitespace around = and ; is allowed")
	}
}

func TestParseKeepsDefaultsForBadValuesAndIgnoresUnknownTags(t *testing.T) {
	r, ok := Parse("v=DMARC1; p=rejected; adkim=x; fo=0:1; zz=1; pct=50; ri=3600; p=none;; rua=dmarc@example.com, mailto:ok@example.com")
	if !ok {
		t.Fatal("a record with bad values is still a record")
	}
	if r.P != "" || r.ADKIM != 'r' || r.FO != "0" {
		t.Errorf("bad values take their defaults: P=%q ADKIM=%c FO=%q", r.P, r.ADKIM, r.FO)
	}
	if strings.Join(r.Invalid, ",") != "p,adkim,fo,p,rua" {
		t.Errorf("Invalid = %q", r.Invalid)
	}
	if r.Legacy["pct"] != "50" || r.Legacy["ri"] != "3600" {
		t.Errorf("RFC 7489's dropped tags are kept as legacy: %v", r.Legacy)
	}
	if strings.Join(r.RUA, ",") != "mailto:ok@example.com" || strings.Join(r.BadRUA, ",") != "dmarc@example.com" {
		t.Errorf("an address without a scheme is not a URI: RUA=%q BadRUA=%q", r.RUA, r.BadRUA)
	}
}

func TestRequested(t *testing.T) {
	parse := func(s string) Record { r, _ := Parse(s); return r }
	cases := []struct {
		name              string
		record            string
		subdomain, exists bool
		want              Policy
		applies           bool
	}{
		{"the domain's own p", "v=DMARC1; p=reject; sp=none", false, true, Reject, true},
		{"sp for an existing subdomain", "v=DMARC1; p=reject; sp=none", true, true, None, true},
		{"p when sp is absent", "v=DMARC1; p=quarantine", true, true, Quarantine, true},
		{"np for a subdomain that does not exist", "v=DMARC1; p=reject; sp=none; np=quarantine", true, false, Quarantine, true},
		{"sp when np is absent", "v=DMARC1; p=reject; sp=none", true, false, None, true},
		{"no p, a valid rua: p=none", "v=DMARC1; rua=mailto:r@example.com", false, true, None, true},
		{"no p and no rua: no DMARC", "v=DMARC1; adkim=s", false, true, "", false},
		{"an invalid sp with a valid rua: p=none", "v=DMARC1; p=reject; sp=bogus; rua=mailto:r@example.com", true, true, None, true},
		{"an invalid sp, no rua: no DMARC", "v=DMARC1; p=reject; sp=bogus", false, true, "", false},
		{"a rua without a scheme does not count", "v=DMARC1; rua=r@example.com", false, true, "", false},
		{"a rua with a space in it does not count", "v=DMARC1; rua=mailto:a@example.com mailto:b@example.com", false, true, "", false},
	}
	for _, tc := range cases {
		got, ok := parse(tc.record).Requested(tc.subdomain, tc.exists)
		if got != tc.want || ok != tc.applies {
			t.Errorf("%s: Requested = %q %v, want %q %v", tc.name, got, ok, tc.want, tc.applies)
		}
	}
	testing := parse("v=DMARC1; p=reject; t=y")
	if testing.Applied(Reject) != Quarantine || testing.Applied(Quarantine) != None || testing.Applied(None) != None {
		t.Error("t=y applies each policy one level lower")
	}
	if parse("v=DMARC1; p=reject").Applied(Reject) != Reject {
		t.Error("without t=y the policy applies as requested")
	}
}

// zone answers lookups from a map of names to TXT records. A name missing
// from it does not exist; a name mapped to nil fails the lookup.
type zone map[string][]string

func (z zone) lookup(_ context.Context, name string) ([]string, error) {
	txts, ok := z[name]
	switch {
	case !ok:
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	case txts == nil:
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return txts, nil
}

func TestDiscover(t *testing.T) {
	cases := []struct {
		name    string
		zone    zone
		domain  string
		at      string
		policy  Policy
		queried int
	}{
		{"the domain's own record", zone{"_dmarc.example.com": {"v=DMARC1; p=reject"}}, "example.com", "example.com", Reject, 1},
		{"a subdomain with no record takes its parent's sp", zone{"_dmarc.example.com": {"v=DMARC1; p=reject; sp=quarantine"}},
			"mail.example.com", "example.com", Quarantine, 3},
		{"records at two levels: the fewest labels is the Organizational Domain",
			zone{"_dmarc.mail.example.com": {"v=DMARC1; p=none"}, "_dmarc.example.com": {"v=DMARC1; p=reject"}},
			"a.mail.example.com", "example.com", Reject, 4},
		{"psd=n stops the walk", zone{"_dmarc.mail.example.com": {"v=DMARC1; p=quarantine; psd=n"}, "_dmarc.example.com": {"v=DMARC1; p=reject"}},
			"a.mail.example.com", "mail.example.com", Quarantine, 2},
		{"psd=y with no record below it: the PSD's applies", zone{"_dmarc.com": {"v=DMARC1; p=reject; psd=y"}},
			"a.mail.example.com", "com", Reject, 4},
		{"psd=y with the Organizational Domain's record below it",
			zone{"_dmarc.example.com": {"v=DMARC1; p=none"}, "_dmarc.com": {"v=DMARC1; p=reject; psd=y"}},
			"a.mail.example.com", "example.com", None, 4},
		{"two records at one name are discarded", zone{"_dmarc.mail.example.com": {"v=DMARC1; p=none", "v=DMARC1; p=reject"}, "_dmarc.example.com": {"v=DMARC1; p=quarantine"}},
			"mail.example.com", "example.com", Quarantine, 3},
		{"text that is not DMARC is skipped", zone{"_dmarc.example.com": {"google-site-verification=x", "v=DMARC1; p=reject"}},
			"example.com", "example.com", Reject, 1},
	}
	for _, tc := range cases {
		found, ok, err := Discover(context.Background(), tc.domain, tc.zone.lookup)
		if err != nil || !ok {
			t.Errorf("%s: Discover = %v %v", tc.name, ok, err)
			continue
		}
		p, _ := found.Policy(tc.domain)
		if found.At != tc.at || p != tc.policy || len(found.Queried) != tc.queried {
			t.Errorf("%s: at %s, policy %s, %d queries %v; want %s, %s, %d", tc.name, found.At, p, len(found.Queried), found.Queried, tc.at, tc.policy, tc.queried)
		}
	}

	long := "a.b.c.d.e.f.g.h.i.j.mail.example.com"
	found, ok, err := Discover(context.Background(), long, zone{}.lookup)
	want := []string{"_dmarc." + long, "_dmarc.g.h.i.j.mail.example.com", "_dmarc.h.i.j.mail.example.com", "_dmarc.i.j.mail.example.com",
		"_dmarc.j.mail.example.com", "_dmarc.mail.example.com", "_dmarc.example.com", "_dmarc.com"}
	if ok || err != nil || !reflect.DeepEqual(found.Queried, want) {
		t.Errorf("a long name takes RFC 9989's eight queries: %v %v %q", ok, err, found.Queried)
	}

	_, ok, err = Discover(context.Background(), "mail.example.com", zone{"_dmarc.example.com": nil}.lookup)
	var dnsErr *net.DNSError
	if ok || !errors.As(err, &dnsErr) || dnsErr.IsNotFound {
		t.Errorf("a failed lookup is an error, not an absent record: %v %v", ok, err)
	}
}
