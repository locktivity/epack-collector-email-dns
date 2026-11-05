package spf

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseValidRecords(t *testing.T) {
	valid := []string{
		"v=spf1 -all",
		"V=SPF1 MX -ALL",
		"v=spf1",
		"v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.7 ip6:2001:db8::/32 ip6:::ffff:192.0.2.1 a mx/24 a:mail.example.com/28//64 mx//64 ~all",
		"v=spf1 include:_spf.google.com include:spf.protection.outlook.com ?all",
		"v=spf1 exists:%{i}.%{l1r+-}._spf.%{d} redirect=_spf.example.com",
		"v=spf1 ptr ptr:example.com. -all",
		"v=spf1 a:example.com. exp=explain.%{d} -all",
		"v=spf1 ip4:0.0.0.0/0 ra=postmaster  -all  ",
		"v=spf1 include:%{d2} -all",
	}
	for _, txt := range valid {
		if _, err := Parse(txt); err != nil {
			t.Errorf("Parse(%q): %v", txt, err)
		}
	}
}

func TestParseRejectsWhatReceiversReturnPermerrorFor(t *testing.T) {
	cases := map[string]string{
		"v=spf1 ip4: -all":                     "IPv4",
		"v=spf1 ip4:192.0.2.256 -all":          "IPv4",
		"v=spf1 ip4:192.0.2.0/33 -all":         "over 32",
		"v=spf1 ip4:192.0.02.1 -all":           "IPv4",
		"v=spf1 ip4:192.0.2.0/024 -all":        "leading zeros",
		"v=spf1 ip6:192.0.2.1 -all":            "IPv6",
		"v=spf1 ip6:2001:db8::/129 -all":       "over 128",
		"v=spf1 mx ~-all":                      "unknown mechanism",
		"v=spf1 include -all":                  "needs :domain",
		"v=spf1 include:example -all":          "top-level label",
		"v=spf1 include:example.123 -all":      "top-level label",
		"v=spf1 a:example.com/33 -all":         "over 32",
		"v=spf1 all:x":                         "no argument",
		"v=spf1 redirect=a.com redirect=b.com": "more than once",
		"v=spf1 exists:%{c}.example.com -all":  "only in exp",
		"v=spf1 exists:%{x}.example.com -all":  "unknown macro letter",
		"v=spf1 exists:%{d.example.com -all":   "no closing",
		"v=spf1 include:50%.example.com -all":  "not a macro",
		"v=spf1 +-all":                         "unknown mechanism",
		"v=spf1 ipv4:192.0.2.1 -all":           "unknown mechanism",
	}
	for txt, want := range cases {
		_, err := Parse(txt)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want an error mentioning %q", txt, err, want)
		}
	}
	for _, txt := range []string{"v=spf10 -all", "spf1 -all", "v=spf1\t-all"} {
		if _, err := Parse(txt); err != ErrNotSPF && txt != "v=spf1\t-all" {
			t.Errorf("Parse(%q) = %v, want ErrNotSPF", txt, err)
		}
	}
	if _, err := Parse("v=spf1\t-all"); err == nil {
		t.Error("terms are separated by spaces only")
	}
}

func TestParseReadsTheTerms(t *testing.T) {
	r, err := Parse("v=spf1 -ip4:192.0.2.0/24 a:mail.example.com//64 ~all redirect=_spf.example.com ra=postmaster")
	if err != nil {
		t.Fatal(err)
	}
	want := []Mechanism{
		{Qualifier: '-', Kind: "ip4", Target: "192.0.2.0", Prefix4: 24, Prefix6: -1},
		{Qualifier: '+', Kind: "a", Target: "mail.example.com", Prefix4: -1, Prefix6: 64},
		{Qualifier: '~', Kind: "all", Prefix4: -1, Prefix6: -1},
	}
	if !reflect.DeepEqual(r.Mechanisms, want) || r.Redirect != "_spf.example.com" || r.Unknown["ra"] != "postmaster" {
		t.Errorf("Parse = %+v", r)
	}
	if q, ok := r.All(); !ok || q != '~' {
		t.Errorf("All = %c %v", q, ok)
	}
	if r.Lookups() != 2 {
		t.Errorf("Lookups = %d, want 2 for a and redirect", r.Lookups())
	}
}

func TestSelect(t *testing.T) {
	if txt, ok, err := Select([]string{"google-site-verification=x", "v=spf1 -all"}); !ok || err != nil || txt != "v=spf1 -all" {
		t.Errorf("Select = %q %v %v", txt, ok, err)
	}
	if _, ok, err := Select([]string{"v=spf10 -all", "other"}); ok || err != nil {
		t.Errorf("no SPF record is none, not an error: %v %v", ok, err)
	}
	if _, _, err := Select([]string{"v=spf1 -all", "v=spf1 mx -all"}); err == nil {
		t.Error("two SPF records are a permerror")
	}
}
