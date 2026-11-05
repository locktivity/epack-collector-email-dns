// Package dmarc reads DMARC Policy Records and finds the one that applies
// to a domain, as RFC 9989 defines them. RFC 9989 obsoletes RFC 7489: it
// drops the pct, rf, and ri tags, adds t, np, and psd, and replaces the
// public suffix list with a walk up the DNS tree.
package dmarc

import (
	"context"
	"errors"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Policy is a Domain Owner Assessment Policy: what the domain owner asks a
// receiver to do with mail that fails DMARC.
type Policy string

// Policies, in RFC 9989's order from least to most strict.
const (
	None       Policy = "none"
	Quarantine Policy = "quarantine"
	Reject     Policy = "reject"
)

// Record is a parsed DMARC Policy Record.
type Record struct {
	// P, SP, and NP are the policies the record requests for the domain it
	// is published at, for its existing subdomains, and for its
	// non-existent ones. Each is "" when its tag is absent or its value is
	// not one of the three.
	P, SP, NP Policy
	// PSD is the psd tag: 'y' for a Public Suffix Domain, 'n' for a domain
	// that is its own Organizational Domain, or the default 'u'.
	PSD byte
	// Testing is t=y: the domain owner is testing, and asks receivers to
	// apply each policy one level lower.
	Testing bool
	// RUA and RUF list the reporting URIs that are URIs, with a scheme, as
	// RFC 9989 requires. BadRUA and BadRUF list the entries that are not,
	// such as an address without mailto: or an entry with a space in it.
	// Receivers ignore those.
	RUA, RUF, BadRUA, BadRUF []string
	// ADKIM and ASPF are the alignment modes: 'r', the default, or 's'.
	ADKIM, ASPF byte
	// FO is the failure reporting options, "0" by default.
	FO string
	// Invalid names, in order, the tags whose values RFC 9989's grammar
	// rejects, and tags repeated after their first appearance. Each takes
	// its default.
	Invalid []string
	// Legacy holds the tags RFC 7489 defined and RFC 9989 dropped, pct, rf,
	// and ri, by name. Receivers ignore them.
	Legacy map[string]string
}

var (
	tagName   = regexp.MustCompile(`^[A-Za-z]+$`)
	uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)
	reportCap = regexp.MustCompile(`![0-9]+[kmgtKMGT]?$`)
)

// Parse reads a DMARC Policy Record. It reports false for text that is not
// one, since its first tag must be v=DMARC1, with DMARC1 in that case. An
// unknown tag is ignored, and a tag whose value does not match the grammar
// takes its default, as RFC 9989 says; Invalid names those.
func Parse(txt string) (Record, bool) {
	r := Record{PSD: 'u', ADKIM: 'r', ASPF: 'r', FO: "0"}
	parts := strings.Split(txt, ";")
	name, value, ok := tag(parts[0])
	if !ok || name != "v" || value != "DMARC1" {
		return Record{}, false
	}
	seen := map[string]bool{"v": true}
	for _, part := range parts[1:] {
		if strings.TrimSpace(part) == "" {
			continue
		}
		name, value, ok := tag(part)
		if !ok {
			r.Invalid = append(r.Invalid, strings.TrimSpace(part))
			continue
		}
		if seen[name] {
			r.Invalid = append(r.Invalid, name)
			continue
		}
		seen[name] = true
		if !r.set(name, value) {
			r.Invalid = append(r.Invalid, name)
		}
	}
	return r, true
}

// tag splits one tag-value pair, with optional whitespace around the
// equals sign and the value.
func tag(s string) (name, value string, ok bool) {
	n, v, found := strings.Cut(s, "=")
	n, v = strings.TrimSpace(n), strings.TrimSpace(v)
	if !found || !tagName.MatchString(n) || v == "" {
		return "", "", false
	}
	return strings.ToLower(n), v, true
}

// set applies one tag and reports whether its value is valid. An unknown
// tag is valid, and ignored.
func (r *Record) set(name, value string) bool {
	lower := strings.ToLower(value)
	switch name {
	case "p", "sp", "np":
		p, ok := policy(lower)
		if !ok {
			return false
		}
		switch name {
		case "p":
			r.P = p
		case "sp":
			r.SP = p
		default:
			r.NP = p
		}
	case "t":
		if lower != "y" && lower != "n" {
			return false
		}
		r.Testing = lower == "y"
	case "psd":
		if lower != "y" && lower != "n" && lower != "u" {
			return false
		}
		r.PSD = lower[0]
	case "adkim", "aspf":
		if lower != "r" && lower != "s" {
			return false
		}
		if name == "adkim" {
			r.ADKIM = lower[0]
		} else {
			r.ASPF = lower[0]
		}
	case "fo":
		if !validFO(lower) {
			return false
		}
		r.FO = lower
	case "rua":
		r.RUA, r.BadRUA = uris(value)
		return len(r.BadRUA) == 0
	case "ruf":
		r.RUF, r.BadRUF = uris(value)
		return len(r.BadRUF) == 0
	case "pct", "rf", "ri":
		if r.Legacy == nil {
			r.Legacy = map[string]string{}
		}
		r.Legacy[name] = value
	}
	return true
}

func policy(s string) (Policy, bool) {
	switch p := Policy(s); p {
	case None, Quarantine, Reject:
		return p, true
	}
	return "", false
}

// validFO checks fo's colon-separated options: 0 or 1, at most one of
// them, and d and s, each at most once.
func validFO(s string) bool {
	seen := map[string]bool{}
	for _, o := range strings.Split(s, ":") {
		if (o != "0" && o != "1" && o != "d" && o != "s") || seen[o] {
			return false
		}
		seen[o] = true
	}
	return !seen["0"] || !seen["1"]
}

// uris splits a reporting URI list into the entries that are URIs with a
// scheme and those that are not. An obsolete size limit, such as !10m, is
// dropped, as RFC 9989 says reporters do. RFC 3986 allows no whitespace in a
// URI, so an entry with whitespace inside it is not one.
func uris(s string) (good, bad []string) {
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := url.Parse(reportCap.ReplaceAllString(entry, ""))
		if err != nil || strings.ContainsFunc(entry, unicode.IsSpace) || !uriScheme.MatchString(u.Scheme) || (u.Opaque == "" && u.Host == "" && u.Path == "") {
			bad = append(bad, entry)
			continue
		}
		good = append(good, entry)
	}
	return good, bad
}

// Requested returns the policy the record requests: for the domain it is
// published at, or, with subdomain set, for a subdomain of it, which takes
// np when it does not exist and otherwise sp, each falling back to p, as
// RFC 9989 section 4.10.1 says. A record whose p is absent or invalid, or
// whose sp or np is invalid, acts as p=none when it lists a valid rua URI,
// and otherwise calls for no DMARC processing, which Requested reports as
// false.
func (r Record) Requested(subdomain, exists bool) (Policy, bool) {
	if r.P == "" || slices.Contains(r.Invalid, "sp") || slices.Contains(r.Invalid, "np") {
		if len(r.RUA) > 0 {
			return None, true
		}
		return "", false
	}
	switch {
	case subdomain && !exists && r.NP != "":
		return r.NP, true
	case subdomain && r.SP != "":
		return r.SP, true
	}
	return r.P, true
}

// Applied returns the policy a receiver applies to failing mail when the
// record requests p: p itself, or one level lower under t=y, as RFC 9989
// section 4.7 says.
func (r Record) Applied(p Policy) Policy {
	if !r.Testing {
		return p
	}
	switch p {
	case Reject:
		return Quarantine
	case Quarantine:
		return None
	}
	return p
}

// Lookup returns the TXT records at a name. A name with no TXT records, or
// one that does not exist, returns a *net.DNSError whose IsNotFound is true;
// any other error is a lookup that failed. componentsdk.Resolver's
// LookupTXT is one.
type Lookup func(ctx context.Context, name string) ([]string, error)

// Found is the DMARC Policy Record that applies to a domain.
type Found struct {
	Record Record
	// At is the domain the record is published for: the domain itself, or
	// its Organizational Domain or Public Suffix Domain.
	At string
	// Queried lists the names looked up, in order.
	Queried []string
}

// Policy returns the policy the record requests for domain, the one
// Discover was asked about, which exists: p when the record is the
// domain's own, and sp, falling back to p, when it is published above.
func (f Found) Policy(domain string) (Policy, bool) {
	return f.Record.Requested(!strings.EqualFold(trimDot(domain), f.At), true)
}

// maxLabels is where the DNS tree walk shortens a long name to, so that no
// walk takes more than eight queries.
const maxLabels = 7

// Discover finds the DMARC Policy Record that applies to mail from domain,
// as RFC 9989 section 4.10.1 says: the domain's own, or, failing that, the
// one that a walk up the DNS tree selects for its Organizational Domain or
// Public Suffix Domain. It reports false when no record applies, and
// returns an error when a lookup failed, since no answer is then known.
func Discover(ctx context.Context, domain string, lookup Lookup) (Found, bool, error) {
	domain = trimDot(domain)
	var queried []string
	query := func(name string) (Record, bool, error) {
		queried = append(queried, "_dmarc."+name)
		return fetch(ctx, lookup, name)
	}
	own, ok, err := query(domain)
	if err != nil {
		return Found{Queried: queried}, false, err
	}
	if ok {
		return Found{Record: own, At: domain, Queried: queried}, true, nil
	}
	labels := strings.Split(domain, ".")
	if len(labels) > maxLabels+1 {
		labels = labels[len(labels)-maxLabels:]
	} else {
		labels = labels[1:]
	}
	type hit struct {
		name   string
		record Record
	}
	var hits []hit
	for ; len(labels) > 0; labels = labels[1:] {
		name := strings.Join(labels, ".")
		r, ok, err := query(name)
		if err != nil {
			return Found{Queried: queried}, false, err
		}
		if !ok {
			continue
		}
		hits = append(hits, hit{name, r})
		if r.PSD == 'y' || r.PSD == 'n' {
			break
		}
	}
	if len(hits) == 0 {
		return Found{Queried: queried}, false, nil
	}
	// The walk stops at a psd=n or psd=y record, so only the last hit can
	// carry one. Select the Organizational Domain as RFC 9989 section
	// 4.10.2 says: a psd=n record's domain is its own, a psd=y record's is
	// the domain one label below it, and otherwise it is the domain with
	// the fewest labels. Its record applies, or the Public Suffix Domain's
	// when it has none.
	pick := hits[len(hits)-1]
	if pick.record.PSD == 'y' {
		all := strings.Split(domain, ".")
		org := strings.Join(all[len(all)-len(strings.Split(pick.name, "."))-1:], ".")
		for _, h := range hits {
			if h.name == org {
				pick = h
			}
		}
	}
	return Found{Record: pick.record, At: pick.name, Queried: queried}, true, nil
}

// fetch looks up one name's DMARC Policy Record. It reports false when the
// name has none, or more than one, which RFC 9989 says to discard.
func fetch(ctx context.Context, lookup Lookup, name string) (Record, bool, error) {
	txts, err := lookup(ctx, "_dmarc."+name)
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return Record{}, false, nil
	case err != nil:
		return Record{}, false, err
	}
	var found []Record
	for _, txt := range txts {
		if r, ok := Parse(txt); ok {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		return Record{}, false, nil
	}
	return found[0], true, nil
}

func trimDot(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
