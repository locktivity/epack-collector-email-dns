// Package spf reads Sender Policy Framework records as RFC 7208 defines
// them. A receiver that finds a syntax error anywhere in a record returns
// permerror, which most treat as no SPF at all, so Parse rejects what RFC
// 7208's grammar does.
package spf

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Mechanism is one directive: a qualifier and a mechanism.
type Mechanism struct {
	// Qualifier is '+', the default, '-', '~', or '?'.
	Qualifier byte
	// Kind is the mechanism's name, lowercase: all, include, a, mx, ptr,
	// ip4, ip6, or exists.
	Kind string
	// Target is the domain-spec or network, as written, or "" when the
	// mechanism has none.
	Target string
	// Prefix4 and Prefix6 are the CIDR lengths, or -1 when not given.
	Prefix4, Prefix6 int
}

// Record is a parsed SPF record.
type Record struct {
	Mechanisms []Mechanism
	// Redirect and Exp are the redirect and exp modifiers' domain-specs, or
	// "" when absent.
	Redirect, Exp string
	// Unknown holds the other modifiers, which receivers ignore, by
	// lowercase name.
	Unknown map[string]string
}

// ErrNotSPF is Parse's error for text without the version section
// v=spf1.
var ErrNotSPF = errors.New("not an SPF record: it does not start with v=spf1")

// IsRecord reports whether txt starts with the version section v=spf1,
// ended by a space or by the end of the text, as RFC 7208 section 4.5
// selects records. A record that starts v=spf10 is not one.
func IsRecord(txt string) bool {
	if len(txt) < 6 || !strings.EqualFold(txt[:6], "v=spf1") {
		return false
	}
	return len(txt) == 6 || txt[6] == ' '
}

// Select picks the SPF record from a name's TXT records. It reports false
// when there is none, and returns an error when there is more than one,
// which RFC 7208 makes a permerror.
func Select(txts []string) (string, bool, error) {
	var found []string
	for _, txt := range txts {
		if IsRecord(txt) {
			found = append(found, txt)
		}
	}
	switch len(found) {
	case 0:
		return "", false, nil
	case 1:
		return found[0], true, nil
	}
	return "", false, fmt.Errorf("%d SPF records at one name; RFC 7208 allows one", len(found))
}

var (
	modifierName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)
	qnum         = regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`)
	cidrLength   = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})$`)
	dualCIDR     = regexp.MustCompile(`(/(0|[1-9][0-9]*))?(//(0|[1-9][0-9]*))?$`)
	topLabel     = regexp.MustCompile(`^([A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*|[A-Za-z0-9]+-[A-Za-z0-9-]*[A-Za-z0-9])$`)
)

// Parse reads an SPF record and returns an error for any syntax error in
// it, as RFC 7208 sections 4.6 and 12 define them: an unknown mechanism, a
// malformed address or CIDR length, a domain-spec that does not end in a
// top label or a macro, a bad macro, or a repeated redirect or exp.
func Parse(txt string) (Record, error) {
	if !IsRecord(txt) {
		return Record{}, ErrNotSPF
	}
	var r Record
	for _, term := range strings.Split(txt[6:], " ") {
		if term == "" {
			continue
		}
		if name, value, ok := modifier(term); ok {
			if err := r.addModifier(name, value); err != nil {
				return Record{}, fmt.Errorf("%q: %w", term, err)
			}
			continue
		}
		m, err := directive(term)
		if err != nil {
			return Record{}, fmt.Errorf("%q: %w", term, err)
		}
		r.Mechanisms = append(r.Mechanisms, m)
	}
	return r, nil
}

// modifier reports whether term is a modifier, name=value, rather than a
// directive, whose ":" or "/" comes before any "=".
func modifier(term string) (name, value string, ok bool) {
	i := strings.IndexAny(term, "=:/")
	if i < 0 || term[i] != '=' || !modifierName.MatchString(term[:i]) {
		return "", "", false
	}
	return strings.ToLower(term[:i]), term[i+1:], true
}

func (r *Record) addModifier(name, value string) error {
	switch name {
	case "redirect", "exp":
		if err := domainSpec(value); err != nil {
			return err
		}
		target := &r.Redirect
		if name == "exp" {
			target = &r.Exp
		}
		if *target != "" {
			return fmt.Errorf("%s appears more than once", name)
		}
		*target = value
	default:
		if err := macroString(value); err != nil {
			return err
		}
		if r.Unknown == nil {
			r.Unknown = map[string]string{}
		}
		r.Unknown[name] = value
	}
	return nil
}

func directive(term string) (Mechanism, error) {
	m := Mechanism{Qualifier: '+', Prefix4: -1, Prefix6: -1}
	if strings.ContainsRune("+-~?", rune(term[0])) {
		m.Qualifier = term[0]
		term = term[1:]
	}
	end := strings.IndexAny(term, ":/")
	if end < 0 {
		end = len(term)
	}
	m.Kind = strings.ToLower(term[:end])
	rest := term[end:]
	switch m.Kind {
	case "all":
		if rest != "" {
			return m, errors.New("all takes no argument")
		}
	case "include", "exists":
		if !strings.HasPrefix(rest, ":") {
			return m, fmt.Errorf("%s needs :domain", m.Kind)
		}
		m.Target = rest[1:]
		return m, domainSpec(m.Target)
	case "ptr":
		if rest == "" {
			return m, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return m, errors.New("ptr takes :domain")
		}
		m.Target = rest[1:]
		return m, domainSpec(m.Target)
	case "a", "mx":
		cidr := dualCIDR.FindStringSubmatchIndex(rest)
		spec, lengths := rest[:cidr[0]], rest[cidr[0]:]
		if err := dualLengths(&m, lengths); err != nil {
			return m, err
		}
		if spec == "" {
			return m, nil
		}
		if !strings.HasPrefix(spec, ":") {
			return m, fmt.Errorf("%s takes :domain", m.Kind)
		}
		m.Target = spec[1:]
		return m, domainSpec(m.Target)
	case "ip4", "ip6":
		if !strings.HasPrefix(rest, ":") {
			return m, fmt.Errorf("%s needs :network", m.Kind)
		}
		network, length, hasLength := strings.Cut(rest[1:], "/")
		m.Target = network
		max := 32
		if m.Kind == "ip6" {
			max = 128
		}
		if hasLength {
			n, err := prefix(length, max)
			if err != nil {
				return m, err
			}
			if m.Kind == "ip4" {
				m.Prefix4 = n
			} else {
				m.Prefix6 = n
			}
		}
		if m.Kind == "ip4" {
			return m, ip4(network)
		}
		return m, ip6(network)
	default:
		return m, fmt.Errorf("unknown mechanism %q", m.Kind)
	}
	return m, nil
}

// dualLengths reads a and mx's optional /ip4-length and //ip6-length.
func dualLengths(m *Mechanism, s string) error {
	if s == "" {
		return nil
	}
	v4, v6, _ := strings.Cut(s, "//")
	if v4 != "" {
		n, err := prefix(strings.TrimPrefix(v4, "/"), 32)
		if err != nil {
			return err
		}
		m.Prefix4 = n
	}
	if v6 != "" {
		n, err := prefix(v6, 128)
		if err != nil {
			return err
		}
		m.Prefix6 = n
	}
	return nil
}

func prefix(s string, max int) (int, error) {
	if !cidrLength.MatchString(s) {
		return 0, fmt.Errorf("CIDR length %q is not a number without leading zeros", s)
	}
	n, _ := strconv.Atoi(s)
	if n > max {
		return 0, fmt.Errorf("CIDR length %d is over %d", n, max)
	}
	return n, nil
}

func ip4(s string) error {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return fmt.Errorf("%q is not a dotted-quad IPv4 address", s)
	}
	for _, p := range parts {
		if !qnum.MatchString(p) {
			return fmt.Errorf("%q is not a dotted-quad IPv4 address", s)
		}
	}
	return nil
}

func ip6(s string) error {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() || a.Zone() != "" || !strings.Contains(s, ":") {
		return fmt.Errorf("%q is not an IPv6 address", s)
	}
	return nil
}

// domainSpec checks a macro-string that ends in "." and a top label, with
// an optional trailing dot, or in a macro.
func domainSpec(s string) error {
	tokens, err := macroTokens(s)
	if err != nil {
		return err
	}
	if len(tokens) > 0 && tokens[len(tokens)-1].macro {
		return nil
	}
	text := strings.TrimSuffix(s, ".")
	dot := strings.LastIndexByte(text, '.')
	if dot < 0 || strings.ContainsRune(text[dot+1:], '%') || !topLabel.MatchString(text[dot+1:]) {
		return fmt.Errorf("%q does not end in a top-level label or a macro", s)
	}
	return nil
}

func macroString(s string) error {
	_, err := macroTokens(s)
	return err
}

// macroToken is a macro-expand or a run of literal text.
type macroToken struct {
	text  string
	macro bool
}

// macroTokens splits a macro-string into its macros and literal text. The
// letters c, r, and t are allowed only in exp text that DNS returns, not in
// a record.
func macroTokens(s string) ([]macroToken, error) {
	var out []macroToken
	for i := 0; i < len(s); {
		c := s[i]
		if c != '%' {
			if c < 0x21 || c > 0x7e {
				return nil, fmt.Errorf("character %q is not allowed", c)
			}
			j := i
			for j < len(s) && s[j] != '%' && s[j] >= 0x21 && s[j] <= 0x7e {
				j++
			}
			out = append(out, macroToken{text: s[i:j]})
			i = j
			continue
		}
		if i+1 >= len(s) {
			return nil, errors.New("a % ends the text")
		}
		switch s[i+1] {
		case '%', '_', '-':
			out = append(out, macroToken{text: s[i : i+2], macro: true})
			i += 2
			continue
		case '{':
		default:
			return nil, fmt.Errorf("%%%c is not a macro", s[i+1])
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return nil, errors.New("a macro has no closing }")
		}
		body := s[i+2 : i+end]
		if err := macroBody(body); err != nil {
			return nil, err
		}
		out = append(out, macroToken{text: s[i : i+end+1], macro: true})
		i += end + 1
	}
	return out, nil
}

// macroBody checks what sits between %{ and }: a letter, optional digits
// and r, and delimiters.
func macroBody(b string) error {
	if b == "" {
		return errors.New("an empty macro")
	}
	letter := b[0] | 0x20
	if !strings.ContainsRune("slodiphv", rune(letter)) {
		if strings.ContainsRune("crt", rune(letter)) {
			return fmt.Errorf("macro letter %c is allowed only in exp text", b[0])
		}
		return fmt.Errorf("unknown macro letter %c", b[0])
	}
	rest := b[1:]
	for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		rest = rest[1:]
	}
	if len(rest) > 0 && (rest[0] == 'r' || rest[0] == 'R') {
		rest = rest[1:]
	}
	for _, d := range rest {
		if !strings.ContainsRune(".-+,/_=", d) {
			return fmt.Errorf("%q is not a macro delimiter", d)
		}
	}
	return nil
}

// All returns the qualifier of the record's all mechanism, and false when
// it has none.
func (r Record) All() (byte, bool) {
	for _, m := range r.Mechanisms {
		if m.Kind == "all" {
			return m.Qualifier, true
		}
	}
	return 0, false
}

// LookupLimit is RFC 7208 section 4.6.4's cap on the terms that cause DNS
// lookups in one check. A check that needs more fails with permerror.
const LookupLimit = 10

// Lookups counts the terms that cost a DNS lookup when the record is
// evaluated: include, a, mx, ptr, exists, and redirect. LookupLimit caps a
// check, counting the terms of included records too.
func (r Record) Lookups() int {
	n := 0
	for _, m := range r.Mechanisms {
		switch m.Kind {
		case "include", "a", "mx", "ptr", "exists":
			n++
		}
	}
	if r.Redirect != "" {
		n++
	}
	return n
}
