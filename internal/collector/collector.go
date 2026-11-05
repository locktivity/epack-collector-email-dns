package collector

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/locktivity/epack-collector-email-dns/internal/dmarc"
	"github.com/locktivity/epack-collector-email-dns/internal/spf"
	"github.com/locktivity/epack/componentsdk"
	"golang.org/x/net/idna"
)

// Common DKIM selectors to check
var commonDKIMSelectors = []string{
	"default",
	"selector1", "selector2", // Microsoft 365
	"google",   // Google Workspace
	"k1",       // Mailchimp
	"s1", "s2", // Generic
	"mail",
	"dkim",
}

// Lookup operations, as the collector result counts them.
const (
	opMX    = "dns.mx.lookup"
	opSPF   = "dns.spf.lookup"
	opDMARC = "dns.dmarc.lookup"
	opDKIM  = "dns.dkim.lookup"
)

// Steps of a run, in order. Each looks up one kind of record for every
// domain.
const (
	stepMX    = "mail_servers"
	stepSPF   = "spf"
	stepDMARC = "dmarc"
	stepDKIM  = "dkim"
)

// Collect gathers email DNS posture for all configured domains. A name or
// record that does not exist is an answer. Any other lookup failure, such as
// SERVFAIL or a timeout, leaves the values that depend on it out of the
// posture, with a gap for each in cfg.Recorder.
func Collect(ctx context.Context, cfg Config) *EmailDNSPosture {
	s := scanner{resolver: cfg.Resolver, rec: cfg.Recorder, progress: cfg.OnProgress}
	scans := make([]domainScan, len(cfg.Domains))
	for i, domain := range cfg.Domains {
		name, err := lookupName(domain)
		if err != nil {
			// Run rejects a domain with no A-label form, so only a direct
			// caller gets here. Its lookups use the domain as written.
			name = domain
		}
		scans[i].name = name
		scans[i].result = DomainResult{Domain: domain, Errors: []string{}}
	}

	s.step(ctx, stepMX, "Mail servers", scans, func(ctx context.Context, d *domainScan) {
		d.mx = s.collectMX(ctx, d.name, &d.result)
	})
	s.step(ctx, stepSPF, "SPF records", scans, func(ctx context.Context, d *domainScan) {
		d.spf = s.collectSPF(ctx, d.name, &d.result)
	})
	s.step(ctx, stepDMARC, "DMARC policies", scans, func(ctx context.Context, d *domainScan) {
		d.dmarc = s.collectDMARC(ctx, d.name, &d.result)
	})
	s.step(ctx, stepDKIM, "DKIM keys at common selectors", scans, func(ctx context.Context, d *domainScan) {
		d.dkimUnread, d.dkim = s.collectDKIM(ctx, d.name, &d.result)
	})

	posture := &EmailDNSPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   cfg.Now().UTC(),
		Domains:       make([]DomainResult, 0, len(scans)),
	}
	for i := range scans {
		s.assess(i, &scans[i])
		posture.Domains = append(posture.Domains, scans[i].result)
	}
	if cfg.OnProgress != nil {
		cfg.OnProgress(int64(len(scans)), int64(len(scans)), "Collection complete")
	}

	posture.Summary = s.summarize(scans)
	posture.Diagnostics = computeDiagnostics(posture.Domains)
	return posture
}

// scanner looks up each domain's records and records a gap for each value a
// failed lookup leaves out.
type scanner struct {
	resolver Resolver
	rec      *componentsdk.Recorder
	progress func(current, total int64, message string)
}

// step runs lookup for every domain as the run's step named name.
func (s *scanner) step(ctx context.Context, name, title string, scans []domainScan, lookup func(context.Context, *domainScan)) {
	ctx, step := componentsdk.StartStep(ctx, name, title)
	defer step.End()
	for i := range scans {
		if s.progress != nil {
			s.progress(int64(i), int64(len(scans)), title+": "+scans[i].result.Domain)
		}
		lookup(ctx, &scans[i])
	}
}

// domainScan is one domain's result with the error of each lookup that
// failed, so the summary can tell a domain without a record from one whose
// record could not be read. name is the domain as its lookups use it.
type domainScan struct {
	name                 string
	result               DomainResult
	mx, spf, dmarc, dkim error
	dkimUnread           int
}

// lookupName returns the name that domain's lookups use. A domain written
// with Unicode characters is looked up by its A-label form, as RFC 5891
// section 5.5 says. lookupName fails for one that has no A-label form. An
// ASCII domain is looked up as written.
func lookupName(domain string) (string, error) {
	for i := 0; i < len(domain); i++ {
		if domain[i] >= utf8.RuneSelf {
			return idna.Lookup.ToASCII(domain)
		}
	}
	return domain, nil
}

// assess evaluates the domain at index from its lookups and records a gap for
// each value a failed lookup left out.
func (s *scanner) assess(index int, d *domainScan) {
	r := &d.result
	r.Assessment = computeAssessment(r, d.dkim == nil)

	if d.mx != nil {
		s.rec.NotCollected(domainAt(index, "mx"), d.mx)
	}
	if d.spf != nil {
		s.rec.NotCollected(domainAt(index, "spf"), d.spf)
	}
	if d.dmarc != nil {
		s.rec.NotCollected(domainAt(index, "dmarc"), d.dmarc)
		s.rec.NotCollected(domainAt(index, "assessment/enforced"), d.dmarc)
		s.rec.NotCollected(domainAt(index, "assessment/has_reporting"), d.dmarc)
	}
	switch {
	case d.dkim != nil && r.DKIM != nil:
		s.rec.Partial(domainAt(index, "dkim"), d.dkimUnread, d.dkim)
	case d.dkim != nil:
		s.rec.NotCollected(domainAt(index, "dkim"), d.dkim)
	}
	if r.Assessment.Issues == nil {
		s.rec.NotCollected(domainAt(index, "assessment/issues"), cmp.Or(d.spf, d.dmarc, d.dkim))
	}
}

func domainAt(index int, field string) componentsdk.Location {
	return componentsdk.Location{Path: ArtifactPath, Pointer: fmt.Sprintf("/domains/%d/%s", index, field)}
}

func summaryAt(field string) componentsdk.Location {
	return componentsdk.Location{Path: ArtifactPath, Pointer: "/summary/" + field}
}

func named(ctx context.Context, op string) context.Context {
	return componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op})
}

func (s *scanner) collectMX(ctx context.Context, domain string, result *DomainResult) error {
	mxRecords, err := s.resolver.LookupMX(named(ctx, opMX), domain)
	if err != nil && !isNotFound(err) {
		result.Errors = append(result.Errors, "MX lookup failed: "+err.Error())
		return err
	}

	result.MX = make([]MXRecord, 0, len(mxRecords))
	for _, mx := range mxRecords {
		result.MX = append(result.MX, MXRecord{
			Host:     strings.TrimSuffix(mx.Host, "."),
			Priority: mx.Pref,
		})
	}

	// Sort by priority
	sort.Slice(result.MX, func(i, j int) bool {
		return result.MX[i].Priority < result.MX[j].Priority
	})
	return nil
}

func (s *scanner) collectSPF(ctx context.Context, domain string, result *DomainResult) error {
	txtRecords, err := s.resolver.LookupTXT(named(ctx, opSPF), domain)
	if err != nil && !isNotFound(err) {
		result.Errors = append(result.Errors, "SPF lookup failed: "+err.Error())
		return err
	}
	result.SPF.Read = true

	var spfRecords []string
	for _, txt := range txtRecords {
		if spf.IsRecord(txt) {
			spfRecords = append(spfRecords, txt)
		}
	}

	if len(spfRecords) == 0 {
		return nil
	}

	// Multiple SPF records is an invalid configuration per RFC 7208
	if len(spfRecords) > 1 {
		result.SPF.Record = &SPFRecord{
			Record: spfRecords[0],
			Valid:  false,
		}
		result.Errors = append(result.Errors, "Multiple SPF records found (invalid per RFC 7208)")
		return nil
	}

	result.SPF.Record = &SPFRecord{
		Record: spfRecords[0],
		Valid:  validateSPF(spfRecords[0]),
	}
	return nil
}

// collectDMARC finds the DMARC record that applies to the domain, as RFC
// 9989 section 4.10 defines it. That is the domain's own record, or the one
// the DNS tree walk finds above it.
func (s *scanner) collectDMARC(ctx context.Context, domain string, result *DomainResult) error {
	answers := map[string][]string{}
	lookup := func(ctx context.Context, name string) ([]string, error) {
		txts, err := s.resolver.LookupTXT(ctx, name)
		answers[name] = txts
		return txts, err
	}
	found, ok, err := dmarc.Discover(named(ctx, opDMARC), domain, lookup)
	if err != nil {
		result.Errors = append(result.Errors, "DMARC lookup failed: "+err.Error())
		return err
	}
	result.DMARC.Read = true

	// Receivers ignore every record at a name that has more than one, and
	// look further up the tree.
	own := found.Queried[0]
	if len(dmarcRecords(answers[own])) > 1 {
		result.Errors = append(result.Errors, "Multiple DMARC records found (receivers ignore them)")
	}
	if !ok {
		return nil
	}
	at := "_dmarc." + found.At
	text := dmarcRecords(answers[at])[0]
	result.DMARC.Record = newDMARCRecord(text, found.Record, at != own)
	return nil
}

// dmarcRecords returns the TXT records that are DMARC records.
func dmarcRecords(txts []string) []string {
	var out []string
	for _, txt := range txts {
		if _, ok := dmarc.Parse(txt); ok {
			out = append(out, txt)
		}
	}
	return out
}

// newDMARCRecord describes the DMARC record r, whose text is text. above is
// true when the DNS tree walk found the record above the domain.
func newDMARCRecord(text string, r dmarc.Record, above bool) *DMARCRecord {
	d := &DMARCRecord{
		Record:          text,
		Policy:          "unknown",
		SubdomainPolicy: "unknown",
		Pct:             100,
		RUA:             tagValue(text, "rua"),
		RUF:             tagValue(text, "ruf"),
		parsed:          r,
		above:           above,
	}
	if pct, err := strconv.Atoi(r.Legacy["pct"]); err == nil && pct >= 0 && pct <= 100 {
		d.Pct = pct
	}
	// Receivers treat a record with no valid p tag, or an invalid sp or np
	// tag, as p=none when it lists a valid rua URI. Without one, no DMARC
	// policy applies, and the record is not valid.
	if p, ok := r.Requested(false, true); ok {
		sp, _ := r.Requested(true, true)
		d.Policy, d.SubdomainPolicy, d.Valid = string(p), string(sp), true
	}
	return d
}

// tagValue returns the value of the first tag called name in a DMARC
// record, as written, or "" when the record has no such tag.
func tagValue(record, name string) string {
	for _, part := range strings.Split(record, ";") {
		key, value, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// collectDKIM looks up the common selectors and returns how many lookups
// failed, with the first failure. It keeps the records the selectors that
// answered returned, and leaves the list out only when every lookup failed.
func (s *scanner) collectDKIM(ctx context.Context, domain string, result *DomainResult) (int, error) {
	records := []DKIMRecord{}
	failed := 0
	var firstErr error

	for _, selector := range commonDKIMSelectors {
		dkimDomain := selector + "._domainkey." + domain
		txtRecords, err := s.resolver.LookupTXT(named(ctx, opDKIM), dkimDomain)
		if err != nil {
			// NXDOMAIN is expected for selectors that don't exist
			if isNotFound(err) {
				continue
			}
			// Report real errors (SERVFAIL, timeout, etc.)
			result.Errors = append(result.Errors, "DKIM lookup failed for selector "+selector+": "+err.Error())
			failed++
			firstErr = cmp.Or(firstErr, err)
			continue
		}

		for _, txt := range txtRecords {
			if isDKIMRecord(txt) {
				records = append(records, DKIMRecord{
					Selector: selector,
					Record:   txt,
					Valid:    validateDKIM(txt),
				})
				break
			}
		}
	}

	if failed < len(commonDKIMSelectors) {
		result.DKIM = records
	}
	return failed, firstErr
}

// validateSPF reports whether an SPF record matches RFC 7208's grammar, since
// receivers return permerror for a syntax error anywhere in it. A record
// with no mechanism and no redirect or exp modifier, such as a bare v=spf1,
// also reads as invalid.
func validateSPF(record string) bool {
	r, err := spf.Parse(record)
	return err == nil && (len(r.Mechanisms) > 0 || r.Redirect != "" || r.Exp != "")
}

// validateDKIM reports whether a DKIM key record's p tag holds key data.
// RFC 6376 section 3.2 says a tag name given twice makes the whole tag list
// invalid. Section 3.6.1 says p is base64. Section 2.4 allows whitespace
// anywhere in it and up to two = signs at the end. An empty p tag means the
// key was revoked.
func validateDKIM(record string) bool {
	key, ok := dkimPublicKey(record)
	if !ok || repeatsTag(record) {
		return false
	}
	key = strings.Join(strings.Fields(key), "")
	key = strings.TrimSuffix(strings.TrimSuffix(key, "="), "=")
	if key == "" {
		return false
	}
	_, err := base64.RawStdEncoding.DecodeString(key)
	return err == nil
}

// computeAssessment evaluates the records it was given and leaves out what a
// failed lookup leaves undecided. dkimComplete says whether every DKIM
// selector's lookup answered.
func computeAssessment(result *DomainResult, dkimComplete bool) Assessment {
	spfRecord, dmarcRecord := result.SPF.Record, result.DMARC.Record
	enforced, hasReporting := false, false
	issues := []string{}

	// Check SPF
	if spfRecord == nil {
		issues = append(issues, "No SPF record")
	} else if !spfRecord.Valid {
		issues = append(issues, "Invalid SPF record")
	}

	// Check DMARC
	if dmarcRecord == nil {
		issues = append(issues, "No DMARC record")
	} else if !dmarcRecord.Valid {
		issues = append(issues, "Invalid DMARC record")
	} else {
		r := dmarcRecord.parsed
		// The record's p applies when the record is the domain's own, and
		// its subdomain policy applies when the record is above it. Under
		// t=y, receivers apply that policy one level lower.
		requested, _ := r.Requested(dmarcRecord.above, true)
		if r.Applied(requested) == dmarc.Reject {
			enforced = true
		}
		switch requested {
		case dmarc.None:
			issues = append(issues, "DMARC policy is 'none' (monitoring only)")
		case dmarc.Quarantine:
			issues = append(issues, "DMARC policy is 'quarantine' (not reject)")
		}
		if r.Testing && requested != dmarc.None {
			issues = append(issues, "DMARC policy is in testing mode (t=y), so receivers apply it one level lower")
		}
		for _, tag := range []string{"p", "sp", "np"} {
			if slices.Contains(r.Invalid, tag) && (tag != "p" || r.P == "") {
				issues = append(issues, "DMARC "+tag+"= tag has an invalid value, so receivers treat the record as p=none")
			}
		}

		hasReporting = len(r.RUA) > 0
		if !hasReporting {
			issues = append(issues, "No DMARC aggregate reporting (rua) configured")
		}
		if len(r.BadRUA) > 0 {
			issues = append(issues, "DMARC rua has an address that is not a URI, such as one without mailto:")
		}

		if dmarcRecord.SubdomainPolicy != "reject" {
			issues = append(issues, "Subdomain policy is not 'reject'")
		}
	}

	// Check DKIM (note: only common selectors are checked, custom selectors may exist)
	hasValidDKIM := false
	if len(result.DKIM) == 0 {
		issues = append(issues, "No DKIM records found for common selectors (custom selectors not checked)")
	} else {
		for _, dkim := range result.DKIM {
			if dkim.Valid {
				hasValidDKIM = true
				break
			}
		}
		if !hasValidDKIM {
			issues = append(issues, "No valid DKIM records (all keys are malformed or revoked)")
		}
	}

	var assessment Assessment
	if result.DMARC.Read {
		assessment.Enforced, assessment.HasReporting = new(enforced), new(hasReporting)
	}
	// A selector whose lookup failed could only add keys, so a valid key
	// already read settles the DKIM check.
	if result.SPF.Read && result.DMARC.Read && (dkimComplete || hasValidDKIM) {
		assessment.Issues = issues
	}
	return assessment
}

// tally counts the domains a summary value covers: those it holds for, and
// those whose lookups failed, with the first failure.
type tally struct {
	holds, unread int
	err           error
}

// add counts one domain. A domain the value holds for counts even when one of
// its lookups failed, as when one DKIM selector failed and another returned a
// record.
func (t *tally) add(holds bool, err error) {
	switch {
	case holds:
		t.holds++
	case err != nil:
		t.unread++
		t.err = cmp.Or(t.err, err)
	}
}

// summarize rolls the domains up. A value is left out, with a partial gap,
// when a lookup it depends on failed for any domain.
func (s *scanner) summarize(scans []domainScan) Summary {
	total := len(scans)
	summary := Summary{
		TotalDomains: total,
	}

	if total == 0 {
		return summary
	}

	var withMX, withSPF, withDMARC, withDKIM, withAllThree, enforced, withReporting tally
	for _, d := range scans {
		r := d.result
		hasMX, hasSPF, hasDMARC := len(r.MX) > 0, r.SPF.Record != nil, r.DMARC.Record != nil
		withMX.add(hasMX, d.mx)
		withSPF.add(hasSPF, d.spf)
		withDMARC.add(hasDMARC, d.dmarc)
		withDKIM.add(len(r.DKIM) > 0, d.dkim)
		withAllThree.add(hasMX && hasSPF && hasDMARC, cmp.Or(d.mx, d.spf, d.dmarc))
		enforced.add(r.Assessment.Enforced != nil && *r.Assessment.Enforced, d.dmarc)
		withReporting.add(r.Assessment.HasReporting != nil && *r.Assessment.HasReporting, d.dmarc)
	}

	summary.WithMxCount, summary.WithMxPct = s.share("with_mx", withMX, total)
	summary.WithSpfCount, summary.WithSpfPct = s.share("with_spf", withSPF, total)
	summary.WithDmarcCount, summary.WithDmarcPct = s.share("with_dmarc", withDMARC, total)
	summary.WithDkimCount, summary.WithDkimPct = s.share("with_dkim", withDKIM, total)
	summary.WithAllThreeCount, summary.WithAllThreePct = s.share("with_all_three", withAllThree, total)
	summary.EnforcedCount, summary.EnforcedPct = s.share("enforced", enforced, total)
	summary.WithReportingCount, summary.WithReportingPct = s.share("with_reporting", withReporting, total)
	if enforced.unread > 0 {
		s.rec.Partial(summaryAt("all_enforced"), enforced.unread, enforced.err)
	} else {
		summary.AllEnforced = new(enforced.holds == total)
	}

	return summary
}

// share returns how many domains t holds for and that count's percentage of
// all domains, rounded down. Both are nil, each with a partial gap at the
// summary's name_count and name_pct, when some domains could not be read.
func (s *scanner) share(name string, t tally, total int) (count, pct *int) {
	s.rec.Helper()
	if t.unread > 0 {
		s.rec.Partial(summaryAt(name+"_count"), t.unread, t.err)
		s.rec.Partial(summaryAt(name+"_pct"), t.unread, t.err)
		return nil, nil
	}
	return new(t.holds), new(t.holds * 100 / total)
}

func computeDiagnostics(domains []DomainResult) *Diagnostics {
	var domainErrors []string

	for _, d := range domains {
		for _, err := range d.Errors {
			domainErrors = append(domainErrors, d.Domain+": "+err)
		}
	}

	if len(domainErrors) == 0 {
		return nil
	}

	return &Diagnostics{
		DomainErrors: domainErrors,
	}
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// isDKIMRecord reports whether a TXT record is a DKIM key record.
func isDKIMRecord(record string) bool {
	_, ok := dkimPublicKey(record)
	return ok
}

// dkimPublicKey returns the value of a DKIM key record's p tag, and reports
// false for a TXT record that is not a key record. RFC 6376 section 3.6.1
// requires the p tag. A v tag must come first and be exactly DKIM1 when it
// is present. Section 3.2 makes tag names case-sensitive, so P is not the p
// tag.
func dkimPublicKey(record string) (string, bool) {
	key, hasKey := "", false
	for i, tag := range dkimTags(record) {
		switch tag.name {
		case "v":
			if i > 0 || tag.value != "DKIM1" {
				return "", false
			}
		case "p":
			if !hasKey {
				key, hasKey = tag.value, true
			}
		}
	}
	return key, hasKey
}

// repeatsTag reports whether a DKIM key record has a tag name more than
// once.
func repeatsTag(record string) bool {
	seen := map[string]bool{}
	for _, tag := range dkimTags(record) {
		if seen[tag.name] {
			return true
		}
		seen[tag.name] = true
	}
	return false
}

// dkimTag is one tag of a DKIM key record, with its name as written.
type dkimTag struct{ name, value string }

// dkimTags splits a DKIM key record into tag=value pairs, as RFC 6376
// section 3.2 says. Semicolons separate the pairs, and whitespace around the
// equals sign and the value is not part of either. A part with no equals
// sign is skipped.
func dkimTags(record string) []dkimTag {
	var tags []dkimTag
	for _, part := range strings.Split(record, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		tags = append(tags, dkimTag{strings.TrimSpace(name), strings.TrimSpace(value)})
	}
	return tags
}
