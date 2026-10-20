package collector

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
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
		scans[i].result = DomainResult{Domain: domain, Errors: []string{}}
	}

	s.step(ctx, stepMX, "Mail servers", scans, func(ctx context.Context, d *domainScan) {
		d.mx = s.collectMX(ctx, d.result.Domain, &d.result)
	})
	s.step(ctx, stepSPF, "SPF records", scans, func(ctx context.Context, d *domainScan) {
		d.spf = s.collectSPF(ctx, d.result.Domain, &d.result)
	})
	s.step(ctx, stepDMARC, "DMARC policies", scans, func(ctx context.Context, d *domainScan) {
		d.dmarc = s.collectDMARC(ctx, d.result.Domain, &d.result)
	})
	s.step(ctx, stepDKIM, "DKIM keys at common selectors", scans, func(ctx context.Context, d *domainScan) {
		d.dkimUnread, d.dkim = s.collectDKIM(ctx, d.result.Domain, &d.result)
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
// record could not be read.
type domainScan struct {
	result               DomainResult
	mx, spf, dmarc, dkim error
	dkimUnread           int
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
		if isSPFRecord(txt) {
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

func (s *scanner) collectDMARC(ctx context.Context, domain string, result *DomainResult) error {
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := s.resolver.LookupTXT(named(ctx, opDMARC), dmarcDomain)
	if err != nil && !isNotFound(err) {
		result.Errors = append(result.Errors, "DMARC lookup failed: "+err.Error())
		return err
	}
	result.DMARC.Read = true

	var dmarcRecords []string
	for _, txt := range txtRecords {
		if isDMARCRecord(txt) {
			dmarcRecords = append(dmarcRecords, txt)
		}
	}

	if len(dmarcRecords) == 0 {
		return nil
	}

	// Multiple DMARC records is an invalid configuration per RFC 7489
	if len(dmarcRecords) > 1 {
		dmarc := parseDMARC(dmarcRecords[0])
		dmarc.Valid = false
		result.DMARC.Record = dmarc
		result.Errors = append(result.Errors, "Multiple DMARC records found (invalid per RFC 7489)")
		return nil
	}

	result.DMARC.Record = parseDMARC(dmarcRecords[0])
	return nil
}

func parseDMARC(record string) *DMARCRecord {
	dmarc := &DMARCRecord{
		Record: record,
		Pct:    100, // Default per RFC
		Valid:  validateDMARC(record),
	}

	parts := strings.Split(record, ";")
	for _, part := range parts {
		key, value := parseDMARCTag(part)

		switch key {
		case "p":
			policy := strings.ToLower(value)
			if policy == "none" || policy == "quarantine" || policy == "reject" {
				dmarc.Policy = policy
			} else {
				dmarc.Policy = "unknown"
			}

		case "sp":
			sp := strings.ToLower(value)
			if sp == "none" || sp == "quarantine" || sp == "reject" {
				dmarc.SubdomainPolicy = sp
			}

		case "pct":
			if pct, err := strconv.Atoi(value); err == nil && pct >= 0 && pct <= 100 {
				dmarc.Pct = pct
			}

		case "rua":
			// Value already trimmed by parseDMARCTag, preserves original case
			dmarc.RUA = value

		case "ruf":
			dmarc.RUF = value
		}
	}

	// If no subdomain policy, it inherits from main policy
	if dmarc.SubdomainPolicy == "" {
		dmarc.SubdomainPolicy = dmarc.Policy
	}

	return dmarc
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

func validateSPF(record string) bool {
	// Must be a valid SPF record (exact version match)
	if !isSPFRecord(record) {
		return false
	}
	lower := strings.ToLower(record)

	// SPF mechanisms are space-separated tokens after v=spf1
	// Valid mechanisms: all, include:, a, a:, a/, mx, mx:, mx/, ip4:, ip6:, exists:, redirect=, ptr, ptr:
	// Unknown modifiers (name=value where name starts with alpha) are allowed per RFC 7208 §12
	parts := strings.Fields(lower)
	if len(parts) < 2 {
		return false // Just "v=spf1" with no mechanisms
	}

	hasValidMechanism := false
	for _, part := range parts[1:] { // Skip v=spf1
		// Remove qualifier prefix if present (+, -, ~, ?)
		mechanism := strings.TrimLeft(part, "+-~?")

		// Check for known mechanisms
		isKnownMechanism := mechanism == "all" ||
			mechanism == "a" ||
			mechanism == "mx" ||
			mechanism == "ptr" ||
			strings.HasPrefix(mechanism, "include:") ||
			strings.HasPrefix(mechanism, "a:") ||
			strings.HasPrefix(mechanism, "a/") ||
			strings.HasPrefix(mechanism, "mx:") ||
			strings.HasPrefix(mechanism, "mx/") ||
			strings.HasPrefix(mechanism, "ip4:") ||
			strings.HasPrefix(mechanism, "ip6:") ||
			strings.HasPrefix(mechanism, "exists:") ||
			strings.HasPrefix(mechanism, "redirect=") ||
			strings.HasPrefix(mechanism, "ptr:") ||
			strings.HasPrefix(mechanism, "exp=")

		// Check for unknown modifier: name=value where name starts with alpha
		// Per RFC 7208 §12: unknown-modifier = name "=" macro-string
		// name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
		isUnknownModifier := false
		if strings.Contains(mechanism, "=") {
			eqIdx := strings.Index(mechanism, "=")
			name := mechanism[:eqIdx]
			if len(name) > 0 && isAlpha(name[0]) && isValidSPFName(name) {
				isUnknownModifier = true
			}
		}

		if isKnownMechanism {
			hasValidMechanism = true
		} else if !isUnknownModifier {
			// Invalid term (not a known mechanism and not an unknown modifier)
			return false
		}
		// Unknown modifiers are valid but don't count as mechanisms
	}
	return hasValidMechanism
}

// isAlpha returns true if c is an ASCII letter.
func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isDigit returns true if c is an ASCII digit.
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isValidSPFName checks if s is a valid SPF name per RFC 7208 §12.
// name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
func isValidSPFName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlpha(c) && !isDigit(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func validateDMARC(record string) bool {
	// Must be a valid DMARC record (exact version match)
	if !isDMARCRecord(record) {
		return false
	}
	// Parse all tags and validate p= value (sp= is optional and invalid values are ignored per receiver behavior)
	parts := strings.Split(record, ";")
	for _, part := range parts {
		key, value := parseDMARCTag(part)
		if key == "p" {
			policy := strings.ToLower(value)
			// Only valid policy values per RFC 7489
			return policy == "none" || policy == "quarantine" || policy == "reject"
		}
	}
	return false
}

// hasInvalidSP checks if a DMARC record contains an sp= tag with an invalid value.
// Returns true if sp= is present but not one of: none, quarantine, reject.
// Handles optional whitespace around "=" per RFC 7489 ABNF.
func hasInvalidSP(record string) bool {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		key, value := parseDMARCTag(part)
		if key == "sp" {
			sp := strings.ToLower(value)
			if sp != "none" && sp != "quarantine" && sp != "reject" {
				return true
			}
		}
	}
	return false
}

func validateDKIM(record string) bool {
	// Must be a valid DKIM record and contain a non-empty public key
	if !isDKIMRecord(record) {
		return false
	}
	// Check for non-empty p= value
	lower := strings.ToLower(record)
	parts := strings.Split(lower, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			key := strings.TrimPrefix(part, "p=")
			key = strings.TrimSpace(key)
			return key != "" // Non-empty key
		}
	}
	return false
}

// computeAssessment evaluates the records it was given and leaves out what a
// failed lookup leaves undecided. dkimComplete says whether every DKIM
// selector's lookup answered.
func computeAssessment(result *DomainResult, dkimComplete bool) Assessment {
	spf, dmarc := result.SPF.Record, result.DMARC.Record
	enforced, hasReporting := false, false
	issues := []string{}

	// Check SPF
	if spf == nil {
		issues = append(issues, "No SPF record")
	} else if !spf.Valid {
		issues = append(issues, "Invalid SPF record")
	}

	// Check DMARC
	if dmarc == nil {
		issues = append(issues, "No DMARC record")
	} else if !dmarc.Valid {
		issues = append(issues, "Invalid DMARC record")
	} else {
		if dmarc.Policy == "reject" && dmarc.Pct == 100 {
			enforced = true
		} else if dmarc.Policy == "none" {
			issues = append(issues, "DMARC policy is 'none' (monitoring only)")
		} else if dmarc.Policy == "quarantine" {
			issues = append(issues, "DMARC policy is 'quarantine' (not reject)")
		} else if dmarc.Pct < 100 {
			issues = append(issues, "DMARC pct is less than 100%")
		}

		if dmarc.RUA != "" {
			hasReporting = true
		} else {
			issues = append(issues, "No DMARC aggregate reporting (rua) configured")
		}

		if dmarc.SubdomainPolicy != "reject" {
			issues = append(issues, "Subdomain policy is not 'reject'")
		}

		// Check for invalid sp= value (record is still valid, but sp= is malformed)
		if hasInvalidSP(dmarc.Record) {
			issues = append(issues, "DMARC sp= tag has invalid value (ignored, using p= for subdomains)")
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

// isSPFRecord checks if a TXT record is a valid SPF record (exact v=spf1 version).
func isSPFRecord(record string) bool {
	lower := strings.ToLower(record)
	// Must be exactly "v=spf1" followed by space or end of string
	if lower == "v=spf1" {
		return true
	}
	return strings.HasPrefix(lower, "v=spf1 ")
}

// parseDMARCTag parses a DMARC tag and returns the key and value.
// Handles optional whitespace around "=" per RFC 7489 ABNF.
func parseDMARCTag(tag string) (key, value string) {
	tag = strings.TrimSpace(tag)
	idx := strings.Index(tag, "=")
	if idx == -1 {
		return "", ""
	}
	key = strings.TrimSpace(tag[:idx])
	value = strings.TrimSpace(tag[idx+1:])
	return strings.ToLower(key), value
}

// isDMARCRecord checks if a TXT record is a valid DMARC record (exact v=DMARC1 version).
// Per RFC 7489 §6.4, the v= tag must be the first tag.
// Handles optional whitespace around "=" per RFC 7489 ABNF.
func isDMARCRecord(record string) bool {
	parts := strings.SplitN(record, ";", 2)
	if len(parts) == 0 {
		return false
	}
	key, value := parseDMARCTag(parts[0])
	// v= must be first tag with value "dmarc1" (case-insensitive)
	return key == "v" && strings.ToLower(value) == "dmarc1"
}

// isDKIMRecord checks if a TXT record is a valid DKIM record.
// Per RFC 6376 §3.6.1, if v= is present it MUST be the first tag.
// The record must also contain a p= tag.
func isDKIMRecord(record string) bool {
	lower := strings.ToLower(record)
	parts := strings.Split(lower, ";")

	hasKey := false
	versionTagPosition := -1

	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "v=dkim1" || strings.HasPrefix(part, "v=dkim1 ") {
			versionTagPosition = i
		}
		if strings.HasPrefix(part, "p=") {
			hasKey = true
		}
	}

	// Must have a p= tag
	if !hasKey {
		return false
	}

	// If v= tag is present, it must be the first tag (RFC 6376 §3.6.1)
	if versionTagPosition > 0 {
		return false // v= exists but not first
	}

	// If there's a v= tag that's not v=dkim1, it's not a DKIM record
	if versionTagPosition == -1 && strings.Contains(lower, "v=") {
		// Check if there's any other v= tag
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "v=") && part != "v=dkim1" && !strings.HasPrefix(part, "v=dkim1 ") {
				return false
			}
		}
	}

	return true
}
