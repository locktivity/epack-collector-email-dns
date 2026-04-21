package collector

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Common DKIM selectors to check
var commonDKIMSelectors = []string{
	"default",
	"selector1", "selector2", // Microsoft 365
	"google",                 // Google Workspace
	"k1",                     // Mailchimp
	"s1", "s2",               // Generic
	"mail",
	"dkim",
}

// Collect gathers email DNS posture for all configured domains.
func Collect(ctx context.Context, cfg Config) (*EmailDNSPosture, error) {
	posture := &EmailDNSPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   time.Now().UTC(),
		Domains:       make([]DomainResult, 0, len(cfg.Domains)),
	}

	total := len(cfg.Domains)
	for i, domain := range cfg.Domains {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if cfg.OnStatus != nil {
			cfg.OnStatus("Scanning " + domain)
		}
		if cfg.OnProgress != nil {
			cfg.OnProgress(int64(i), int64(total), "Scanning "+domain)
		}

		result := collectDomain(ctx, domain)
		posture.Domains = append(posture.Domains, result)

		// Check if context was cancelled during collection
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	if cfg.OnProgress != nil {
		cfg.OnProgress(int64(total), int64(total), "Collection complete")
	}

	posture.Summary = computeSummary(posture.Domains)
	return posture, nil
}

func collectDomain(ctx context.Context, domain string) DomainResult {
	result := DomainResult{
		Domain: domain,
		MX:     []MXRecord{},
		Errors: []string{},
	}

	// Collect MX records
	collectMX(ctx, domain, &result)

	// Collect SPF record
	collectSPF(ctx, domain, &result)

	// Collect DMARC record
	collectDMARC(ctx, domain, &result)

	// Collect DKIM records for common selectors
	collectDKIM(ctx, domain, &result)

	// Compute assessment
	result.Assessment = computeAssessment(&result)

	return result
}

func collectMX(ctx context.Context, domain string, result *DomainResult) {
	resolver := net.Resolver{}
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		if !isNotFound(err) {
			result.Errors = append(result.Errors, "MX lookup failed: "+err.Error())
		}
		return
	}

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
}

func collectSPF(ctx context.Context, domain string, result *DomainResult) {
	resolver := net.Resolver{}
	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		if !isNotFound(err) {
			result.Errors = append(result.Errors, "SPF lookup failed: "+err.Error())
		}
		return
	}

	var spfRecords []string
	for _, txt := range txtRecords {
		if isSPFRecord(txt) {
			spfRecords = append(spfRecords, txt)
		}
	}

	if len(spfRecords) == 0 {
		return
	}

	// Multiple SPF records is an invalid configuration per RFC 7208
	if len(spfRecords) > 1 {
		result.SPF = &SPFRecord{
			Record: spfRecords[0],
			Valid:  false,
		}
		result.Errors = append(result.Errors, "Multiple SPF records found (invalid per RFC 7208)")
		return
	}

	result.SPF = &SPFRecord{
		Record: spfRecords[0],
		Valid:  validateSPF(spfRecords[0]),
	}
}

func collectDMARC(ctx context.Context, domain string, result *DomainResult) {
	resolver := net.Resolver{}
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		if !isNotFound(err) {
			result.Errors = append(result.Errors, "DMARC lookup failed: "+err.Error())
		}
		return
	}

	var dmarcRecords []string
	for _, txt := range txtRecords {
		if isDMARCRecord(txt) {
			dmarcRecords = append(dmarcRecords, txt)
		}
	}

	if len(dmarcRecords) == 0 {
		return
	}

	// Multiple DMARC records is an invalid configuration per RFC 7489
	if len(dmarcRecords) > 1 {
		dmarc := parseDMARC(dmarcRecords[0])
		dmarc.Valid = false
		result.DMARC = dmarc
		result.Errors = append(result.Errors, "Multiple DMARC records found (invalid per RFC 7489)")
		return
	}

	result.DMARC = parseDMARC(dmarcRecords[0])
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

func collectDKIM(ctx context.Context, domain string, result *DomainResult) {
	resolver := net.Resolver{}

	for _, selector := range commonDKIMSelectors {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, "DKIM lookup interrupted: "+ctx.Err().Error())
			return
		default:
		}

		dkimDomain := selector + "._domainkey." + domain
		txtRecords, err := resolver.LookupTXT(ctx, dkimDomain)
		if err != nil {
			// NXDOMAIN is expected for selectors that don't exist
			if isNotFound(err) {
				continue
			}
			// Report real errors (SERVFAIL, timeout, etc.)
			result.Errors = append(result.Errors, "DKIM lookup failed for selector "+selector+": "+err.Error())
			continue
		}

		for _, txt := range txtRecords {
			if isDKIMRecord(txt) {
				result.DKIM = append(result.DKIM, DKIMRecord{
					Selector: selector,
					Record:   txt,
					Valid:    validateDKIM(txt),
				})
				break
			}
		}
	}
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

func computeAssessment(result *DomainResult) Assessment {
	assessment := Assessment{}
	var issues []string

	// Check SPF
	if result.SPF == nil {
		issues = append(issues, "No SPF record")
	} else if !result.SPF.Valid {
		issues = append(issues, "Invalid SPF record")
	}

	// Check DMARC
	if result.DMARC == nil {
		issues = append(issues, "No DMARC record")
	} else if !result.DMARC.Valid {
		issues = append(issues, "Invalid DMARC record")
	} else {
		if result.DMARC.Policy == "reject" && result.DMARC.Pct == 100 {
			assessment.Enforced = true
		} else if result.DMARC.Policy == "none" {
			issues = append(issues, "DMARC policy is 'none' (monitoring only)")
		} else if result.DMARC.Policy == "quarantine" {
			issues = append(issues, "DMARC policy is 'quarantine' (not reject)")
		} else if result.DMARC.Pct < 100 {
			issues = append(issues, "DMARC pct is less than 100%")
		}

		if result.DMARC.RUA != "" {
			assessment.HasReporting = true
		} else {
			issues = append(issues, "No DMARC aggregate reporting (rua) configured")
		}

		if result.DMARC.SubdomainPolicy != "reject" {
			issues = append(issues, "Subdomain policy is not 'reject'")
		}

		// Check for invalid sp= value (record is still valid, but sp= is malformed)
		if hasInvalidSP(result.DMARC.Record) {
			issues = append(issues, "DMARC sp= tag has invalid value (ignored, using p= for subdomains)")
		}
	}

	// Check DKIM (note: only common selectors are checked, custom selectors may exist)
	if len(result.DKIM) == 0 {
		issues = append(issues, "No DKIM records found for common selectors (custom selectors not checked)")
	} else {
		hasValidDKIM := false
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

	assessment.Issues = issues
	return assessment
}

func computeSummary(domains []DomainResult) Summary {
	summary := Summary{
		TotalDomains: len(domains),
	}

	for _, d := range domains {
		if len(d.MX) > 0 {
			summary.WithMX++
		}
		if d.SPF != nil {
			summary.WithSPF++
		}
		if d.DMARC != nil {
			summary.WithDMARC++
		}
		if len(d.DKIM) > 0 {
			summary.WithDKIM++
		}
		if len(d.MX) > 0 && d.SPF != nil && d.DMARC != nil {
			summary.WithAllThree++
		}
		summary.ErrorCount += len(d.Errors)

		// Enforcement metrics
		if d.Assessment.Enforced {
			summary.Enforced++
		}
		if d.Assessment.HasReporting {
			summary.WithReporting++
		}
	}

	// Compute percentages and all-enforced flag
	if summary.TotalDomains > 0 {
		summary.EnforcedPct = (summary.Enforced * 100) / summary.TotalDomains
		summary.WithReportingPct = (summary.WithReporting * 100) / summary.TotalDomains
		summary.AllEnforced = summary.Enforced == summary.TotalDomains
	}

	return summary
}

func isNotFound(err error) bool {
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}
	return false
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
