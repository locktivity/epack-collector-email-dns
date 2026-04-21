//go:build e2e

package collector

import (
	"context"
	"os"
	"testing"
	"time"
)

// testDomain returns the domain to use for e2e tests.
// Override with E2E_TEST_DOMAIN environment variable.
// NOTE: The test domain must have proper email security configured:
//   - MX records
//   - Valid SPF record
//   - DMARC with p=reject and rua (aggregate reporting)
//   - DKIM records for common selectors
func testDomain() string {
	if d := os.Getenv("E2E_TEST_DOMAIN"); d != "" {
		return d
	}
	return "locktivity.com"
}

// TestE2E_LiveDNS tests against real DNS records.
// Run with: go test -tags e2e -v ./internal/collector/
// Override domain with: E2E_TEST_DOMAIN=yourdomain.com go test -tags e2e -v ./internal/collector/
// The test domain must have MX, SPF, DMARC (p=reject with rua), and DKIM configured.
func TestE2E_LiveDNS(t *testing.T) {
	domain := testDomain()
	cfg := Config{
		Domains: []string{
			domain,
			"doesntexist." + domain,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	posture, err := Collect(ctx, cfg)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Verify we got results for both domains
	if len(posture.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(posture.Domains))
	}

	// Find the primary domain result
	var primary *DomainResult
	for i := range posture.Domains {
		if posture.Domains[i].Domain == domain {
			primary = &posture.Domains[i]
			break
		}
	}

	if primary == nil {
		t.Fatalf("%s not found in results", domain)
	}

	// Primary domain should have MX records
	if len(primary.MX) == 0 {
		t.Errorf("%s: expected MX records", domain)
	}

	// Primary domain should have SPF
	if primary.SPF == nil {
		t.Errorf("%s: expected SPF record", domain)
	} else if !primary.SPF.Valid {
		t.Errorf("%s: SPF record should be valid", domain)
	}

	// Primary domain should have DMARC with p=reject
	if primary.DMARC == nil {
		t.Errorf("%s: expected DMARC record", domain)
	} else {
		if primary.DMARC.Policy != "reject" {
			t.Errorf("%s: DMARC policy = %q, want reject", domain, primary.DMARC.Policy)
		}
		if !primary.Assessment.Enforced {
			t.Errorf("%s: expected assessment.enforced = true", domain)
		}
		if !primary.Assessment.HasReporting {
			t.Errorf("%s: expected assessment.has_reporting = true", domain)
		}
	}

	// Primary domain should have DKIM
	if len(primary.DKIM) == 0 {
		t.Errorf("%s: expected DKIM records", domain)
	}

	// Verify summary statistics
	if posture.Summary.TotalDomains != 2 {
		t.Errorf("Summary.TotalDomains = %d, want 2", posture.Summary.TotalDomains)
	}

	// At least primary domain should be enforced (50% = 1 of 2)
	if posture.Summary.EnforcedPct < 50 {
		t.Errorf("Summary.EnforcedPct = %d, want >= 50", posture.Summary.EnforcedPct)
	}

	t.Logf("Summary: %+v", posture.Summary)
}

// TestE2E_ProgressCallbacks verifies progress callbacks are invoked.
func TestE2E_ProgressCallbacks(t *testing.T) {
	domain := testDomain()
	var statusCalls []string
	var progressCalls []struct{ current, total int64 }

	cfg := Config{
		Domains: []string{domain},
		OnStatus: func(s string) {
			statusCalls = append(statusCalls, s)
		},
		OnProgress: func(current int64, total int64, message string) {
			progressCalls = append(progressCalls, struct{ current, total int64 }{current, total})
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := Collect(ctx, cfg)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(statusCalls) == 0 {
		t.Error("Expected OnStatus to be called")
	}

	if len(progressCalls) == 0 {
		t.Error("Expected OnProgress to be called")
	}

	// Should have progress call for completion (1/1 and final)
	lastProgress := progressCalls[len(progressCalls)-1]
	if lastProgress.current != lastProgress.total {
		t.Errorf("Final progress should be complete: got %d/%d", lastProgress.current, lastProgress.total)
	}
}
