//go:build record

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// TestRecord records a sandbox, a domain whose mail records are kept with
// known settings, to testdata/recordings/email-dns.json for the
// collectortest suite. It reads the sandbox's domain from SANDBOX_DOMAIN and
// skips when it is not set. The domain becomes example.com and its first
// label example, the value of any other SANDBOX_ variable becomes a stable
// fake, and Record writes nothing if one remains. recordScrubPatterns
// replace the DKIM key, and nothing is written while unscrubbed finds
// anything:
//
//	SANDBOX_DOMAIN=sandbox.example go test -tags record -run 'TestRecord/^email-dns$' -count=1 ./internal/collector/
func TestRecord(t *testing.T) {
	t.Run("email-dns", func(t *testing.T) {
		domain := os.Getenv("SANDBOX_DOMAIN")
		if domain == "" {
			t.Skip("set SANDBOX_DOMAIN to record")
		}
		identifiers := collectortest.EnvIdentifiers("SANDBOX_", map[string]string{"SANDBOX_DOMAIN": "example.com"})
		// The first label can appear on its own, as in a report address.
		if label, _, _ := strings.Cut(domain, "."); len(label) >= 6 {
			identifiers[label] = "example"
		}
		tmp := filepath.Join(t.TempDir(), "email-dns.json")
		report, err := collectortest.Record(collectortest.RecordOptions{
			Spec: Spec("record", "collectortest"),
			Run:  Run,
			Config: map[string]any{
				"level": "audit",
				"domains": []any{
					"enforced.email." + domain,
					"monitor.email." + domain,
					"malformed.email." + domain,
					"bare.email." + domain,
				},
			},
			Out:   tmp,
			Scrub: collectortest.ScrubRules{Identifiers: identifiers, Patterns: recordScrubPatterns},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.ExitCode != 0 {
			t.Errorf("the recorded run exited %d: %+v", report.ExitCode, report.Failure)
		}
		raw, err := os.ReadFile(tmp)
		if err != nil {
			t.Fatal(err)
		}
		problems, err := unscrubbed(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) > 0 {
			t.Fatalf("the recording still holds what it must not, so nothing was written:\n%s", strings.Join(problems, "\n"))
		}
		out := filepath.Join("testdata", "recordings", "email-dns.json")
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("recorded %d DNS records", report.DNS)
	})
}
