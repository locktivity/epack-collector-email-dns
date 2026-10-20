package collector

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// placeholderDKIMKey stands in for a DKIM public key in a recording. It is
// the opening every RSA 2048-bit key shares, so it holds no key material,
// and the collector reads any key that is not empty as a key.
const placeholderDKIMKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"

// dkimKey finds the key a DKIM record publishes after p=.
var dkimKey = regexp.MustCompile(`(\bp=)([A-Za-z0-9+/]{44,}={0,2})`)

// recordScrubPatterns remove from a recording what the collector never reads
// and a public repository must not hold: the sandbox's DKIM public key,
// which passive DNS services can search by, and so find the domain.
var recordScrubPatterns = []collectortest.ScrubPattern{
	{Pattern: dkimKey, Replace: "${1}" + placeholderDKIMKey},
}

// kitFakeEmail is the form of the email addresses Record writes in place of
// real ones.
var kitFakeEmail = regexp.MustCompile(`^user[0-9]+@example\.com$`)

var recordedEmail = regexp.MustCompile(`[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

// unscrubbed lists each DNS answer in a recording file that holds what the
// record test removes: a DKIM key other than the placeholder, or an email
// address other than the kit's fakes. It names where each is, never the
// value.
func unscrubbed(raw []byte) ([]string, error) {
	var file struct {
		DNS []collectortest.DNSRecord `json:"dns"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	var problems []string
	for i, rec := range file.DNS {
		for j, v := range rec.Values {
			at := fmt.Sprintf("dns[%d].values[%d]", i, j)
			for _, m := range dkimKey.FindAllStringSubmatch(v, -1) {
				if m[2] != placeholderDKIMKey {
					problems = append(problems, at+" holds a DKIM key")
				}
			}
			for _, m := range recordedEmail.FindAllString(v, -1) {
				if !kitFakeEmail.MatchString(strings.ToLower(m)) {
					problems = append(problems, at+" holds an email address")
				}
			}
		}
	}
	return problems, nil
}

func TestRecordScrubPatterns(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	scrub := func(in string) string {
		for _, p := range recordScrubPatterns {
			in = p.Pattern.ReplaceAllString(in, p.Replace)
		}
		return in
	}

	dkim := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	if got, want := scrub(dkim), "v=DKIM1; k=rsa; p="+placeholderDKIMKey; got != want {
		t.Errorf("DKIM record scrubs to %q, want %q", got, want)
	}
	if !validateDKIM(scrub(dkim)) {
		t.Error("the scrubbed DKIM record should still read as a valid key")
	}
	for _, kept := range []string{"v=DKIM1; p=", "v=DMARC1; p=reject; rua=mailto:user1@example.com", "v=spf1 -all"} {
		if got := scrub(kept); got != kept {
			t.Errorf("the scrub changed %q to %q", kept, got)
		}
	}
}

func TestUnscrubbedFindsKeysAndAddresses(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"dns": []collectortest.DNSRecord{
		{Name: "s1._domainkey.enforced.email.example.com", Type: "TXT", Values: []string{"v=DKIM1; k=rsa; p=" + strings.Repeat("A1b2", 20)}},
		{Name: "_dmarc.enforced.email.example.com", Type: "TXT", Values: []string{"v=DMARC1; p=reject; rua=mailto:dmarc-reports@sandbox.example"}},
		{Name: "s1._domainkey.monitor.email.example.com", Type: "TXT", Values: []string{"v=DKIM1; k=rsa; p=" + placeholderDKIMKey}},
		{Name: "_dmarc.monitor.email.example.com", Type: "TXT", Values: []string{"v=DMARC1; p=reject; rua=mailto:user1@example.com"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	problems, err := unscrubbed(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"dns[0].values[0] holds a DKIM key", "dns[1].values[0] holds an email address"}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems = %q, want %q", problems, want)
	}
}

// TestRecordingsScrubbed fails while a committed recording holds what the
// record test removes.
func TestRecordingsScrubbed(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "recordings", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		problems, err := unscrubbed(raw)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, p := range problems {
			t.Errorf("%s: %s", path, p)
		}
	}
}
