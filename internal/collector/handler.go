package collector

import (
	"fmt"
	"time"

	"github.com/locktivity/epack-collector-email-dns/docs/schema"
	"github.com/locktivity/epack/componentsdk"
)

// ArtifactPath is the posture artifact's path in the pack.
const ArtifactPath = "artifacts/email-dns.json"

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        "email-dns",
		Version:     version,
		Commit:      commit,
		Description: "Collects email DNS security posture (MX, SPF, DMARC, DKIM)",
		Schemas:     schema.Schemas(),
		TraceMap:    schema.TraceMap,
		Timeout:     30 * time.Minute,
	}
}

// Run is the collector's handler. It fails only for invalid configuration,
// and otherwise emits what it collected with a gap recorded for each value a
// failed lookup left out.
func Run(ctx componentsdk.CollectorContext) error {
	domains, err := getStringSlice(ctx.Config(), "domains")
	if err != nil {
		return componentsdk.NewConfigError("domains: %v", err)
	}

	if len(domains) == 0 {
		return componentsdk.NewConfigError("domains is required")
	}

	posture := Collect(ctx.Context(), Config{
		Domains:    domains,
		Resolver:   componentsdk.NewResolver(ctx),
		Recorder:   componentsdk.Records(ctx),
		Now:        func() time.Time { return componentsdk.Now(ctx) },
		OnProgress: ctx.Progress,
	})

	return ctx.Emit([]componentsdk.CollectedArtifact{
		{
			Data:   posture,
			Path:   ArtifactPath,
			Schema: "evidencepack/email-dns@v1",
		},
	})
}

func getStringSlice(cfg map[string]any, key string) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	v, ok := cfg[key]
	if !ok {
		return nil, nil
	}
	switch val := v.(type) {
	case []string:
		return val, nil
	case []any:
		result := make([]string, 0, len(val))
		for i, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("item at index %d is %T, expected string", i, item)
			}
			result = append(result, s)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("expected array of strings, got %T", v)
	}
}
