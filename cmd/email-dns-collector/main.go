// email-dns-collector collects email DNS security posture for a list of domains.
package main

import (
	"fmt"

	"github.com/locktivity/epack-collector-email-dns/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "email-dns",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects email DNS security posture (MX, SPF, DMARC, DKIM)",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	domains, err := getStringSlice(cfg, "domains")
	if err != nil {
		return componentsdk.NewConfigError("domains: %v", err)
	}

	if len(domains) == 0 {
		return componentsdk.NewConfigError("domains is required")
	}

	config := collector.Config{
		Domains:    domains,
		OnStatus:   ctx.Status,
		OnProgress: ctx.Progress,
	}

	posture, err := collector.Collect(ctx.Context(), config)
	if err != nil {
		return componentsdk.NewNetworkError("collecting posture: %v", err)
	}

	return ctx.Emit([]componentsdk.CollectedArtifact{
		{
			Data: posture,
			Path: "artifacts/email-dns.json",
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
