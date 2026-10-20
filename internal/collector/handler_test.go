package collector

import (
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestRunRejectsInvalidDomains(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]any
	}{
		{"no domains", nil},
		{"empty list", map[string]any{"domains": []any{}}},
		{"not a list", map[string]any{"domains": "example.com"}},
		{"not a string", map[string]any{"domains": []any{"example.com", 42}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{Config: tt.config})
			if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
				t.Fatalf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
			}
			if res.Artifacts != nil {
				t.Errorf("emitted %d artifacts, want none", len(res.Artifacts))
			}
		})
	}
}
