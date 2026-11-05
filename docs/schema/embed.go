// Package schema embeds the collector's methods for its normalized artifact
// and its trace map.
package schema

import (
	_ "embed"
	"encoding/json"
)

// methods is methods.json: for each field of the evidencepack/email-dns@v1 artifact that
// the collector measures, one plain sentence on how it measures it.
//
//go:embed methods.json
var methods []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifact to the lookups and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Methods returns the sentences in methods.json for
// componentsdk.CollectorSpec.Methods. The SDK writes each one as the
// x-epack-method of its field in the SDK's own evidencepack/email-dns@v1 schema.
func Methods() map[string]map[string]string {
	var byField map[string]string
	if err := json.Unmarshal(methods, &byField); err != nil {
		panic("docs/schema/methods.json: " + err.Error())
	}
	return map[string]map[string]string{"evidencepack/email-dns@v1": byField}
}
