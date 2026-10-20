// email-dns-collector collects email DNS security posture for a list of domains.
package main

import (
	"github.com/locktivity/epack-collector-email-dns/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(collector.Spec(Version, Commit), collector.Run)
}
