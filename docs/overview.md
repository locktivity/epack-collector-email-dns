# Email DNS Posture Collector

The Email DNS Posture Collector gathers email security configuration from DNS records for your domains.

## What It Collects

This collector queries DNS for each configured domain and aggregates email authentication posture:

- **MX Records**: Mail exchange servers and priorities
- **SPF Records**: Sender Policy Framework configuration
- **DMARC Records**: Domain-based Message Authentication policy including:
  - Policy (none/quarantine/reject)
  - Subdomain policy
  - Percentage applied
  - Aggregate reporting URI (rua)
  - Forensic reporting URI (ruf)
- **DKIM Records**: DomainKeys Identified Mail (checks common selectors)
- **Assessment**: Per-domain pass/fail evaluation based on enforcement status

All metrics include enforcement status (whether DMARC is set to `p=reject`) and reporting configuration.

## Use Cases

- **Third-party risk assessments**: Provide evidence of email security posture to customers and auditors
- **Compliance monitoring**: Verify all sending domains have proper email authentication
- **Security benchmarking**: Track email security improvements over time
- **Gap identification**: Find domains missing SPF, DKIM, or DMARC

## How It Works

1. The collector receives a list of domains from your configuration
2. For each domain, it performs DNS lookups:
   - MX records for mail servers
   - TXT records for SPF (v=spf1)
   - TXT records at `_dmarc.domain` for DMARC
   - TXT records at `selector._domainkey.domain` for common DKIM selectors
3. Records are parsed and validated
4. Per-domain assessment is computed (enforced, has reporting, issues)
5. Summary statistics are aggregated
6. Output is wrapped in the epack collector protocol envelope

A name or record that does not exist is an answer, not a failure. A lookup that fails with SERVFAIL, a refused query, or a timeout leaves the values that depend on it out of the output, and the collector result artifact, `artifacts/email-dns.collector-result.json`, records a gap for each. See [Partial Collection and Exit Codes](configuration.md#partial-collection-and-exit-codes).

## Authentication

This collector does not require authentication - it only queries public DNS records.

See [Configuration](configuration.md) for setup instructions.
