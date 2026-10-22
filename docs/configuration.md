# Configuration

## Basic Setup

The Email DNS collector queries public DNS records and does not require authentication.

```yaml
collectors:
  email-dns:
    source: locktivity/epack-collector-email-dns@^0.2
    config:
      domains:
        - example.com
        - company.org
```

## Configuration Options

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `domains` | []string | Yes | - | List of email domains to scan |

## DKIM Selectors

The collector automatically checks these common DKIM selectors for each domain:

| Selector | Provider |
|----------|----------|
| `default` | Generic |
| `selector1`, `selector2` | Microsoft 365 |
| `google` | Google Workspace |
| `k1` | Mailchimp |
| `s1`, `s2` | Generic |
| `mail` | Generic |
| `dkim` | Generic |

If your organization uses custom DKIM selectors not in this list, the DKIM check may not find them. The collector reports what it finds, but absence of a DKIM record doesn't necessarily mean DKIM isn't configured.

## DNS Resolution

The collector uses the system's default DNS resolver. For consistent results across environments, ensure your DNS resolver can reach authoritative nameservers for all configured domains.

## Partial Collection and Exit Codes

A name or record that does not exist (NXDOMAIN, or a name with no record of that type) is an answer: `mx`, `dkim`, and `assessment.issues` are `[]` when empty, and `spf` and `dmarc` are `null` when the domain publishes none. Any other lookup failure, such as SERVFAIL, a refused query, or a timeout, leaves the values that depend on the lookup out of the artifact rather than reading as a missing record:

| Lookup that failed | Values left out |
|--------------------|-----------------|
| MX | The domain's `mx` |
| SPF | The domain's `spf` and `assessment.issues` |
| DMARC | The domain's `dmarc`, `assessment.enforced`, `assessment.has_reporting`, and `assessment.issues`, so `assessment` is `{}` |
| Some DKIM selectors | The domain's `assessment.issues`, unless another selector returned a valid key. `dkim` keeps the records the other selectors returned |
| Every DKIM selector | The domain's `dkim` and `assessment.issues` |

A summary value is left out when a lookup it depends on failed for any domain, so `with_spf_count` and `with_spf_pct` are absent if one domain's SPF lookup failed. A domain with a DKIM record counts toward `with_dkim_pct` even when another selector's lookup failed. A run that reaches its time limit emits what it collected, with the remaining values left out the same way.

The artifact `artifacts/email-dns.collector-result.json` lists a gap for each value left out, with its code: `vendor_error` for SERVFAIL or a refused query, and `timeout` for a timeout. A summary value's gap counts the domains left unmeasured. A `dkim` list that holds the records some selectors returned has a `partial` gap that counts the selectors whose lookups failed. The artifact also counts the lookups by operation (`dns.mx.lookup`, `dns.spf.lookup`, `dns.dmarc.lookup`, and `dns.dkim.lookup`) and response code. Each gap names the `operation` and `call` number of the lookup that failed. The per-domain `errors` and `diagnostics.domain_errors` entries remain.

| Exit | Code | When |
|------|------|------|
| 0 | | The run collected, even if some values were left out |
| 2 | `config_invalid` | `domains` is missing, empty, or not a list of strings |

## Troubleshooting

**"domains is required"**

The `domains` field must be set in your config:

```yaml
config:
  domains:
    - example.com  # Required - at least one domain
```

**DNS lookup failures**

A lookup that fails with SERVFAIL, a refused query, or a timeout never reads as a missing record. The values that depend on it are left out (see [Partial Collection and Exit Codes](#partial-collection-and-exit-codes)), and the domain's `errors` list gives the error. The run still succeeds.

If DNS lookups fail for specific domains:
- Verify the domain exists and is reachable
- Check your network's DNS resolution
- Ensure the domain's DNS servers are responding

**Missing DKIM records**

DKIM records may not be found if:
- The domain uses a custom selector not in the default list
- DKIM is not configured for the domain
- The DKIM record has been removed or is misconfigured

**DMARC policy shows "unknown"**

The DMARC policy is extracted from the `p=` tag. If parsing fails or the policy value is non-standard, it will show as "unknown".
