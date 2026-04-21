# Configuration

## Basic Setup

The Email DNS collector queries public DNS records and does not require authentication.

```yaml
collectors:
  email-dns:
    source: locktivity/epack-collector-email-dns@^0.1
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

## Troubleshooting

**"domains is required"**

The `domains` field must be set in your config:

```yaml
config:
  domains:
    - example.com  # Required - at least one domain
```

**DNS lookup failures**

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
