# Examples

## Basic Usage

### Single Domain

```yaml
stream: myorg/email-dns-posture

collectors:
  email-dns:
    source: locktivity/epack-collector-email-dns@^0.2
    config:
      domains:
        - example.com
```

Then run:

```bash
epack collect
```

### Multiple Domains

```yaml
stream: myorg/email-dns-posture

collectors:
  email-dns:
    source: locktivity/epack-collector-email-dns@^0.2
    config:
      domains:
        - example.com
        - company.org
        - brand.io
        - marketing.example.com
```

### Including Parked Domains

Best practice is to include all domains you own, including parked domains. Parked domains should still have DMARC set to `p=reject` to prevent spoofing.

```yaml
collectors:
  email-dns:
    source: locktivity/epack-collector-email-dns@^0.2
    config:
      domains:
        - example.com           # Primary domain
        - corp.example.com      # Corporate subdomain
        - parked-domain.com     # Parked domain
        - old-brand.com         # Legacy domain
```

## Sample Output

```json
{
  "protocol_version": 1,
  "data": {
    "schema_version": "1.0.0",
    "collected_at": "2026-04-20T10:30:00Z",
    "domains": [
      {
        "domain": "example.com",
        "mx": [
          {"host": "smtp.google.com", "priority": 10}
        ],
        "spf": {
          "record": "v=spf1 include:_spf.google.com ~all",
          "valid": true
        },
        "dmarc": {
          "record": "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@example.com",
          "policy": "reject",
          "subdomain_policy": "reject",
          "pct": 100,
          "rua": "mailto:dmarc@example.com",
          "valid": true
        },
        "dkim": [
          {"selector": "google", "record": "v=DKIM1; k=rsa; p=...", "valid": true}
        ],
        "assessment": {
          "enforced": true,
          "has_reporting": true,
          "issues": []
        }
      },
      {
        "domain": "parked-domain.com",
        "mx": [],
        "spf": {
          "record": "v=spf1 -all",
          "valid": true
        },
        "dmarc": {
          "record": "v=DMARC1; p=reject; sp=reject",
          "policy": "reject",
          "subdomain_policy": "reject",
          "pct": 100,
          "valid": true
        },
        "dkim": [],
        "assessment": {
          "enforced": true,
          "has_reporting": false,
          "issues": [
            "No DMARC aggregate reporting (rua) configured",
            "No DKIM records found for common selectors (custom selectors not checked)"
          ]
        }
      }
    ],
    "summary": {
      "total_domains": 2,
      "with_mx_count": 1,
      "with_mx_pct": 50,
      "with_spf_count": 2,
      "with_spf_pct": 100,
      "with_dmarc_count": 2,
      "with_dmarc_pct": 100,
      "with_dkim_count": 1,
      "with_dkim_pct": 50,
      "with_all_three_count": 1,
      "with_all_three_pct": 50,
      "enforced_count": 2,
      "enforced_pct": 100,
      "with_reporting_count": 1,
      "with_reporting_pct": 50,
      "all_enforced": true
    }
  }
}
```

## Understanding the Output

### Assessment

Each domain includes an `assessment` object:

| Field | Description |
|-------|-------------|
| `enforced` | `true` if DMARC policy is `reject` with `pct=100` |
| `has_reporting` | `true` if `rua` (aggregate reports) is configured |
| `issues` | List of problems found |

### Summary Metrics

| Field | Description |
|-------|-------------|
| `total_domains` | Number of domains scanned |
| `with_mx_pct` | Percentage of domains with MX records |
| `with_spf_pct` | Percentage of domains with SPF records |
| `with_dmarc_pct` | Percentage of domains with DMARC records |
| `with_dkim_pct` | Percentage of domains with DKIM records |
| `with_all_three_pct` | Percentage with MX + SPF + DMARC |
| `enforced_pct` | Percentage with DMARC `p=reject` |
| `with_reporting_pct` | Percentage with aggregate reporting (`rua`) |
| `all_enforced` | `true` only if ALL domains have `p=reject` |

Each percentage has a count beside it, such as `with_mx_count`, the number of domains it counts. The percentage is that count over `total_domains`, rounded down.

A value is absent when a lookup it depends on failed, such as a SERVFAIL or a timeout, and the collector result artifact records a gap for it. See [Partial Collection and Exit Codes](configuration.md#partial-collection-and-exit-codes).

### Pass Criteria

For full compliance with email authentication requirements:
- `all_enforced` should be `true`
- `with_reporting_pct` should be `100`
- All sending domains should have SPF and DKIM

## CI/CD Integration

### GitHub Actions

```yaml
name: Collect Evidence

on:
  schedule:
    - cron: "0 0 * * 1"  # Weekly on Monday
  workflow_dispatch:

jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install epack
        run: |
          curl -sSL https://github.com/locktivity/epack/releases/latest/download/epack-linux-amd64 -o epack
          chmod +x epack
          sudo mv epack /usr/local/bin/

      - name: Collect evidence
        run: epack collect --frozen

      - name: Upload pack
        uses: actions/upload-artifact@v4
        with:
          name: evidence-pack
          path: "*.pack"
```
