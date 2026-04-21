# Examples

## Basic Usage

### Single Domain

```yaml
stream: myorg/email-dns-posture

collectors:
  email-dns:
    source: locktivity/epack-collector-email-dns@^0.1
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
    source: locktivity/epack-collector-email-dns@^0.1
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
    source: locktivity/epack-collector-email-dns@^0.1
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
          "has_reporting": true
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
      "with_mx": 1,
      "with_spf": 2,
      "with_dmarc": 2,
      "with_dkim": 1,
      "with_all_three": 1,
      "error_count": 0,
      "enforced": 2,
      "with_reporting": 1,
      "all_enforced": true,
      "enforced_pct": 100,
      "with_reporting_pct": 50
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
| `all_enforced` | `true` only if ALL domains have `p=reject` |
| `enforced_pct` | Percentage of domains with enforcement |
| `with_reporting_pct` | Percentage with aggregate reporting |

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
