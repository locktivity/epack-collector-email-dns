# epack-collector-email-dns

Collects email DNS security posture (SPF, DKIM, DMARC) for a list of domains.

## What it collects

- **MX Records**: Mail exchange servers for the domain
- **SPF Records**: Sender Policy Framework configuration
- **DMARC Records**: Full DMARC policy including subdomain policy, reporting URIs, and percentage
- **DKIM Records**: DomainKeys Identified Mail (checks common selectors)
- **Assessment**: Pass/fail evaluation per domain based on enforcement and reporting

See [docs/overview.md](docs/overview.md) for detailed documentation.

## Quick Start

```yaml
# epack.yaml
collectors:
  email-dns:
    source: locktivity/epack-collector-email-dns@^0.1
    config:
      domains:
        - example.com
        - company.org
```

```bash
epack collect
```

## Binary Download

Download pre-built binaries with SLSA Level 3 provenance from the [Releases](https://github.com/locktivity/epack-collector-email-dns/releases) page.

Each release includes:
- Binaries for linux/darwin on amd64/arm64
- SLSA provenance attestations (`.sigstore.json`)
- SHA256 checksums

## Development

```bash
# Build
make build

# Run tests
make test

# Lint
make lint

# SDK test (requires epack)
make sdk-test

# SDK run (requires epack)
make sdk-run
```

## Testing

```bash
# Unit tests
go test -race -v ./...

# E2E tests (requires network access)
go test -tags e2e -v ./internal/collector/
```

## Release

Releases are automated via GitHub Actions on version tags:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow:
1. Runs tests and conformance checks
2. Builds binaries for all platforms with SLSA Level 3 provenance
3. Creates a GitHub release with all artifacts

## Output Schema

The collector outputs to `artifacts/email-dns.json`. See [docs/schema/v1.0.0.json](docs/schema/v1.0.0.json) for the full JSON schema.

### Key Fields

| Field | Description |
|-------|-------------|
| `assessment.enforced` | `true` if DMARC policy is `reject` with `pct=100` |
| `assessment.has_reporting` | `true` if `rua` (aggregate reports) is configured |
| `summary.all_enforced` | `true` only if ALL domains have `p=reject` |

### Pass Criteria

For full compliance per the email authentication requirements:
- All domains must have `all_enforced: true` (DMARC `p=reject`)
- All domains should have reporting configured (`with_reporting_pct: 100`)
- SPF and DKIM should be present on all sending domains

## Documentation

- [Overview](docs/overview.md) - What it collects and how it works
- [Configuration](docs/configuration.md) - Setup and options
- [Examples](docs/examples.md) - Usage examples and sample output
- [Schema](docs/schema/v1.0.0.json) - JSON schema for output

## License

Apache 2.0 - see [LICENSE](LICENSE)
