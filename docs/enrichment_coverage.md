# SBOM Enrichment Coverage

This document details sbomify's enrichment capabilities, data sources, and expected coverage.

## Data Sources by Ecosystem

sbomify queries multiple sources in priority order, using fallbacks when primary sources lack data.

| Ecosystem            | Primary Source | Fallbacks              |
| -------------------- | -------------- | ---------------------- |
| Python (pip)         | PyPI API       | deps.dev → ecosyste.ms |
| JavaScript (npm)     | deps.dev       | ecosyste.ms            |
| Rust (cargo)         | deps.dev       | ecosyste.ms            |
| Go (mod)             | deps.dev       | ecosyste.ms            |
| Ruby (gem)           | deps.dev       | ecosyste.ms            |
| Java/Maven           | deps.dev       | ecosyste.ms            |
| Dart (pub)           | pub.dev API    | ecosyste.ms            |
| Debian/Ubuntu (deb)  | Debian Sources | Repology → ecosyste.ms |
| Alpine (apk)         | Repology       | ecosyste.ms            |
| Red Hat/Fedora (rpm) | Repology       | ecosyste.ms            |

## Expected Field Coverage

Coverage varies by ecosystem and data source availability.

Legend: 🟢 High | 🟡 Medium | 🟠 Low

| Ecosystem            | Supplier | License | Description | Homepage | Repository |
| -------------------- | -------- | ------- | ----------- | -------- | ---------- |
| Python (pip)         | 🟢       | 🟢      | 🟢          | 🟢       | 🟢         |
| JavaScript (npm)     | 🟢       | 🟢      | 🟢          | 🟢       | 🟢         |
| Rust (cargo)         | 🟢       | 🟢      | 🟢          | 🟡       | 🟢         |
| Go (mod)             | 🟡       | 🟢      | 🟡          | 🟠       | 🟢         |
| Ruby (gem)           | 🟢       | 🟢      | 🟢          | 🟢       | 🟡         |
| Java/Maven           | 🟢       | 🟢      | 🟡          | 🟡       | 🟡         |
| Dart (pub)           | 🟢       | 🟢      | 🟢          | 🟢       | 🟢         |
| Debian/Ubuntu (deb)  | 🟢       | 🟢      | 🟢          | 🟡       | 🟠         |
| Alpine (apk)         | 🟢       | 🟢      | 🟡          | 🟡       | 🟠         |
| Red Hat/Fedora (rpm) | 🟢       | 🟢      | 🟡          | 🟡       | 🟠         |

## Ecosystem Notes

- **Python (pip)**: PyPI requires license metadata for new packages since 2023.
- **JavaScript (npm)**: npm registry has excellent metadata coverage.
- **Rust (cargo)**: crates.io requires license field.
- **Go (mod)**: Go modules are often just GitHub repos with minimal metadata.
- **Java/Maven**: Maven Central has good metadata but older artifacts may lack some fields.
- **Dart (pub)**: pub.dev has excellent metadata.
- **Debian/Ubuntu (deb)**: Debian packages have maintainer info but may lack upstream URLs.

## Example: Before and After Enrichment

### Scanner Output (Trivy)

```json
{
  "type": "library",
  "name": "django",
  "version": "5.1",
  "purl": "pkg:pypi/django@5.1"
}
```

### After sbomify Enrichment

```json
{
  "type": "library",
  "name": "django",
  "version": "5.1",
  "purl": "pkg:pypi/django@5.1",
  "publisher": "Django Software Foundation",
  "description": "A high-level Python web framework that encourages rapid development and clean, pragmatic design.",
  "licenses": [
    {
      "expression": "BSD-3-Clause"
    }
  ],
  "externalReferences": [
    {
      "type": "website",
      "url": "https://www.djangoproject.com/"
    },
    {
      "type": "vcs",
      "url": "https://github.com/django/django"
    },
    {
      "type": "distribution",
      "url": "https://pypi.org/project/Django/"
    }
  ]
}
```

## Limitations

- **Network required**: Enrichment calls external APIs during CI. Not suitable for air-gapped environments.
- **Rate limits**: Large SBOMs (1000+ packages) may experience slower enrichment due to API rate limits.
- **Best effort**: Private packages, vendored code, and obscure packages may not have registry data.
- **Data freshness**: Metadata is fetched at enrichment time. Registry data may lag behind actual releases.
- **Coverage varies**: Different ecosystems and registries have different metadata requirements and quality.

_Generated: 2025-12-17_
