# sbomify GitHub Action

[![sbomified](https://sbomify.com/assets/images/logo/badge.svg)](https://app.sbomify.com/public/component/Gu9wem8mkX)
[![CI/CD Pipeline](https://github.com/sbomify/github-action/actions/workflows/sbomify.yaml/badge.svg)](https://github.com/sbomify/github-action/actions/workflows/sbomify.yaml)

Generate, augment, enrich, and manage SBOMs in your CI/CD pipeline. Works standalone or with [sbomify](https://sbomify.com).

**Platform agnostic**: Despite the name, this runs anywhere—GitHub Actions, GitLab CI, Bitbucket Pipelines, or any Docker-capable environment. See [examples below](#other-cicd-platforms).

**Why generate SBOMs in CI/CD?** Generating SBOMs at build time enables cryptographic signing and attestation, creating a verifiable chain of trust from source to artifact. Learn more about the [SBOM lifecycle](https://sbomify.com/features/generate-collaborate-analyze/).

## Quick Start

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    ENRICH: true
```

That's it! This generates an SBOM from your lockfile and enriches it with metadata from package registries.

## Features

- **Generate** SBOMs from lockfiles (Python, Node, Rust, Go, Ruby, Dart, C++)
- **Generate** SBOMs from Docker images
- **Inject** additional packages not in lockfiles (vendored code, runtime deps, system libraries)
- **Augment** with business metadata (supplier, authors, licenses, lifecycle phase) from config file or sbomify
- **Enrich** with package metadata from PyPI, pub.dev, npm, Maven, deps.dev, and more
- **Upload** to sbomify for collaboration and vulnerability management
- **Tag** SBOMs with product releases
- **Attest** with GitHub's build provenance

## Usage Examples

### Standalone (no sbomify account needed)

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: poetry.lock
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    COMPONENT_NAME: my-app
    COMPONENT_VERSION: ${{ github.ref_name }}
    ENRICH: true
```

### Standalone with Augmentation

Add business metadata without a sbomify account using a local config file:

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    AUGMENT: true  # Uses sbomify.json in project root
    ENRICH: true
```

See [Augmentation Config File](#augmentation-config-file) for the config format.

### With sbomify

```yaml
- uses: sbomify/github-action@master
  env:
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: your-component-id
    LOCK_FILE: requirements.txt
    AUGMENT: true
    ENRICH: true
```

### Self-Hosted sbomify

```yaml
- uses: sbomify/github-action@master
  env:
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: your-component-id
    API_BASE_URL: https://sbomify.yourcompany.com
    LOCK_FILE: requirements.txt
    AUGMENT: true
    ENRICH: true
```

### Docker Image

```yaml
- uses: sbomify/github-action@master
  env:
    DOCKER_IMAGE: my-app:latest
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    ENRICH: true
```

### With Attestation

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: Cargo.lock
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: false
    ENRICH: true

- uses: actions/attest-build-provenance@v1
  with:
    subject-path: sbom.cdx.json
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `LOCK_FILE` | † | Path to lockfile (requirements.txt, poetry.lock, Cargo.lock, etc.) |
| `SBOM_FILE` | † | Path to existing SBOM file |
| `DOCKER_IMAGE` | † | Docker image name |
| `OUTPUT_FILE` | No | Write final SBOM to this path |
| `ENRICH` | No | Add metadata from package registries |
| `TOKEN` | ‡ | sbomify API token |
| `COMPONENT_ID` | ‡ | sbomify component ID |
| `AUGMENT` | No | Add metadata from sbomify |
| `COMPONENT_NAME` | No | Override component name in SBOM |
| `COMPONENT_VERSION` | No | Override component version in SBOM |
| `PRODUCT_RELEASE` | No | Tag SBOM with releases: `'["product_id:v1.0.0"]'` |
| `UPLOAD` | No | Upload SBOM (default: true) |
| `UPLOAD_DESTINATIONS` | No | Comma-separated destinations: `sbomify`, `dependency-track` (default: `sbomify`) |
| `API_BASE_URL` | No | Override sbomify API URL for self-hosted instances |
| `ADDITIONAL_PACKAGES_FILE` | No | Custom path to additional packages file |
| `ADDITIONAL_PACKAGES` | No | Inline PURLs to inject (comma or newline separated) |

† **One** of `LOCK_FILE`, `SBOM_FILE`, or `DOCKER_IMAGE` is required (pick one)
‡ Required when uploading to sbomify or using sbomify features (`AUGMENT`, `PRODUCT_RELEASE`)

### Dependency Track Configuration

When uploading to Dependency Track (`UPLOAD_DESTINATIONS=dependency-track`), configure with `DTRACK_*` prefixed environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `DTRACK_API_KEY` | Yes | Dependency Track API key |
| `DTRACK_API_URL` | Yes | Full API base URL (e.g., `https://dtrack.example.com/api`) |
| `DTRACK_PROJECT_ID` | § | Project UUID (alternative to using `COMPONENT_NAME`/`COMPONENT_VERSION`) |
| `DTRACK_AUTO_CREATE` | No | Auto-create project if it doesn't exist (default: false) |

§ Either `DTRACK_PROJECT_ID` **or** both `COMPONENT_NAME` and `COMPONENT_VERSION` are required

> **Note**: Dependency Track only supports **CycloneDX** format (not SPDX). It uses the global `COMPONENT_NAME` and `COMPONENT_VERSION` for project identification.

#### Dependency Track Example

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: true
    UPLOAD_DESTINATIONS: dependency-track
    COMPONENT_NAME: my-app
    COMPONENT_VERSION: ${{ github.ref_name }}
    DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
    DTRACK_API_URL: https://dtrack.example.com/api
    DTRACK_AUTO_CREATE: true
    ENRICH: true
```

#### Upload to Multiple Destinations

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: true
    UPLOAD_DESTINATIONS: sbomify,dependency-track
    # Component metadata (used by both sbomify and Dependency Track)
    COMPONENT_NAME: my-app
    COMPONENT_VERSION: ${{ github.ref_name }}
    # sbomify config
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: your-component-id
    # Dependency Track config
    DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
    DTRACK_API_URL: https://dtrack.example.com/api
    DTRACK_AUTO_CREATE: true
    ENRICH: true
```

## Supported Lockfiles

| Language | Files |
|----------|-------|
| Python | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pyproject.toml` |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile` |
| Go | `go.mod`, `go.sum` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.json`, `composer.lock` |
| .NET/C# | `packages.lock.json` |
| Swift | `Package.swift`, `Package.resolved` |
| Dart | `pubspec.lock` |
| Elixir | `mix.lock` |
| Scala | `build.sbt` |
| C++ | `conan.lock` |
| Terraform | `.terraform.lock.hcl` |

## Additional Packages

Inject packages not captured by lockfile scanning—vendored code, runtime dependencies, or system libraries.

### Convention-Based File

If `additional_packages.txt` exists in your working directory, it's automatically detected:

```txt
# additional_packages.txt
# Runtime dependencies not in lockfile
pkg:pypi/requests@2.31.0
pkg:npm/lodash@4.17.21

# System libraries
pkg:deb/debian/openssl@3.0.11
```

**File format:**

- One [PURL](https://github.com/package-url/purl-spec) per line
- Lines starting with `#` are comments
- Empty lines are ignored

### Custom File Location

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: requirements.txt
    ADDITIONAL_PACKAGES_FILE: .sbomify/extra-packages.txt
```

### Inline Packages

For dynamic or programmatic use:

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: requirements.txt
    ADDITIONAL_PACKAGES: "pkg:pypi/requests@2.31.0,pkg:npm/lodash@4.17.21"
```

### Build-Time Injection

Append packages across multiple steps:

```yaml
- name: Add Python runtime deps
  run: echo "pkg:pypi/requests@2.31.0" >> additional_packages.txt

- name: Add system libraries
  run: |
    echo "pkg:deb/debian/openssl@3.0.11" >> additional_packages.txt
    echo "pkg:deb/debian/libssl3@3.0.11" >> additional_packages.txt

- name: Generate SBOM
  uses: sbomify/github-action@master
  env:
    LOCK_FILE: requirements.txt
    # No additional config needed - file is auto-detected
```

**Merge behavior:** If both file and inline packages are provided, they are merged and deduplicated. Injected packages flow through augmentation and enrichment like any other component.

## Other CI/CD Platforms

### GitLab

```yaml
generate-sbom:
  image: sbomifyhub/sbomify-action
  variables:
    LOCK_FILE: poetry.lock
    OUTPUT_FILE: sbom.cdx.json
    UPLOAD: "false"
    ENRICH: "true"
  script:
    - /sbomify.sh
```

### Bitbucket

```yaml
pipelines:
  default:
    - step:
        script:
          - pipe: docker://sbomifyhub/sbomify-action:latest
            variables:
              LOCK_FILE: poetry.lock
              OUTPUT_FILE: sbom.cdx.json
              UPLOAD: "false"
              ENRICH: "true"
```

### Docker

```bash
docker run --rm -v $(pwd):/code \
  -e LOCK_FILE=/code/requirements.txt \
  -e OUTPUT_FILE=/code/sbom.cdx.json \
  -e UPLOAD=false \
  sbomifyhub/sbomify-action
```

## Augmentation vs Enrichment

**Augmentation** (`AUGMENT=true`) adds organizational metadata to your SBOM—supplier info, authors, licenses, and lifecycle phase. This addresses [NTIA Minimum Elements](https://sbomify.com/compliance/ntia-minimum-elements/) and [CISA 2025](https://sbomify.com/compliance/cisa-minimum-elements/) requirements.

Augmentation sources (in priority order):

1. **Local config file** (`sbomify.json`) — No account needed. Local values take precedence.
2. **sbomify API** — Fetches metadata configured in your sbomify component. Requires account.

**Enrichment** (`ENRICH=true`) fetches package metadata from public registries. No account needed.

### Augmentation Config File

Create `sbomify.json` in your project root to provide augmentation metadata:

```json
{
  "lifecycle_phase": "build",
  "supplier": {
    "name": "My Company",
    "url": ["https://example.com"],
    "contacts": [{"name": "Support", "email": "support@example.com"}]
  },
  "authors": [
    {"name": "John Doe", "email": "john@example.com"}
  ],
  "licenses": ["MIT"]
}
```

**Supported fields:**

| Field | Description | SBOM Mapping |
|-------|-------------|--------------|
| `lifecycle_phase` | Generation context (CISA 2025) | CycloneDX 1.5+: `metadata.lifecycles[].phase`; SPDX: `creationInfo.creatorComment` |
| `supplier` | Organization that supplies the component | CycloneDX: `metadata.supplier`; SPDX: `packages[].supplier` |
| `authors` | List of component authors | CycloneDX: `metadata.authors[]`; SPDX: `creationInfo.creators[]` |
| `licenses` | SPDX license identifiers | CycloneDX: `metadata.licenses[]`; SPDX: Document-level licenses |

**Valid `lifecycle_phase` values:** `design`, `pre-build`, `build`, `post-build`, `operations`, `discovery`, `decommission`

**Priority:** Local config values override sbomify API values when both are available.

### Enrichment Data Sources

| Source | Package Types | Data |
|--------|---------------|------|
| PyPI | Python | License, author, homepage |
| pub.dev | Dart | License, author, homepage, repo |
| RPM Repos | Rocky, Alma, CentOS, Fedora, Amazon Linux | License, vendor, description, homepage |
| Ubuntu APT | Ubuntu packages | Maintainer, description, homepage, download URL |
| deps.dev | Python, npm, Maven, Go, Rust, Ruby, NuGet | License, homepage, repo |
| ecosyste.ms | All major ecosystems | License, description, maintainer |
| Debian Sources | Debian packages | Maintainer, description, homepage |
| Repology | Linux distros | License, homepage |

## SBOM Quality Improvement

SBOM generators like Trivy and Syft focus on dependency detection—they produce name, version, and PURL, but typically leave metadata fields empty. sbomify queries package registries to fill in these gaps, improving license compliance and supply chain visibility.

### What's Typically Missing

Scanners detect packages but don't fetch metadata. Here's what a typical Trivy component looks like:

```json
{
  "type": "library",
  "name": "django",
  "version": "5.1",
  "purl": "pkg:pypi/django@5.1"
}
```

After sbomify enrichment, the same component includes supplier, license, and reference URLs:

```json
{
  "type": "library",
  "name": "django",
  "version": "5.1",
  "purl": "pkg:pypi/django@5.1",
  "publisher": "Django Software Foundation",
  "description": "A high-level Python web framework...",
  "licenses": [{"expression": "BSD-3-Clause"}],
  "externalReferences": [
    {"type": "website", "url": "https://www.djangoproject.com/"},
    {"type": "vcs", "url": "https://github.com/django/django"},
    {"type": "distribution", "url": "https://pypi.org/project/Django/"}
  ]
}
```

### Fields sbomify Adds

sbomify attempts to populate these fields for each component:

| Field | Description | Coverage |
|-------|-------------|----------|
| **Supplier/Publisher** | Package maintainer or organization | High for popular registries |
| **License** | SPDX license expression | High (most registries require it) |
| **Description** | Package summary | High |
| **Homepage** | Project website | Medium-High |
| **Repository** | Source code URL | Medium-High |
| **Download URL** | Registry/distribution link | High |
| **Issue Tracker** | Bug reporting URL | Medium |

**Coverage varies by ecosystem.** Popular packages on PyPI, npm, and crates.io have excellent metadata. RPM-based distros (Rocky, Alma, CentOS, Fedora, Amazon Linux) and Debian/Ubuntu have high coverage through direct repository queries. Alpine and less common registries may have partial data. sbomify queries multiple sources with fallbacks, but some fields may remain empty for obscure packages.

### Data Sources (Priority Order)

sbomify queries sources in priority order, stopping when data is found:

| Ecosystem | Primary Source | Fallback Sources |
|-----------|----------------|------------------|
| Python | PyPI API | deps.dev → ecosyste.ms |
| JavaScript | deps.dev | ecosyste.ms |
| Rust | deps.dev | ecosyste.ms |
| Go | deps.dev | ecosyste.ms |
| Ruby | deps.dev | ecosyste.ms |
| Java/Maven | deps.dev | ecosyste.ms |
| Dart | pub.dev API | ecosyste.ms |
| Debian | Debian Sources | Repology → ecosyste.ms |
| Ubuntu | Ubuntu APT | Repology → ecosyste.ms |
| Alpine | Repology | ecosyste.ms |
| Rocky/Alma/CentOS | RPM Repos | Repology → ecosyste.ms |
| Fedora | RPM Repos | Repology → ecosyste.ms |
| Amazon Linux | RPM Repos | Repology → ecosyste.ms |

### Limitations

- **Network required**: Enrichment calls external APIs during CI. Not suitable for air-gapped environments.
- **Rate limits**: APIs may rate-limit large SBOMs. sbomify uses caching and backoff, but very large dependency trees (1000+ packages) may see slower enrichment.
- **Best effort**: If a package isn't in any registry (private packages, vendored code), no metadata will be added.

> 📖 See [docs/enrichment_coverage.md](docs/enrichment_coverage.md) for detailed coverage information by ecosystem.

## SBOM Generation

sbomify uses a plugin architecture for SBOM generation, automatically selecting the best generator for each input type and ecosystem.

### Generator Selection

Generators are tried in priority order. Native tools (optimized for specific ecosystems) are preferred over generic scanners. Each tool supports different ecosystems:

| Priority | Generator | Supported Ecosystems | Output Formats |
|----------|-----------|---------------------|----------------|
| 10 | **cyclonedx-py** | Python only | CycloneDX 1.0–1.7 |
| 20 | **cdxgen** | Python, JavaScript, **Java/Gradle**, Go, Rust, Ruby, Dart, C++, PHP, .NET, Swift, Elixir, Scala, Docker images | CycloneDX 1.4–1.7 |
| 30 | **Trivy** | Python, JavaScript, Java/Gradle, Go, Rust, Ruby, C++, PHP, .NET, Docker images | CycloneDX 1.6, SPDX 2.3 |
| 35 | **Syft** | Python, JavaScript, Go, Rust, Ruby, Dart, C++, PHP, .NET, Swift, Elixir, Terraform, Docker images | CycloneDX 1.2–1.6, SPDX 2.2–2.3 |

### How It Works

1. **Python lockfiles** → cyclonedx-py (native, most accurate for Python)
2. **Java lockfiles** (pom.xml, build.gradle, gradle.lockfile) → cdxgen (best Java support)
3. **Dart lockfiles** (pubspec.lock) → cdxgen or Syft (Trivy doesn't support Dart)
4. **Other lockfiles** (Cargo.lock, package-lock.json, go.mod, etc.) → cdxgen (then Trivy, then Syft as fallbacks)
5. **Docker images** → cdxgen (then Trivy, then Syft as fallbacks)

If the primary generator fails or doesn't support the input, the next one in priority order is tried automatically.

### Format Defaults

- **CycloneDX**: Version 1.6 (default)
- **SPDX**: Version 2.3 (default)

Generated SBOMs are validated against their JSON schemas before output.

## Format Support

- **CycloneDX**: 1.3, 1.4, 1.5, 1.6, 1.7 (JSON)
- **SPDX**: 2.2, 2.3 (JSON)

> 📖 See [docs/adr/0001-plugin-architecture.md](docs/adr/0001-plugin-architecture.md) for architecture details.

## Links

- [Documentation](https://sbomify.com/features/generate-collaborate-analyze/)
- [sbomify Platform](https://sbomify.com)
- [Attestation Guide](https://sbomify.com/2024/10/31/github-action-update-and-attestation/)
- [Architecture Decision Records (ADR)](docs/adr/)

## License

Apache-2.0
