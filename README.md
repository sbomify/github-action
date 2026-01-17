# sbomify GitHub Action

[![sbomified](https://sbomify.com/assets/images/logo/badge.svg)](https://app.sbomify.com/public/component/Gu9wem8mkX)
[![CI/CD Pipeline](https://github.com/sbomify/github-action/actions/workflows/sbomify.yaml/badge.svg)](https://github.com/sbomify/github-action/actions/workflows/sbomify.yaml)
[![PyPI version](https://badge.fury.io/py/sbomify-action.svg)](https://pypi.org/project/sbomify-action/)
[![Slack](https://img.shields.io/badge/Slack-Join%20Community-4A154B?logo=slack)](https://join.slack.com/t/sbomify/shared_invite/zt-3na54pa1f-MXrFWhotmZr0YxXc8sABTw)

Generate, augment, enrich, and manage SBOMs in your CI/CD pipeline. Works standalone or with [sbomify](https://sbomify.com).

**Recommended**: Use the GitHub Action or Docker image—they include all SBOM generators (Trivy, Syft, cdxgen) pre-installed. For other CI platforms, see [examples below](#other-cicd-platforms). A [pip package](#pip-advanced) is also available for advanced use cases.

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

That's it! This generates a CycloneDX SBOM from your lockfile and enriches it with metadata from package registries. For SPDX format, set `SBOM_FORMAT: spdx`.

## Features

- **Generate** SBOMs from lockfiles (Python, Node, Rust, Go, Ruby, Dart, C++) in CycloneDX or SPDX format
- **Generate** SBOMs from Docker images
- **Inject** additional packages not in lockfiles (vendored code, runtime deps, system libraries)
- **Augment** with business metadata (supplier, authors, licenses, lifecycle phase) from config file or sbomify
- **VCS Auto-Detection** — Automatically adds repository URL, commit SHA, and branch info from CI environment
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

### SPDX Format

Generate SPDX instead of CycloneDX:

```yaml
- uses: sbomify/github-action@master
  env:
    LOCK_FILE: requirements.txt
    OUTPUT_FILE: sbom.spdx.json
    SBOM_FORMAT: spdx
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

| Variable                   | Required | Description                                                                      |
| -------------------------- | -------- | -------------------------------------------------------------------------------- |
| `LOCK_FILE`                | †        | Path to lockfile (requirements.txt, poetry.lock, Cargo.lock, etc.)               |
| `SBOM_FILE`                | †        | Path to existing SBOM file                                                       |
| `DOCKER_IMAGE`             | †        | Docker image name                                                                |
| `OUTPUT_FILE`              | No       | Write final SBOM to this path                                                    |
| `SBOM_FORMAT`              | No       | Output format: `cyclonedx` (default) or `spdx`                                   |
| `ENRICH`                   | No       | Add metadata from package registries                                             |
| `TOKEN`                    | ‡        | sbomify API token                                                                |
| `COMPONENT_ID`             | ‡        | sbomify component ID                                                             |
| `AUGMENT`                  | No       | Add metadata from sbomify                                                        |
| `COMPONENT_NAME`           | No       | Override component name in SBOM                                                  |
| `COMPONENT_VERSION`        | No       | Override component version in SBOM                                               |
| `COMPONENT_PURL`           | No       | Add or override component PURL in SBOM                                           |
| `PRODUCT_RELEASE`          | No       | Tag SBOM with product releases (see [Product Releases](#product-releases))       |
| `UPLOAD`                   | No       | Upload SBOM (default: true)                                                      |
| `UPLOAD_DESTINATIONS`      | No       | Comma-separated destinations: `sbomify`, `dependency-track` (default: `sbomify`) |
| `API_BASE_URL`             | No       | Override sbomify API URL for self-hosted instances                               |
| `ADDITIONAL_PACKAGES_FILE` | No       | Custom path to additional packages file                                          |
| `ADDITIONAL_PACKAGES`      | No       | Inline PURLs to inject (comma or newline separated)                              |
| `DISABLE_VCS_AUGMENTATION` | No       | Set to `true` to disable auto-detection of VCS info from CI environment          |

† **One** of `LOCK_FILE`, `SBOM_FILE`, or `DOCKER_IMAGE` is required (pick one)
‡ Required when uploading to sbomify or using sbomify features (`AUGMENT`, `PRODUCT_RELEASE`)

### Dependency Track Configuration

When uploading to Dependency Track (`UPLOAD_DESTINATIONS=dependency-track`), configure with `DTRACK_*` prefixed environment variables:

| Variable             | Required | Description                                                              |
| -------------------- | -------- | ------------------------------------------------------------------------ |
| `DTRACK_API_KEY`     | Yes      | Dependency Track API key                                                 |
| `DTRACK_API_URL`     | Yes      | Full API base URL (e.g., `https://dtrack.example.com/api`)               |
| `DTRACK_PROJECT_ID`  | §        | Project UUID (alternative to using `COMPONENT_NAME`/`COMPONENT_VERSION`) |
| `DTRACK_AUTO_CREATE` | No       | Auto-create project if it doesn't exist (default: false)                 |

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

## Product Releases

Tag your SBOMs with product releases for version tracking and release management in sbomify.

```yaml
- uses: sbomify/github-action@master
  env:
    TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
    COMPONENT_ID: your-component-id
    LOCK_FILE: requirements.txt
    PRODUCT_RELEASE: '["product_id:v1.0.0"]'
```

**Format:** JSON array of `"product_id:version"` strings. You can tag multiple releases:

```yaml
PRODUCT_RELEASE: '["product_id_1:v1.0.0", "product_id_2:v2.0.0"]'
```

**Behavior:**

- **Get-or-create**: If the release already exists, it's reused. If not, it's created automatically.
- **Tagging**: The uploaded SBOM is associated with each specified release.
- **Partial failures**: If some releases succeed and others fail, the action logs a warning but continues.

> **Note**: Requires `TOKEN` and `COMPONENT_ID` to be set, as this feature interacts with the sbomify API.

## Supported Lockfiles

| Language   | Files                                                                          |
| ---------- | ------------------------------------------------------------------------------ |
| Python     | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pyproject.toml` |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` |
| Java       | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`               |
| Go         | `go.mod`, `go.sum`                                                             |
| Rust       | `Cargo.lock`                                                                   |
| Ruby       | `Gemfile.lock`                                                                 |
| PHP        | `composer.json`, `composer.lock`                                               |
| .NET/C#    | `packages.lock.json`                                                           |
| Swift      | `Package.swift`, `Package.resolved`                                            |
| Dart       | `pubspec.lock`                                                                 |
| Elixir     | `mix.lock`                                                                     |
| Scala      | `build.sbt`                                                                    |
| C++        | `conan.lock`                                                                   |
| Terraform  | `.terraform.lock.hcl`                                                          |

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

### pip (Advanced)

For local development or environments where Docker isn't available, install via pip:

```bash
pip install sbomify-action
```

Then run with environment variables:

```bash
export LOCK_FILE=requirements.txt
export OUTPUT_FILE=sbom.cdx.json
export UPLOAD=false
export ENRICH=true
sbomify-action
```

**Note**: SBOM generation requires external tools (trivy, syft, or cdxgen) to be installed separately. The Docker image includes all tools pre-installed, which is why it's the recommended approach.

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

| Field             | Description                                  | SBOM Mapping                                                                       |
| ----------------- | -------------------------------------------- | ---------------------------------------------------------------------------------- |
| `lifecycle_phase` | Generation context (CISA 2025)               | CycloneDX 1.5+: `metadata.lifecycles[].phase`; SPDX: `creationInfo.creatorComment` |
| `supplier`        | Organization that supplies the component     | CycloneDX: `metadata.supplier`; SPDX: `packages[].supplier`                        |
| `authors`         | List of component authors                    | CycloneDX: `metadata.authors[]`; SPDX: `creationInfo.creators[]`                   |
| `licenses`        | SPDX license identifiers                     | CycloneDX: `metadata.licenses[]`; SPDX: Document-level licenses                    |
| `vcs_url`         | Repository URL (overrides CI auto-detection) | CycloneDX: `externalReferences[type=vcs]`; SPDX: `downloadLocation`                |
| `vcs_commit_sha`  | Full commit SHA                              | Appended to VCS URL as `@sha`                                                      |
| `vcs_ref`         | Branch or tag name                           | Added as comment/context                                                           |

**Valid `lifecycle_phase` values:** `design`, `pre-build`, `build`, `post-build`, `operations`, `discovery`, `decommission`

**Priority:** Local config values override sbomify API values when both are available.

### VCS Information (Auto-Detected)

When running in CI environments, sbomify automatically detects and adds VCS (Version Control System) information to your SBOM:

| CI Platform         | Auto-Detected Fields                                                       |
| ------------------- | -------------------------------------------------------------------------- |
| GitHub Actions      | Repository URL, commit SHA, branch/tag (supports GitHub Enterprise Server) |
| GitLab CI           | Project URL, commit SHA, ref name (supports self-managed instances)        |
| Bitbucket Pipelines | Repository URL, commit SHA, branch/tag                                     |

**What's added to the SBOM:**

- **CycloneDX**: VCS external reference on root component with `git+https://...@sha` format
- **SPDX**: `downloadLocation` with commit-pinned URL, `sourceInfo` with build context, VCS external reference

**Overriding auto-detected values:**

Add VCS fields to `sbomify.json` to override auto-detected values (useful for self-hosted instances):

```json
{
  "vcs_url": "https://github.mycompany.com/org/repo",
  "vcs_commit_sha": "abc123def456",
  "vcs_ref": "main"
}
```

**Disabling VCS augmentation:**

Set the environment variable to disable VCS information entirely:

```yaml
env:
  DISABLE_VCS_AUGMENTATION: "true"
```

### Enrichment Data Sources

| Source         | Package Types                                                    | Data                                                      |
| -------------- | ---------------------------------------------------------------- | --------------------------------------------------------- |
| License DB     | Alpine, Wolfi, Ubuntu, Rocky, Alma, CentOS, Fedora, Amazon Linux | License, description, supplier, homepage, maintainer, CLE |
| PyPI           | Python                                                           | License, author, homepage                                 |
| pub.dev        | Dart                                                             | License, author, homepage, repo                           |
| crates.io      | Rust/Cargo                                                       | License, author, homepage, repo, description              |
| Debian Sources | Debian packages                                                  | Maintainer, description, homepage                         |
| deps.dev       | Python, npm, Maven, Go, Ruby, NuGet (+ Rust fallback)            | License, homepage, repo                                   |
| ecosyste.ms    | All major ecosystems                                             | License, description, maintainer                          |
| Repology       | Linux distros                                                    | License, homepage                                         |

### License Database

For Linux distro packages, sbomify uses pre-computed databases that provide comprehensive package metadata. The databases are built by pulling data directly from official distro sources (Alpine APKINDEX, Ubuntu/Debian apt repositories, RPM repos) and normalizing it into a consistent format with validated SPDX license expressions.

- **Generated automatically** on each release from official distro repositories
- **Downloaded on-demand** from GitHub Releases during enrichment
- **Cached locally** (~/.cache/sbomify/license-db/) for faster subsequent runs
- **Normalized** — vendor-specific license strings converted to valid SPDX expressions

**Data provided:**

| Field           | Description                                    |
| --------------- | ---------------------------------------------- |
| License         | SPDX-validated license expression              |
| Description     | Package summary                                |
| Supplier        | Package maintainer/vendor                      |
| Homepage        | Project website URL                            |
| Download URL    | Package download location                      |
| Maintainer      | Name and email                                 |
| CLE (lifecycle) | End-of-support, end-of-life, and release dates |

[CLE (Common Lifecycle Enumeration)](https://sbomify.com/compliance/cle/) provides distro-level lifecycle dates, enabling automated end-of-life tracking for OS packages.

**Supported distros:**

| Distro       | Versions            |
| ------------ | ------------------- |
| Alpine       | 3.13–3.21           |
| Wolfi        | rolling             |
| Ubuntu       | 20.04, 22.04, 24.04 |
| Rocky Linux  | 8, 9                |
| AlmaLinux    | 8, 9                |
| CentOS       | Stream 8, Stream 9  |
| Fedora       | 39, 40, 41, 42      |
| Amazon Linux | 2, 2023             |

The license database is the **primary source** for Linux distro packages, taking precedence over other enrichment sources. If a package isn't found in the database, sbomify falls back to Repology and ecosyste.ms.

**Local generation** (advanced): If you need a database for an unsupported version or want to generate offline:

```bash
sbomify-license-db --distro alpine --version 3.20 --output alpine-3.20.json.gz
```

Set `SBOMIFY_DISABLE_LICENSE_DB_GENERATION=true` to disable automatic local generation fallback.

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

| Field                  | Description                        | Coverage                          |
| ---------------------- | ---------------------------------- | --------------------------------- |
| **Supplier/Publisher** | Package maintainer or organization | High for popular registries       |
| **License**            | SPDX license expression            | High (most registries require it) |
| **Description**        | Package summary                    | High                              |
| **Homepage**           | Project website                    | Medium-High                       |
| **Repository**         | Source code URL                    | Medium-High                       |
| **Download URL**       | Registry/distribution link         | High                              |
| **Issue Tracker**      | Bug reporting URL                  | Medium                            |

**Coverage varies by ecosystem.** Popular packages on PyPI, npm, and crates.io have excellent metadata. Linux distros (Alpine, Ubuntu, Rocky, Alma, CentOS, Fedora, Amazon Linux, Wolfi) have high license coverage through pre-computed license databases. sbomify queries multiple sources with fallbacks, but some fields may remain empty for obscure packages.

### Data Sources (Priority Order)

sbomify queries sources in priority order, stopping when data is found:

| Ecosystem         | Primary Source | Fallback Sources       |
| ----------------- | -------------- | ---------------------- |
| Python            | PyPI API       | deps.dev → ecosyste.ms |
| JavaScript        | deps.dev       | ecosyste.ms            |
| Rust              | crates.io API  | deps.dev → ecosyste.ms |
| Go                | deps.dev       | ecosyste.ms            |
| Ruby              | deps.dev       | ecosyste.ms            |
| Java/Maven        | deps.dev       | ecosyste.ms            |
| Dart              | pub.dev API    | ecosyste.ms            |
| Debian            | Debian Sources | Repology → ecosyste.ms |
| Ubuntu            | License DB     | Repology → ecosyste.ms |
| Alpine            | License DB     | Repology → ecosyste.ms |
| Wolfi             | License DB     | Repology → ecosyste.ms |
| Rocky/Alma/CentOS | License DB     | Repology → ecosyste.ms |
| Fedora            | License DB     | Repology → ecosyste.ms |
| Amazon Linux      | License DB     | Repology → ecosyste.ms |

### Limitations

- **Network required**: Enrichment calls external APIs during CI. Not suitable for air-gapped environments.
- **Rate limits**: APIs may rate-limit large SBOMs. sbomify uses caching and backoff, but very large dependency trees (1000+ packages) may see slower enrichment.
- **Best effort**: If a package isn't in any registry (private packages, vendored code), no metadata will be added.

> 📖 See [docs/enrichment_coverage.md](docs/enrichment_coverage.md) for detailed coverage information by ecosystem.

## SBOM Generation

sbomify uses a plugin architecture for SBOM generation, automatically selecting the best generator for each input type and ecosystem.

### Generator Selection

Generators are tried in priority order. Native tools (optimized for specific ecosystems) are preferred over generic scanners. Each tool supports different ecosystems:

| Priority | Generator           | Supported Ecosystems                                                                                           | Output Formats                  |
| -------- | ------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 10       | **cyclonedx-py**    | Python only                                                                                                    | CycloneDX 1.0–1.7               |
| 10       | **cargo-cyclonedx** | Rust only                                                                                                      | CycloneDX 1.4–1.6               |
| 20       | **cdxgen**          | Python, JavaScript, **Java/Gradle**, Go, Rust, Ruby, Dart, C++, PHP, .NET, Swift, Elixir, Scala, Docker images | CycloneDX 1.4–1.7               |
| 30       | **Trivy**           | Python, JavaScript, Java/Gradle, Go, Rust, Ruby, C++, PHP, .NET, Docker images                                 | CycloneDX 1.6, SPDX 2.3         |
| 35       | **Syft**            | Python, JavaScript, Go, Rust, Ruby, Dart, C++, PHP, .NET, Swift, Elixir, Terraform, Docker images              | CycloneDX 1.2–1.6, SPDX 2.2–2.3 |

### How It Works

1. **Python lockfiles** → cyclonedx-py (native, most accurate for Python)
2. **Rust lockfiles** (Cargo.lock) → cargo-cyclonedx (native, most accurate for Rust)
3. **Java lockfiles** (pom.xml, build.gradle, gradle.lockfile) → cdxgen (best Java support)
4. **Dart lockfiles** (pubspec.lock) → cdxgen or Syft (Trivy doesn't support Dart)
5. **Other lockfiles** (package-lock.json, go.mod, etc.) → cdxgen (then Trivy, then Syft as fallbacks)
6. **Docker images** → cdxgen (then Trivy, then Syft as fallbacks)

If the primary generator fails or doesn't support the input, the next one in priority order is tried automatically.

### Format Selection

Control the output format with the `SBOM_FORMAT` environment variable:

- **CycloneDX** (`SBOM_FORMAT=cyclonedx`): Default format. Uses the latest version supported by the selected generator.
- **SPDX** (`SBOM_FORMAT=spdx`): Uses Trivy (2.3) or Syft (2.2/2.3) depending on availability.

Generated SBOMs are validated against their JSON schemas before output.

### Required Tools

When installed via pip, sbomify-action requires external SBOM generators. The Docker image includes all tools pre-installed.

| Tool             | Install Command                                                                                 | Notes                                                                                                                          |
| ---------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **cyclonedx-py** | `pip install cyclonedx-bom`                                                                     | Native Python generator; `cyclonedx-py` is the CLI command provided by the `cyclonedx-bom` package (installed as a dependency) |
| **Trivy**        | [Installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) | macOS: `brew install trivy`                                                                                                    |
| **Syft**         | [Installation guide](https://github.com/anchore/syft#installation)                              | macOS: `brew install syft`                                                                                                     |
| **cdxgen**       | `npm install -g @cyclonedx/cdxgen`                                                              | Requires Node.js/Bun                                                                                                           |

**Minimum requirement**: At least one generator must be installed for SBOM generation. For Python projects, `cyclonedx-bom` (which provides the `cyclonedx-py` command) is installed as a dependency when you install sbomify-action via pip. For other ecosystems or Docker images, install `trivy`, `syft`, or `cdxgen`.

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
