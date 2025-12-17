# sbomify GitHub Action

[![sbomified](https://sbomify.com/assets/images/logo/badge.svg)](https://app.sbomify.com/public/component/Gu9wem8mkX)
[![CI/CD Pipeline](https://github.com/sbomify/github-action/actions/workflows/sbomify.yaml/badge.svg)](https://github.com/sbomify/github-action/actions/workflows/sbomify.yaml)

Generate, augment, enrich, and manage SBOMs in your CI/CD pipeline. Works standalone or with [sbomify](https://sbomify.com).

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

That's it! This generates an SBOM from your lockfile and attempts to make it NTIA-compliant.

## Features

- **Generate** SBOMs from lockfiles (Python, Node, Rust, Go, Ruby, Dart, C++)
- **Generate** SBOMs from Docker images
- **Augment** with business metadata (supplier, authors, licenses) from sbomify
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
| `LOCK_FILE` | * | Path to lockfile (requirements.txt, poetry.lock, Cargo.lock, etc.) |
| `SBOM_FILE` | * | Path to existing SBOM file |
| `DOCKER_IMAGE` | * | Docker image name |
| `OUTPUT_FILE` | No | Write final SBOM to this path |
| `ENRICH` | No | Add metadata from package registries |
| `TOKEN` | ** | sbomify API token |
| `COMPONENT_ID` | ** | sbomify component ID |
| `AUGMENT` | No | Add metadata from sbomify |
| `COMPONENT_NAME` | No | Override component name in SBOM |
| `COMPONENT_VERSION` | No | Override component version in SBOM |
| `PRODUCT_RELEASE` | No | Tag SBOM with releases: `'["product_id:v1.0.0"]'` |
| `UPLOAD` | No | Upload to sbomify (default: true) |
| `API_BASE_URL` | No | Override sbomify API URL for self-hosted instances |

\* One of `LOCK_FILE`, `SBOM_FILE`, or `DOCKER_IMAGE` required
\** Required when using sbomify features (`UPLOAD`, `AUGMENT`, `PRODUCT_RELEASE`)

## Supported Lockfiles

| Language | Files |
|----------|-------|
| Python | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock` |
| JavaScript | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Rust | `Cargo.lock` |
| Go | `go.mod` |
| Ruby | `Gemfile.lock` |
| Dart | `pubspec.lock` |
| C++ | `conan.lock` |

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

**Augmentation** (`AUGMENT=true`) adds your business metadata from sbomify—supplier info, authors, and licenses you've configured for your component. This requires a sbomify account.

**Enrichment** (`ENRICH=true`) fetches package metadata from public registries. No account needed.

| Source | Package Types | Data |
|--------|---------------|------|
| PyPI | Python | License, author, homepage |
| pub.dev | Dart | License, author, homepage, repo |
| deps.dev | Python, npm, Maven, Go, Rust, Ruby, NuGet | License, homepage, repo |
| ecosyste.ms | All major ecosystems | License, description, maintainer |
| Debian Sources | Debian packages | License, maintainer |
| Repology | Linux distros | License, homepage |

## Format Support

- **CycloneDX**: 1.4, 1.5, 1.6, 1.7 (JSON)
- **SPDX**: 2.2, 2.3 (JSON)

## Links

- [Documentation](https://sbomify.com/features/generate-collaborate-analyze/)
- [sbomify Platform](https://sbomify.com)
- [Attestation Guide](https://sbomify.com/2024/10/31/github-action-update-and-attestation/)

## License

Apache-2.0
