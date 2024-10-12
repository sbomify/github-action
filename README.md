# sbomify SBOM Generation Tool
[![sbomified](https://sbomify.com/assets/images/logo/badge.svg)](https://app.sbomify.com/component/Gu9wem8mkX)

![SBOM lifecycle](https://sbomify.com/assets/images/site/lifecycle.svg)

This is an opinionated tool for helping with the SBOM life cycle, namely [generating, augmenting and enriching](https://sbomify.com/features/generate-collaborate-analyze/).

The goal is to help users generate NTIA Minimum Elements compliant SBOMs by stitching together various tools, along with metadata augmentation from sbomify.

This tool can be used both with an SBOM, as well with a lock-file from various software packages (see `LOCK_FILE`).

## Inputs

### `TOKEN`

**Required** The authorization token for the sbomify API. Use a GitHub Secret to store this token.

### `COMPONENT_ID`

**Required** ID of the component against which the SBOM is to be uploaded.

### `SBOM_FILE` (path)

**Optional** The path to the SBOM file to be uploaded. If not specified, provide a lockfile.

### `LOCK_FILE` (path)

**Optional** The path to the language specific lockfile. If not specified, provide an SBOM.

| Language | Tool Used | Supported Lockfile(s) |
|---|---|---|
| Python | [cyclonedx-python](https://github.com/CycloneDX/cyclonedx-python) | Pipfile (`Pipfile.lock`), Poetry (`poetry.lock` and/or `pyproject.toml`), Pip (`requirements.txt`) |
| Rust | [trivy](https://github.com/aquasecurity/trivy) | `Cargo.lock` |
| JavaScript (Node.js) | [trivy](https://github.com/aquasecurity/trivy) | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Ruby | [trivy](https://github.com/aquasecurity/trivy) | `Gemfile.lock` |
| Go | [trivy](https://github.com/aquasecurity/trivy) | `go.mod` |
| Dart | [trivy](https://github.com/aquasecurity/trivy) | `pubspec.lock` |

### `OUTPUT_FILE` (path)

**Optional** Set this to write the final SBOM to disk for usage with other tools (and/or attestation).

### `AUGMENT` (true/false)

**Optional** Set this option to enrich your SBOM with author, vendor and license metadata provided for your component in sbomify's platform. Most SBOM generation tools will not provide this information for you.

### `OVERRIDE_SBOM_METADTA` (true/false)

**Optional** Set this option when augmenting the SBOM to allow overwriting sbom metadata with metadata for your component. It is useful when when metadata in the SBOM and metadata for your component contain same items. By default metadata present in the SBOM takes precedence. If you want component metadata to overwrite SBOM metadata then set this to True.

### `OVERRIDE_NAME` (true/false)

**Optional** Set this option when augmenting the SBOM to set the component name within the SBOM to your component name at sbomify. This overwrites the name set by sbom generation tool.

### `OVERRIDE_SBOM_VERSION` (string)

**Optional** Set this option when augmenting the SBOM to overwrite the component version within the sbom metadata with the version provided. Useful if the tool generating the sbom is not setting the correct version for your software component.

### `ENRICH` (true/false)

**Optional** Set this option to enrich your SBOM using [Ecosyste.ms](https://github.com/ecosyste-ms). This can help with improving your NTIA Minimum Elements Compliance.

### `UPLOAD` (true/false)

You can use this tool in standalone mode, where you don't upload the final SBOM to sbomify.

## Opinions

While we aspire to become fully format agnostic, we are making some assumptions:

* We always us JSON (i.e. XML is not supported)
* Currently the tooling is skewed towards CycloneDX, but we aim for improving our SPDX support going forward

## Example Usage

```yaml
---
name: Upload an SBOM to sbomify

on: [push]

jobs:
  [...]
  upload-sbom:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Upload SBOM
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'my-component-id'
          SBOM_FILE: 'sbom-file.json'
          AUGMENT: true
          ENRICH: true
```

You could also use this to generate an SBOM:

```yaml
      - name: Upload SBOM
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'my-component-id'
          LOCK_FILE: 'requirementes.txt'
```

We can also use this GitHub Actions in standalone mode to generate an SBOM:

```yaml
      - name: Upload SBOM
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'my-component-id'
          LOCK_FILE: 'Cargo.lock'
          OUTPUT_FILE: 'my-sbom.cdx.json'
          UPLOAD: false
```
