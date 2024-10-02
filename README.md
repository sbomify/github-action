# sbomify Upload Action

This is an opinionated tool for helping with the SBOM life cycle, namely [generating, augmenting and enriching](https://sbomify.com/features/generate-collaborate-analyze/).

The goal is to help users generate NTIA Minimum Elements compliant SBOMs by stitching together various tools, along with metadata from sbomify.

This tool can be used both with an SBOM, as well with a lock-file from various software packages (see `LOCK_FILE`).

## Inputs

### `TOKEN`

**Required** The authorization token for the sbomify API. Use a GitHub Secret to store this token.

### `COMPONENT_ID`

**Required** ID of the component against which the SBOM is to be uploaded.

### `SBOM_FILE`

**Optional** The path to the SBOM file to be uploaded. If not specified, provide a lockfile.

### `LOCK_FILE`

**Optional** The path to the language specific lockfile. If not specified, provide an SBOM.

Supported lock files:

* Python
  * Pipfile (`Pipfile.lock`)
  * Poetry (`poetry.lock` and/or `pyproject.toml`)
  * Pip (`requirements.txt`)

### `OUTPUT_FILE`

**Optional** Set this to write the final SBOM to disk for usage with other tools (and/or attestation).

### `AUGMENT`

**Optional** Set this option to enrich your SBOM with author, vendor and license metadata provided for your component in sbomify's platform. Most SBOM generation tools will not provide this information for you.

### `ENRICH`

**Optional** Set this option to enrich your SBOM using [Ecosyste.ms](https://github.com/ecosyste-ms). This can help with improving your NTIA Minimum Elements Compliance.

## Opinions

While we aspire to become fully format agnostic, we are making some assumptions:

* We always us JSON (i.e. XML is not supported)
* Currently the tooling is skewed towards CycloneDX, but we aim for improving our SPDX support going forward

## Example Usage

```yaml
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
