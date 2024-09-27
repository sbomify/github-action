# sbomify Upload Action

This GitHub Action for generating and uploading SBOMs to sbomify.

You can use this action for just uploading SBOMs, or you can use the generation feature based on a language specific lock file, in which case the tool will use an opinionated approach to author an SBOM for you.

The tool will use:
* JSON as the file format
* The latest version of CycloneDX as the SBOM format supported by the library

## Inputs

### `token`

**Required** The authorization token for the sbomify API. Use a GitHub Secret to store this token.

### `component-id`

**Required** ID of the component against which the SBOM is to be uploaded.

### `sbom-file`

**Optional** The path to the SBOM file to be uploaded. If not specified, provide a lockfile.

### `lockfile`

**Optional** The path to the language specific lockfile. If not specified, provide an SBOM.

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
