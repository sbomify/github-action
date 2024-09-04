# sbomify Upload Action

This GitHub Action uploads an SBOM file to sbomify.

## Inputs

### `token`

**Required** The authorization token for the sbomify API. Use a GitHub Secret to store this token.

### `sbom-file`

**Required** The path to the SBOM file to be uploaded.

### `component-id`

**Required** ID of the component against which the SBOM is to be uploaded.

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
        with:
          token: ${{ secrets.SBOMIFY_TOKEN }}
          sbom-file: 'sbom-file.json'
          component-id: 'xFef-szx_r'
```
