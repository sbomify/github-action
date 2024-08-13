# sbomify Upload Action

This GitHub Action uploads an SBOM file to sbomify.

## Inputs

### `token`

**Required** The authorization token for the sbomify API. Use a GitHub Secret to store this token.

### `sbom-file`

**Required** The path to the SBOM file to be uploaded.

## Example Usage

```yaml
name: Upload SBOM to sbomify

on: [push]

jobs:
upload-sbom:
runs-on: ubuntu-latest
steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Upload SBOM
      uses: yourusername/sbomify-upload-action@v1.0
      with:
      token: ${{ secrets.SBOMIFY_TOKEN }}
      sbom-file: 'sbom-file.json'
```
