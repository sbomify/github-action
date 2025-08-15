# sbomify SBOM Generation Tool
[![sbomified](https://sbomify.com/assets/images/logo/badge.svg)](https://app.sbomify.com/component/Gu9wem8mkX)

![SBOM lifecycle](https://sbomify.com/assets/images/site/lifecycle.svg)

This is an opinionated tool for helping with the SBOM life cycle, namely [generating, augmenting and enriching](https://sbomify.com/features/generate-collaborate-analyze/), plus automatic release management and SBOM tagging.

The goal is to help users generate NTIA Minimum Elements compliant SBOMs by stitching together various tools, along with metadata augmentation from sbomify, and seamlessly associate them with product releases.

This tool can be used both with an SBOM, as well as with a lock-file from various software packages (see `LOCK_FILE`).

## Inputs

### `TOKEN`

**Required** The authorization token for the sbomify API. Use a GitHub Secret to store this token.

### `COMPONENT_ID`

**Required** ID of the component against which the SBOM is to be uploaded.

### `SBOM_FILE` (path)

**Optional** The path to the SBOM file to be uploaded. If not specified, provide a lockfile.

### `DOCKER_IMAGE` (string)

**Optional** The name of a Docker image. This can be either a locally built image, or a publicly available Docker image from Docker Hub.

Note that this will only generate the system packages from the Docker image. Separate out your application dependencies and use `LOCK_FILE` against a separate sbomify component, and then aggregate them using a "project". See [SBOM hierarchy](https://sbomify.com/features/sbom-hierarchy/) for more details.

### `LOCK_FILE` (path)

**Optional** The path to the language specific lockfile. If not specified, provide an SBOM.

| Language | Tool Used | Supported Lockfile(s) |
|---|---|---|
| Python | [cyclonedx-python](https://github.com/CycloneDX/cyclonedx-python) / [trivy](https://github.com/aquasecurity/trivy) | Pipfile (`Pipfile.lock`), Poetry (`poetry.lock` and/or `pyproject.toml`), Pip (`requirements.txt`), uv (`uv.lock`) |
| Rust | [trivy](https://github.com/aquasecurity/trivy) | `Cargo.lock` |
| JavaScript (Node.js) | [trivy](https://github.com/aquasecurity/trivy) | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Ruby | [trivy](https://github.com/aquasecurity/trivy) | `Gemfile.lock` |
| Go | [trivy](https://github.com/aquasecurity/trivy) | `go.mod` |
| Dart | [trivy](https://github.com/aquasecurity/trivy) | `pubspec.lock` |

### `OUTPUT_FILE` (path)

**Optional** Set this to write the final SBOM to disk for usage with other tools (and/or attestation).

### `AUGMENT` (true/false)

**Optional** Adds supplier, author, and license information from your sbomify component to your SBOM. Most SBOM generation tools don't include this business metadata.

**Note:** Works with both CycloneDX and SPDX format SBOMs. The action will intelligently apply metadata according to each format's specifications.

### `OVERRIDE_SBOM_METADATA` (true/false)

**Optional** Controls what happens when both your SBOM and sbomify have the same type of metadata (like supplier information).

- **`false` (default)**: Keep your existing SBOM metadata and add sbomify data to it
- **`true`**: Replace your SBOM metadata with sbomify data

**When to use `false`**: You want to preserve metadata from your build tools and add sbomify information alongside it.

**When to use `true`**: You want to standardize all SBOMs using your sbomify component definitions.

### `COMPONENT_NAME` (string)

**Optional** Set the component name in your SBOM metadata. This allows you to directly specify the name you want for your component.

**When to use**: Useful when you want to set a specific component name regardless of what your SBOM generation tool produces, or when standardizing component names across different SBOMs.

**Example**: `COMPONENT_NAME: 'my-awesome-app'`

### `OVERRIDE_NAME` (true/false)

> **⚠️ Deprecation Notice**: The `OVERRIDE_NAME` environment variable is deprecated. Please use `COMPONENT_NAME` instead. `OVERRIDE_NAME` will continue to work but will show deprecation warnings.

**Optional** (Deprecated) Sets the component name in your SBOM to match the component name from your sbomify configuration.

- **`false` (default)**: Keep the component name as set by your SBOM generation tool
- **`true`**: Replace the component name with the name from your sbomify component

**When to use**: This approach is deprecated. Use `COMPONENT_NAME` instead for direct control over the component name.

### `COMPONENT_VERSION` (string)

**Optional** Set this option when augmenting the SBOM to overwrite the component version within the sbom metadata with the version provided. Useful if the tool generating the sbom is not setting the correct version for your software component.

If you are releasing using GitHub releases, you might want to set `COMPONENT_VERSION` to `${{ github.ref_name }}`, and if you're using rolling releases, you might want to set it to `${{ github.sha }}`.

> **⚠️ Deprecation Notice**: The `SBOM_VERSION` environment variable is deprecated. Please use `COMPONENT_VERSION` instead. `SBOM_VERSION` will continue to work but will show deprecation warnings.

### `ENRICH` (true/false)

**Optional** Set this option to enrich your SBOM using [Ecosyste.ms](https://github.com/ecosyste-ms). This can help with improving your NTIA Minimum Elements Compliance.

### `PRODUCT_RELEASE` (JSON array)

**Optional** Set this to associate your SBOM with one or more product releases. The value should be a JSON array of strings in the format `["product_id:version"]`.

- The `product_id` should be the actual product ID from your sbomify account (e.g., "Gu9wem8mkX")
- The `version` is the release version (e.g., "v1.2.3")

**Example**: `PRODUCT_RELEASE: '["Gu9wem8mkX:v1.2.3", "GFcFpn8q4h:v2.0.0"]'`

When specified, the action will:
1. Check if the specified release exists for each product
2. Create the release if it doesn't exist
3. Tag the uploaded SBOM with the specified release(s)

The action provides user-friendly logging output. For example:
```
[INFO] Processing release v1.2.3 for product Gu9wem8mkX
[INFO] 'Major Feature Release' (v1.2.3) already exists for product Gu9wem8mkX
[INFO] Tagging SBOM sbom_abc123 with 'Major Feature Release' (v1.2.3) (ID: rel_456)
```

**When to use**: Use this when you want to associate your SBOM with specific product releases for better organization and tracking in sbomify.

### `UPLOAD` (true/false)

You can use this tool in standalone mode, where you don't upload the final SBOM to sbomify.

### `API_BASE_URL` (string)

**Optional** Override the sbomify API base URL. Default: `https://app.sbomify.com`

**When to use**: Useful for testing against development instances or when using a self-hosted sbomify instance.

**Examples**:
- Development instance: `API_BASE_URL: 'https://dev.sbomify.com'`
- Local testing: `API_BASE_URL: 'http://127.0.0.1:8000'`

**Note**: The API endpoints (`/api/v1/...`) are automatically appended to this base URL, so you should only provide the base domain.

## Compatibility Notes

### Format Support

The following format-specific behaviors apply:

* **Metadata Augmentation**: Both CycloneDX and SPDX formats are supported for metadata augmentation (`AUGMENT=true`).
* **SBOM Upload**: Both CycloneDX and SPDX formats are supported for upload.
* **Enrichment**: The enrichment process (`ENRICH=true`) works with both formats.

### Supported Operations by Format

| Operation | CycloneDX | SPDX | Notes |
|-----------|-----------|------|-------|
| **Generation** | ✅ | ✅ | All supported lockfile formats work with both formats |
| **Upload** | ✅ | ✅ | Both formats supported for upload to sbomify |
| **Augmentation** | ✅ | ✅ | Full metadata augmentation support for both formats |
| **Enrichment** | ✅ | ✅ | Enrichment process works with both formats |
| **Release Management** | ✅ | ✅ | Automatic release creation and SBOM tagging works with both formats |

## Opinions

While we aspire to become fully format agnostic, we are making some assumptions:

* We always use JSON (i.e. XML is not supported)
* Currently the tooling is skewed towards CycloneDX, but we aim for improving our SPDX support going forward

## Example Usage

### Upload existing SBOM

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
        uses: actions/checkout@v4

      - name: Upload SBOM
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'my-component-id'
          SBOM_FILE: 'sbom-file.json'
          AUGMENT: true
          ENRICH: true
```


### Generate an SBOM from a `requirements.txt` lockfile

```yaml
      - name: Upload SBOM
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'my-component-id'
          LOCK_FILE: 'requirements.txt'
          COMPONENT_NAME: 'my-awesome-app'
          COMPONENT_VERSION: ${{ github.ref_name }}
          AUGMENT: true
          ENRICH: true
```

### Standalone mode

```yaml
      - name: Upload SBOM
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'Your Component ID'
          LOCK_FILE: 'Cargo.lock'
          COMPONENT_NAME: 'my-rust-app'
          OUTPUT_FILE: 'my-sbom.cdx.json'
          AUGMENT: true
          ENRICH: true
```

### Associate SBOM with Product Releases

Use `PRODUCT_RELEASE` to automatically tag your SBOMs with product releases:

```yaml
---
name: Release with SBOM Tagging

on:
  release:
    types: [published]

jobs:
  build-and-tag-sbom:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Generate and Tag SBOM with Release
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'Gu9wem8mkX'
          LOCK_FILE: 'requirements.txt'
          COMPONENT_NAME: 'my-awesome-app'
          COMPONENT_VERSION: ${{ github.ref_name }}
          # Associate with multiple product releases
          PRODUCT_RELEASE: '["Gu9wem8mkX:${{ github.ref_name }}", "GFcFpn8q4h:${{ github.ref_name }}"]'
          AUGMENT: true
          ENRICH: true
```

This will:
- Generate an SBOM from your `requirements.txt`
- Create releases (if they don't exist) for the specified products
- Tag the uploaded SBOM with those releases
- Provide clear logging like: `"Tagging SBOM sbom_123 with 'v2.1.0 Release' (v2.1.0) (ID: rel_456)"`

### Attesting your SBOMs

More sophisticated users may also want to use GitHub's built-in [build provenance attestations](https://github.com/actions/attest-build-provenance). Behind the scenes, this will help you provide a SLSA build provenance predicate using the in-toto format. You can find a fully example [here](https://github.com/sbomify/github-action/blob/master/.github/workflows/sbomify.yaml), but here is a non-complete example:

```yaml
      - name: Upload SBOM (Poetry)
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'Your Component ID'
          LOCK_FILE: 'poetry.lock'
          COMPONENT_NAME: 'my-python-app'
          COMPONENT_VERSION: ${{ github.ref_name }}-${{ github.sha }}
          AUGMENT: true
          ENRICH: true
          OUTPUT_FILE: github-action.cdx.json

      # Alternative example for uv.lock
      - name: Upload SBOM (uv)
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'Your Component ID'
          LOCK_FILE: 'uv.lock'
          COMPONENT_NAME: 'my-python-app'
          COMPONENT_VERSION: ${{ github.ref_name }}-${{ github.sha }}
          AUGMENT: true
          ENRICH: true
          OUTPUT_FILE: github-action.cdx.json

      - name: Attest
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: '${{ github.workspace }}/github-action.cdx.json'
```

You can read more about attestation in [this blog post](https://sbomify.com/2024/10/31/github-action-update-and-attestation/).

## Using in GitLab

While named GitHub Actions, the SBOM generation tool is in fact CI/CD agnostic and will work on most CI/CD platforms, including GitLab.

The CI/CD job would look something similar to this:

```yaml
generate-sbom:
  image: sbomifyhub/sbomify-action
  variables:
    TOKEN: $SBOMIFY_TOKEN
    COMPONENT_ID: 'Your Component ID'
    UPLOAD: true
    AUGMENT: true
    ENRICH: true
    COMPONENT_NAME: 'my-python-app'
    COMPONENT_VERSION: $CI_COMMIT_SHA
    LOCK_FILE: 'poetry.lock'
    OUTPUT_FILE: test-sbom.cdx.json"
  script:
    - /sbomify.sh
```

This repository is mirrored to GitLab under [sbomify/gitlab-pipeline](https://gitlab.com/sbomify/gitlab-pipeline), where [.gitlab-ci.yml](https://github.com/sbomify/github-action/blob/master/.gitlab-ci.yml) triggers a [job](https://gitlab.com/sbomify/gitlab-pipeline/-/jobs).

To use this pipeline in your own CI/CD pipeline, simply copy the flow in the `.gitlab-ci.yml` file above and adjust it to your needs, then new CI/CD variable (Settings > CI/CD > Variables) with the following settings:

* Type: Variable
* Environments: All
* Visibility: Masked and hidden
* Protect variable
* Description: sbomify token
* Key: SBOMIFY_TOKEN
* Value: Your sbomify token

## Using in BitBucket

Much like GitLab, this Action works just fine in BitBucket too. This repository is mirrored on Bitbucket under [sbomify/bitbucket-pipe](https://bitbucket.org/sbomify/bitbucket-pipe).

* Navigate to Settings -> Repository variables
* Create a new Repository variable named `SBOMIFY_TOKEN` with your sbomify token
* Create your `bitbucket-pipelines.yml` file ([example file](https://github.com/sbomify/github-action/blob/master/bitbucket-pipelines.yml))


The file would look something similar to this:

```yaml
pipelines:
  default:
    - step:
        name: Build SBOM
        image: atlassian/default-image:latest
        script:
          - pipe: docker://sbomifyhub/sbomify-action:latest
            variables:
              TOKEN: $SBOMIFY_TOKEN
              COMPONENT_ID: "Your Component ID"
              UPLOAD: "true"
              AUGMENT: "true"
              ENRICH: "true"
              COMPONENT_NAME: "my-python-app"
              COMPONENT_VERSION: $BITBUCKET_COMMIT
              LOCK_FILE: "poetry.lock"
              OUTPUT_FILE: "bitbucket-sbom.cdx.json"
```

## Using in Docker

You can also use the Actions module directly in Docker as follows:

```bash
$ docker run --rm \
   -v $(pwd):/code \
   -e TOKEN=<my token> \
   -e COMPONENT_ID=<my component id> \
   -e LOCK_FILE=/code/requirements.txt \
   -e COMPONENT_NAME=my-app \
   sbomifyhub/sbomify-action
```
