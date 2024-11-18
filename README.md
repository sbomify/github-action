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

### `DOCKER_IMAGE` (string)

**Optional** The name of a Docker image. This can be either a locally built image, or a publicly available Docker image from Docker Hub.

Note that this will only generate the system packages from the Docker image. Separate out your application dependencies and use `LOCK_FILE` against a separate sbomify component, and then aggregate them using a "project". See [SBOM hierarchy](https://sbomify.com/features/sbom-hierarchy/) for more details.

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

### `OVERRIDE_SBOM_METADATA` (true/false)

**Optional** Set this option when augmenting the SBOM to allow overwriting sbom metadata with metadata for your component. It is useful when when metadata in the SBOM and metadata for your component contain same items. By default metadata present in the SBOM takes precedence. If you want component metadata to overwrite SBOM metadata then set this to True.

### `OVERRIDE_NAME` (true/false)

**Optional** Set this option when augmenting the SBOM to set the component name within the SBOM to your component name at sbomify. This overwrites the name set by sbom generation tool.

### `SBOM_VERSION` (string)

**Optional** Set this option when augmenting the SBOM to overwrite the component version within the sbom metadata with the version provided. Useful if the tool generating the sbom is not setting the correct version for your software component.

If you are releasing using GitHub releases, you might want to set `SBOM_VERSION` to `${{ github.ref_name }}`, and if you're using rolling releases, you might want to set it to `${{ github.sha }}`.

### `ENRICH` (true/false)

**Optional** Set this option to enrich your SBOM using [Ecosyste.ms](https://github.com/ecosyste-ms). This can help with improving your NTIA Minimum Elements Compliance.

### `UPLOAD` (true/false)

You can use this tool in standalone mode, where you don't upload the final SBOM to sbomify.

## Opinions

While we aspire to become fully format agnostic, we are making some assumptions:

* We always us JSON (i.e. XML is not supported)
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
          SBOM_VERSION: ${{ github.ref_name }}
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
          OUTPUT_FILE: 'my-sbom.cdx.json'
          AUGMENT: true
          ENRICH: true
```

### Attesting your SBOMs

More sophisticated users may also want to use GitHub's built-in [build provenance attestations](https://github.com/actions/attest-build-provenance). Behind the scenes, this will help you provide a SLSA build provenance predicate using the in-toto format. You can find a fully example [here](https://github.com/sbomify/github-action/blob/master/.github/workflows/sbomify.yaml), but here is a non-complete example:

```yaml
      - name: Upload SBOM
        uses: sbomify/github-action@master
        env:
          TOKEN: ${{ secrets.SBOMIFY_TOKEN }}
          COMPONENT_ID: 'Your Component ID'
          LOCK_FILE: 'poetry.lock'
          SBOM_VERSION: ${{ github.ref_name }}-${{ github.sha }}
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
    SBOM_VERSION: $CI_COMMIT_SHA
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
* Create a new Repository varialbe named `SBOMIFY_TOKEN` with your sbomify token
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
              SBOM_VERSION: $BITBUCKET_COMMIT
              LOCK_FILE: "poetry.lock"
              OUTPUT_FILE: "bitbucket-sbom.cdx.json"
```

## Using in Docker

You can also use the Actions module directly in Docker as follows:

```bash
$ docker run -rm \
   -e TOKEN=<my token> \
   -e COMPONENT_ID=<my component id> \
   -e LOCK_FILE=requirements.txt \
   sbomifyhub/sbomify-action
```
