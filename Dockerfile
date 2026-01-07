FROM python:3.13-slim-trixie AS fetcher

# Use Docker's automatic platform detection
ARG TARGETARCH

WORKDIR /tmp

# Define tool versions
ENV BOMCTL_VERSION=0.4.3 \
    TRIVY_VERSION=0.67.2 \
    SYFT_VERSION=1.39.0

RUN apt-get update && \
    apt-get install -y curl unzip

# Install Trivy (uses Linux-64bit / Linux-ARM64 naming)
RUN TRIVY_ARCH=$(case ${TARGETARCH} in \
        amd64) echo "64bit" ;; \
        arm64) echo "ARM64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac) && \
    curl -sL \
        -o trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" && \
    curl -sL \
        -o trivy_checksum.txt \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" && \
    sha256sum --ignore-missing -c trivy_checksum.txt && \
    tar xvfz trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz && \
    chmod +x /tmp/trivy && \
    mv trivy /usr/local/bin && \
    rm -rf /tmp/*

# Install bomctl (uses linux_amd64 / linux_arm64 naming)
RUN curl -sL \
        -o bomctl_${BOMCTL_VERSION}_linux_${TARGETARCH}.tar.gz \
        "https://github.com/bomctl/bomctl/releases/download/v${BOMCTL_VERSION}/bomctl_${BOMCTL_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    curl -sL \
        -o bomctl_checksum.txt \
        "https://github.com/bomctl/bomctl/releases/download/v${BOMCTL_VERSION}/bomctl_${BOMCTL_VERSION}_checksums.txt" && \
    sha256sum --ignore-missing -c bomctl_checksum.txt && \
    tar xvfz bomctl_${BOMCTL_VERSION}_linux_${TARGETARCH}.tar.gz && \
    chmod +x /tmp/bomctl && \
    mv bomctl /usr/local/bin && \
    rm -rf /tmp/*

# Install Syft (uses linux_amd64 / linux_arm64 naming)
RUN curl -sL \
        -o syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz \
        "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    curl -sL \
        -o syft_checksum.txt \
        "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt" && \
    sha256sum --ignore-missing -c syft_checksum.txt && \
    tar xvfz syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz && \
    chmod +x /tmp/syft && \
    mv syft /usr/local/bin && \
    rm -rf /tmp/*

# Node/Bun stage for cdxgen
FROM oven/bun:debian AS node-fetcher

WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Python builder stage
FROM python:3.13-slim-trixie AS builder

# Install build dependencies and UV
RUN apt-get update && \
    apt-get install -y curl build-essential libxml2-dev libxslt-dev
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app
COPY . /app/

# Build and install using UV
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN uv venv /opt/venv
# Use --active so uv installs into the existing VIRTUAL_ENV (/opt/venv) instead of .venv
RUN uv sync --locked --active
RUN rm -rf dist/ && uv build
RUN uv pip install dist/sbomify_github_action-*.whl

# Final stage
FROM python:3.13-slim-trixie

# Build arguments for dynamic labels (passed at build time)
ARG VERSION=dev
ARG COMMIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown

# OCI Image Labels (https://github.com/opencontainers/image-spec/blob/main/annotations.md)
LABEL org.opencontainers.image.title="sbomify GitHub Action" \
      org.opencontainers.image.description="Generate, enrich, and manage Software Bill of Materials (SBOM) for your projects" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${COMMIT_SHA}" \
      org.opencontainers.image.ref.name="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/sbomify/github-action" \
      org.opencontainers.image.url="https://sbomify.com" \
      org.opencontainers.image.documentation="https://github.com/sbomify/github-action#readme" \
      org.opencontainers.image.vendor="sbomify" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="sbomify <hello@sbomify.com>" \
      org.opencontainers.image.base.name="python:3.13-slim-trixie"

# Additional metadata labels
LABEL com.sbomify.maintainer="sbomify <hello@sbomify.com>" \
      com.sbomify.company="sbomify" \
      com.sbomify.company.url="https://sbomify.com" \
      com.sbomify.vcs.type="git" \
      com.sbomify.vcs.url="https://github.com/sbomify/github-action.git" \
      com.sbomify.vcs.branch="${VCS_REF}" \
      com.sbomify.vcs.commit="${COMMIT_SHA}"

# Note: Java/Maven is installed on-demand at runtime when processing Java/Scala projects
# This reduces the base image size by ~330MB for non-Java workloads

# Copy tools from fetcher
COPY --from=fetcher /usr/local/bin/trivy /usr/local/bin/
COPY --from=fetcher /usr/local/bin/bomctl /usr/local/bin/
COPY --from=fetcher /usr/local/bin/syft /usr/local/bin/
COPY --from=node-fetcher /usr/local/bin/bun /usr/local/bin/
COPY --from=node-fetcher /app/node_modules /app/node_modules
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/app/node_modules/.bin:/opt/venv/bin:$PATH"

# Make 'node' invoke 'bun' so tools that expect 'node' actually run bun (compatibility shim)
RUN ln -s /usr/local/bin/bun /usr/local/bin/node
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Runtime version information (from build args)
ENV SBOMIFY_GITHUB_ACTION_VERSION=${VERSION}
ENV SBOMIFY_GITHUB_ACTION_COMMIT_SHA=${COMMIT_SHA}
ENV SBOMIFY_GITHUB_ACTION_VCS_REF=${VCS_REF}

CMD ["sbomify-action"]
