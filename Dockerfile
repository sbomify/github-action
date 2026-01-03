FROM python:3-slim-bullseye AS fetcher

WORKDIR /tmp

# Define tool versions
ENV BOMCTL_VERSION=0.4.3 \
    TRIVY_VERSION=0.67.2 \
    SYFT_VERSION=1.39.0 \
    CDXGEN_VERSION=12.0.0

RUN apt-get update && \
    apt-get install -y curl unzip

# Install Trivy
RUN curl -sL \
    -o trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
RUN curl -sL \
    -o trivy_checksum.txt \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"
RUN sha256sum --ignore-missing -c trivy_checksum.txt
RUN tar xvfz trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz
RUN chmod +x /tmp/trivy
RUN mv trivy /usr/local/bin
RUN rm -rf /tmp/*

# Install bomctl
RUN curl -sL \
    -o bomctl_${BOMCTL_VERSION}_linux_amd64.tar.gz \
    "https://github.com/bomctl/bomctl/releases/download/v${BOMCTL_VERSION}/bomctl_${BOMCTL_VERSION}_linux_amd64.tar.gz"
RUN curl -sL \
    -o bomctl_checksum.txt \
    "https://github.com/bomctl/bomctl/releases/download/v${BOMCTL_VERSION}/bomctl_${BOMCTL_VERSION}_checksums.txt"
RUN sha256sum --ignore-missing -c bomctl_checksum.txt
RUN tar xvfz bomctl_${BOMCTL_VERSION}_linux_amd64.tar.gz
RUN chmod +x /tmp/bomctl
RUN mv bomctl /usr/local/bin
RUN rm -rf /tmp/*

# Install Syft
RUN curl -sL \
    -o syft_${SYFT_VERSION}_linux_amd64.tar.gz \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"
RUN curl -sL \
    -o syft_checksum.txt \
    "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt"
RUN sha256sum --ignore-missing -c syft_checksum.txt
RUN tar xvfz syft_${SYFT_VERSION}_linux_amd64.tar.gz
RUN chmod +x /tmp/syft
RUN mv syft /usr/local/bin
RUN rm -rf /tmp/*

# Install bun and cdxgen
RUN curl -fsSL https://bun.sh/install | bash
ENV PATH="/root/.bun/bin:${PATH}"
RUN bun install -g @cyclonedx/cdxgen@${CDXGEN_VERSION}

# Python builder stage
FROM python:3-slim-bullseye AS builder

# Install build dependencies and UV
RUN apt-get update && \
    apt-get install -y curl build-essential
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app
COPY . /app/

# Build and install using UV
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN uv venv /opt/venv
RUN uv sync --locked
RUN rm -rf dist/ && uv build
RUN uv pip install dist/sbomify_github_action-*.whl

# Final stage
FROM python:3-slim-bullseye

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
      org.opencontainers.image.base.name="python:3-slim-bullseye"

# Additional metadata labels
LABEL com.sbomify.maintainer="sbomify <hello@sbomify.com>" \
      com.sbomify.company="sbomify" \
      com.sbomify.company.url="https://sbomify.com" \
      com.sbomify.vcs.type="git" \
      com.sbomify.vcs.url="https://github.com/sbomify/github-action.git" \
      com.sbomify.vcs.branch="${VCS_REF}" \
      com.sbomify.vcs.commit="${COMMIT_SHA}"

# Install runtime dependencies for SBOM generation
# - Maven: Required by cdxgen for full Java dependency resolution
# - default-jdk-headless: Java runtime for Maven
RUN apt-get update && \
    apt-get install -y --no-install-recommends maven default-jdk-headless && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy tools from fetcher
COPY --from=fetcher /usr/local/bin/trivy /usr/local/bin/
COPY --from=fetcher /usr/local/bin/bomctl /usr/local/bin/
COPY --from=fetcher /usr/local/bin/syft /usr/local/bin/
COPY --from=fetcher /root/.bun /root/.bun
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/root/.bun/bin:/opt/venv/bin:$PATH"

# Alias node to bun for tools that expect node
RUN ln -s /root/.bun/bin/bun /usr/local/bin/node
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Runtime version information (from build args)
ENV SBOMIFY_GITHUB_ACTION_VERSION=${VERSION}
ENV SBOMIFY_GITHUB_ACTION_COMMIT_SHA=${COMMIT_SHA}
ENV SBOMIFY_GITHUB_ACTION_VCS_REF=${VCS_REF}

# Verify cyclonedx-py is installed and working
RUN pip install --no-cache-dir cyclonedx-bom && \
    cyclonedx-py --version

CMD ["sbomify-action"]
