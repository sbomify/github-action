FROM python:3-slim-bullseye AS fetcher

WORKDIR /tmp

# Define tool versions
ENV BOMCTL_VERSION=0.4.3 \
    TRIVY_VERSION=0.67.2

RUN apt-get update && \
    apt-get install -y curl

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

# Add labels
LABEL org.opencontainers.image.source=https://github.com/sbomify/github-action
LABEL org.opencontainers.image.description="sbomify Action"
LABEL org.opencontainers.image.licenses=Apache-2.0

# Copy tools from fetcher
COPY --from=fetcher /usr/local/bin/trivy /usr/local/bin/
COPY --from=fetcher /usr/local/bin/bomctl /usr/local/bin/
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Verify cyclonedx-py is installed and working
RUN pip install --no-cache-dir cyclonedx-bom && \
    cyclonedx-py --version

CMD ["sbomify-action"]
