FROM python:3-slim-bullseye AS fetcher

WORKDIR /tmp

# Define tool versions
ENV PARLAY_VERSION=0.6.0 \
    TRIVY_VERSION=0.59.1

RUN apt-get update && \
    apt-get install -y curl

# Install Parlay
RUN curl -sL \
    -o parlay_Linux_x86_64.tar.gz \
    "https://github.com/snyk/parlay/releases/download/v${PARLAY_VERSION}/parlay_Linux_x86_64.tar.gz"
RUN curl -sL \
    -o parlay_checksum.txt \
    "https://github.com/snyk/parlay/releases/download/v${PARLAY_VERSION}/checksums.txt"
RUN sha256sum --ignore-missing -c parlay_checksum.txt
RUN tar xvfz parlay_Linux_x86_64.tar.gz
RUN chmod +x parlay
RUN mv parlay /usr/local/bin
RUN rm -rf /tmp/*

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

# Python builder stage
FROM python:3-slim-bullseye AS builder

# Install build dependencies and Poetry
RUN apt-get update && \
    apt-get install -y curl build-essential
RUN curl -sSL https://install.python-poetry.org | python3 -
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/root/.local/bin:${PATH}"
ENV POETRY_NO_INTERACTION=1

WORKDIR /app
COPY . /app/

RUN poetry build

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN uv venv /opt/venv
RUN uv pip install dist/sbomify_github_action-0.1.0-py3-none-any.whl

# Final stage
FROM python:3-slim-bullseye

# Add labels
LABEL org.opencontainers.image.source=https://github.com/sbomify/github-action
LABEL org.opencontainers.image.description="sbomify Action"
LABEL org.opencontainers.image.licenses=Apache-2.0

# Copy tools from fetcher
COPY --from=fetcher /usr/local/bin/parlay /usr/local/bin/
COPY --from=fetcher /usr/local/bin/trivy /usr/local/bin/
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["sbomify-action"]
