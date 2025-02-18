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
    apt-get install -y curl build-essential && \
    curl -sSL https://install.python-poetry.org | python3 -

# Set Poetry configuration
ENV PATH="/root/.local/bin:${PATH}" \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=false \
    POETRY_VIRTUALENVS_PATH="/opt/poetry/virtualenvs" \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

# Add build argument for test dependencies
ARG INSTALL_TEST_DEPS=false

# Install dependencies
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.path /opt/poetry/virtualenvs && \
    if [ "$INSTALL_TEST_DEPS" = "true" ]; then \
        poetry install; \
    else \
        poetry install --only main; \
    fi && \
    poetry env info

# Final stage
FROM python:3-slim-bullseye

# Add labels
LABEL org.opencontainers.image.source=https://github.com/sbomify/github-action
LABEL org.opencontainers.image.description="sbomify Action"
LABEL org.opencontainers.image.licenses=Apache-2.0

# Copy Poetry installation and virtualenv from builder
COPY --from=builder /root/.local /root/.local
COPY --from=builder /opt/poetry/virtualenvs /opt/poetry/virtualenvs

# Copy tools from fetcher
COPY --from=fetcher /usr/local/bin/parlay /usr/local/bin/
COPY --from=fetcher /usr/local/bin/trivy /usr/local/bin/

# Set environment variables and activate virtualenv
RUN VENV_PATH=$(find /opt/poetry/virtualenvs -mindepth 1 -maxdepth 1 -type d | head -n1) && \
    echo "export PATH=${VENV_PATH}/bin:/root/.local/bin:\${PATH}" > /etc/profile.d/venv.sh && \
    echo "export VIRTUAL_ENV=${VENV_PATH}" >> /etc/profile.d/venv.sh && \
    echo "source /etc/profile.d/venv.sh" >> /root/.bashrc

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VIRTUALENVS_PATH="/opt/poetry/virtualenvs" \
    POETRY_VIRTUALENVS_IN_PROJECT=false \
    POETRY_VIRTUALENVS_CREATE=false

# Copy application files
COPY entrypoint.py /usr/src/app/
COPY sbomify.sh /
COPY sbomify_tests.sh /

WORKDIR /usr/src/app

CMD ["/sbomify.sh"]
