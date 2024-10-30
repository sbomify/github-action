FROM python:3-slim-bullseye AS fetcher

WORKDIR /tmp

# Define tool versions
ENV PARLAY_VERSION=0.6.0 \
    TRIVY_VERSION=0.56.2

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

FROM python:3-slim-bullseye

WORKDIR /usr/src/app

RUN mkdir -p /opt/poetry

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_CACHE_DIR=/opt/poetry \
    POETRY_NO_INTERACTION=1

COPY --from=fetcher /usr/local/bin/parlay /usr/local/bin/
COPY --from=fetcher /usr/local/bin/trivy /usr/local/bin/

RUN python -m pip install pipx --no-cache
RUN pipx install poetry --global
RUN pipx ensurepath --global

COPY pyproject.toml /usr/src/app/
COPY poetry.lock /usr/src/app/
RUN poetry install --only main

COPY entrypoint.py /usr/src/app/

CMD [ "poetry", "-C", "/usr/src/app/", "run", "python", "/usr/src/app/entrypoint.py" ]
