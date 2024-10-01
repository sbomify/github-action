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

RUN python -m pip install pipx --no-cache
RUN pipx install poetry --global
RUN pipx ensurepath --global

COPY pyproject.toml /usr/src/app/
COPY poetry.lock /usr/src/app/
RUN poetry install --only main

COPY entrypoint.py /usr/src/app/

CMD [ "poetry", "-C", "/usr/src/app/", "run", "python", "/usr/src/app/entrypoint.py" ]
