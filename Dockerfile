FROM python:3-slim-bullseye

WORKDIR /usr/src/app

RUN python -m pip install pipx --no-cache
RUN pipx install poetry --global
RUN pipx ensurepath --global

COPY pyproject.toml /usr/src/app/
COPY poetry.lock /usr/src/app/
RUN poetry install --only main

COPY entrypoint.py /usr/src/app/

CMD [ "poetry", "run", "python", "/usr/src/app/entrypoint.py" ]
