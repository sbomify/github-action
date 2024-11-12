#!/bin/bash

poetry \
    -C /usr/src/app/ \
    run python /usr/src/app/entrypoint.py
