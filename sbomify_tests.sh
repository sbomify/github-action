#!/bin/bash
source /etc/profile.d/venv.sh

poetry run python tests/test_entrypoint.py
