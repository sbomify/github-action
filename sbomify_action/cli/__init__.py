"""CLI module for sbomify-action.

This module provides the command-line interface for the sbomify action.
It supports both CLI arguments and environment variables for configuration.
"""

from .main import (
    Config,
    build_config,
    cli,
    evaluate_boolean,
    load_config,
    main,
    run_pipeline,
)

__all__ = [
    "cli",
    "main",
    "Config",
    "build_config",
    "load_config",
    "run_pipeline",
    "evaluate_boolean",
]
