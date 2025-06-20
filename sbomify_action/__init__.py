"""sbomify-action package for SBOM generation and enrichment."""


def _get_version() -> str:
    """Get package version with fallback mechanisms."""
    # Method 1: Try importlib.metadata (preferred for installed packages)
    try:
        from importlib.metadata import version

        return version("sbomify-github-action")
    except ImportError:
        pass
    except Exception:
        pass

    # Method 2: Try reading from pyproject.toml directly
    try:
        from pathlib import Path

        import tomllib

        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                pyproject_data = tomllib.load(f)
            return pyproject_data.get("tool", {}).get("poetry", {}).get("version", "unknown")
    except ImportError:
        # Python < 3.11 doesn't have tomllib
        pass
    except Exception:
        pass

    # Method 3: Try toml library as fallback for older Python
    try:
        from pathlib import Path

        import toml

        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "r") as f:
                pyproject_data = toml.load(f)
            return pyproject_data.get("tool", {}).get("poetry", {}).get("version", "unknown")
    except ImportError:
        pass
    except Exception:
        pass

    # Final fallback
    return "unknown"


__version__ = _get_version()
