"""Upload destination implementations."""

from .dependency_track import DependencyTrackConfig, DependencyTrackDestination
from .sbomify import SbomifyDestination

__all__ = [
    "SbomifyDestination",
    "DependencyTrackDestination",
    "DependencyTrackConfig",
]
