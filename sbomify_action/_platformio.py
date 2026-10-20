"""Read what PlatformIO installed for a project.

PlatformIO, the usual build system for Arduino and ESP32 firmware, has no lock
file. `platformio.ini` declares `lib_deps` -- often as ranges such as
`bblanchon/ArduinoJson@^7.0.0` -- and `pio pkg install` resolves them into
`.pio/libdeps/<env>/<library>/`. What it resolved is recorded beside each
library in a `.piopm` file the package manager writes at install time:

    {"type": "library", "name": "ArduinoJson", "version": "7.4.3",
     "spec": {"owner": "bblanchon", "id": 64, "name": "ArduinoJson", "uri": null}}

Libraries installed from git keep the same file inside their `.git/`
directory, with the source in `spec.uri` and the commit folded into the
version (`1.2.7+sha.5438181`).

That is the closest thing to a lock file the ecosystem has: the exact version,
the registry owner and the source, written by the resolver rather than by the
library's author. The `library.json` beside it is the author's manifest, which
is why it is not read here -- many Arduino libraries ship only
`library.properties`, and a git checkout's `library.json` names the release it
was cut from, not the commit that was installed.
"""

from __future__ import annotations

import configparser
import json
import re
from dataclasses import dataclass
from pathlib import Path

from packageurl import PackageURL

from sbomify_action.logging_config import logger

PLATFORMIO_INI = "platformio.ini"
METADATA_FILE = ".piopm"
REGISTRY_URL = "https://registry.platformio.org"

#: A registry version requirement that names exactly one release. Anything
#: carrying ^, ~, a comparison or a wildcard lets PlatformIO pick at install.
_EXACT_VERSION = re.compile(r"^=?\s*v?\d+(\.\d+)*([-+][0-9A-Za-z.\-+]*)?$")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class InstalledLibrary:
    """One library as PlatformIO's package manager recorded it."""

    name: str
    version: str
    owner: str | None = None
    uri: str | None = None
    commit: str | None = None

    @property
    def from_registry(self) -> bool:
        return self.uri is None and self.owner is not None

    @property
    def purl(self) -> str:
        """Package URL for this library.

        purl-spec has no `platformio` type, so registry libraries are
        `generic` with the registry named, and git libraries are identified by
        their repository and commit -- `github` where that is where they live.
        """
        if self.uri:
            url = _strip_vcs_prefix(self.uri)
            github = re.match(r"^https?://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?$", url)
            if github:
                return PackageURL(
                    type="github",
                    namespace=github.group(1),
                    name=github.group(2),
                    version=self.commit or self.version,
                ).to_string()
            vcs_url = f"git+{url}@{self.commit}" if self.commit else f"git+{url}"
            return PackageURL(
                type="generic", name=self.name, version=self.version, qualifiers={"vcs_url": vcs_url}
            ).to_string()
        return PackageURL(
            type="generic",
            namespace=self.owner,
            name=self.name,
            version=self.version,
            qualifiers={"repository_url": REGISTRY_URL},
        ).to_string()


def _strip_vcs_prefix(uri: str) -> str:
    """`git+https://host/repo.git#ref` -> `https://host/repo.git`."""
    url = uri.split("#", 1)[0]
    return url[4:] if url.startswith("git+") else url


def _read_config(ini_path: Path) -> configparser.ConfigParser:
    # PlatformIO interpolates `${section.option}` itself; configparser's own
    # interpolation would choke on it.
    config = configparser.ConfigParser(interpolation=None, strict=False)
    config.read(ini_path, encoding="utf-8")
    return config


def libdeps_dir(ini_path: Path) -> Path:
    """Where `pio pkg install` puts libraries for this project.

    Honours `[platformio] workspace_dir` and `libdeps_dir`, which projects
    use to move `.pio` out of the source tree.
    """
    project = ini_path.parent
    config = _read_config(ini_path)
    workspace = Path(config.get("platformio", "workspace_dir", fallback=".pio"))
    default = (workspace if workspace.is_absolute() else project / workspace) / "libdeps"
    configured = config.get("platformio", "libdeps_dir", fallback=None)
    if not configured or "$" in configured:
        return default
    path = Path(configured)
    return path if path.is_absolute() else project / path


def _git_commit(git_dir: Path) -> str | None:
    """The full commit a git-installed library is checked out at."""
    try:
        head = (git_dir / "HEAD").read_text().strip()
    except OSError:
        return None
    if head.startswith("ref: "):
        try:
            head = (git_dir / head[5:]).read_text().strip()
        except OSError:
            return None
    return head if _FULL_SHA.match(head) else None


def _read_metadata(library_dir: Path) -> InstalledLibrary | None:
    for candidate in (library_dir / METADATA_FILE, library_dir / ".git" / METADATA_FILE):
        if candidate.is_file():
            break
    else:
        return None
    try:
        data = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.debug(f"PlatformIO: unreadable {candidate}: {e}")
        return None
    if not isinstance(data, dict) or data.get("type") != "library":
        return None
    name, version = data.get("name"), data.get("version")
    if not (isinstance(name, str) and name and isinstance(version, str) and version):
        return None
    spec = data.get("spec")
    if not isinstance(spec, dict):
        spec = {}
    uri = spec.get("uri") or None
    return InstalledLibrary(
        name=name,
        version=version,
        owner=spec.get("owner") or None,
        uri=uri,
        commit=_git_commit(library_dir / ".git") if uri else None,
    )


def installed_libraries(ini_path: Path) -> list[InstalledLibrary]:
    """Every library installed for any environment of the project, once each.

    Each `[env:...]` gets its own copy under `libdeps/<env>/`, so a library
    shared by three environments is on disk three times. It is one component.
    """
    root = libdeps_dir(ini_path)
    if not root.is_dir():
        return []
    found: list[InstalledLibrary] = []
    seen: set[InstalledLibrary] = set()
    for env_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for library_dir in sorted(p for p in env_dir.iterdir() if p.is_dir()):
            library = _read_metadata(library_dir)
            if library is None:
                logger.debug(f"PlatformIO: no {METADATA_FILE} in {library_dir}, skipping")
                continue
            if library not in seen:
                seen.add(library)
                found.append(library)
    return found


def declared_lib_deps(ini_path: Path) -> list[str]:
    """Every `lib_deps` entry across the project's sections, as written."""
    config = _read_config(ini_path)
    entries: list[str] = []
    for section in config.sections():
        if section != "env" and not section.startswith("env:"):
            continue
        raw = config.get(section, "lib_deps", fallback="")
        for line in raw.replace(",", "\n").splitlines():
            entry = line.split(";", 1)[0].strip()
            if entry:
                entries.append(entry)
    return entries


def _entry_is_pinned(entry: str) -> bool:
    # `${env.lib_deps}` pulls in another section's entries, which are checked
    # where they are written.
    if entry.startswith("${"):
        return True
    # A local path or symlink is the project's own code, not a resolution.
    if entry.startswith(("file://", "symlink://")) or entry.startswith(("/", "./", "../")):
        return True
    if "://" in entry or entry.startswith("git@"):
        # A git source names its revision after `#`. Without one it follows
        # the default branch.
        return "#" in entry
    _, sep, requirement = entry.partition("@")
    return bool(sep) and bool(_EXACT_VERSION.match(requirement.strip()))


def lib_deps_are_pinned(ini_path: Path) -> bool:
    """Whether every declared library names exactly one version.

    The installed set records what one build resolved. Whether the next build
    resolves the same thing depends on this. Unreadable or empty counts as
    not pinned, for the same reason as an unreadable requirements.txt.
    """
    try:
        entries = declared_lib_deps(ini_path)
    except (OSError, configparser.Error):
        return False
    return bool(entries) and all(_entry_is_pinned(entry) for entry in entries)
