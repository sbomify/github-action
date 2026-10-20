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
is why versions are not read from it -- many Arduino libraries ship only
`library.properties`, and a git checkout's `library.json` names the release it
was cut from, not the commit that was installed. It is read only for the
names a library depends on, which is all it can say about the graph.

`platformio.ini` itself is read the way PlatformIO reads it (see
`ProjectConfig`): `extends`, `[env]` inheritance, `${section.option}`
interpolation, `extra_configs` and the `PLATFORMIO_*_DIR` variables all decide
what a project declares and where it installed it.
"""

from __future__ import annotations

import configparser
import glob
import json
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from packageurl import PackageURL

from sbomify_action.logging_config import logger

PLATFORMIO_INI = "platformio.ini"
METADATA_FILE = ".piopm"
REGISTRY_URL = "https://registry.platformio.org"

#: A registry requirement that names exactly one release. PlatformIO matches
#: with semantic_version's SimpleSpec, where a partial version is a wildcard:
#: `@2.8` accepts 2.8.0 and 2.8.1, and `@1` any 1.x. Only a full
#: MAJOR.MINOR.PATCH, optionally with `=`, pins. A leading `v` is not a
#: version PlatformIO accepts at all.
_EXACT_VERSION = re.compile(r"^=?\s*\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?(\+[0-9A-Za-z.\-]+)?$")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
#: A git ref that is conventionally immutable: a full commit, or a tag that
#: looks like a release. Anything else -- `#develop`, `#main` -- is a branch
#: as far as the syntax can tell, and a branch moves.
_IMMUTABLE_REF = re.compile(r"^([0-9a-f]{40}|v?\d+(\.\d+)*([-+.][0-9A-Za-z.\-+]*)?)$")
_ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")

# PlatformIO's own patterns (platformio/project/config.py).
_VARIABLE = re.compile(r"\$\{(?:([^\.\}\()]+)\.)?([^\}]+)\}")
_INLINE_COMMENT = re.compile(r"\s+;.*$")


class _Unresolvable(Exception):
    """An interpolation PlatformIO would resolve from something we cannot see."""


class ProjectConfig:
    """The subset of PlatformIO's ProjectConfig needed to read lib_deps.

    Mirrors platformio/project/config.py in PlatformIO 6.x: the same comment
    handling, the same `extends` walk, the same multi-value splitting and the
    same interpolation rules. Anything it cannot resolve is left as the
    literal `${...}` so callers can treat it as unknown rather than guess.
    """

    _SYSENV_DIRS = {
        "workspace_dir": "PLATFORMIO_WORKSPACE_DIR",
        "libdeps_dir": "PLATFORMIO_LIBDEPS_DIR",
    }
    _DEFAULTS = {
        ("platformio", "workspace_dir"): "${PROJECT_DIR}/.pio",
        ("platformio", "libdeps_dir"): "${platformio.workspace_dir}/libdeps",
    }

    def __init__(self, ini_path: Path) -> None:
        self.path = ini_path
        self.project_dir = ini_path.resolve().parent
        self._parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"), interpolation=None, strict=False)
        self._read(ini_path)

    def _read(self, path: Path, seen: set[Path] | None = None) -> None:
        seen = seen if seen is not None else set()
        resolved = path.resolve()
        if resolved in seen:
            return
        seen.add(resolved)
        self._parser.read(path, encoding="utf-8")
        for pattern in self.get_list("platformio", "extra_configs"):
            if "${" in pattern:
                continue
            pattern = os.path.expanduser(pattern)
            if not os.path.isabs(pattern):
                pattern = str(self.project_dir / pattern)
            for item in sorted(glob.glob(pattern, recursive=True)):
                self._read(Path(item), seen)

    @staticmethod
    def parse_multi_values(value: str) -> list[str]:
        items = value.split("\n" if "\n" in value else ", ")
        result = []
        for item in items:
            item = item.strip()
            if not item or item.startswith((";", "#")):
                continue
            if ";" in item:
                item = _INLINE_COMMENT.sub("", item).strip()
            result.append(item)
        return result

    def envs(self) -> list[str]:
        return [section[4:] for section in self._parser.sections() if section.startswith("env:")]

    def _walk(self, root: str) -> Iterable[str]:
        """Sections consulted for an option, in PlatformIO's order."""
        queue = ["env", root] if root.startswith("env:") else [root]
        done: set[str] = set()
        while queue:
            section = queue.pop()
            if section in done:
                continue
            done.add(section)
            if not self._parser.has_section(section):
                continue
            yield section
            if self._parser.has_option(section, "extends"):
                queue.extend(self.parse_multi_values(self._parser.get(section, "extends")))

    def _raw(self, section: str, option: str) -> str | None:
        if section == "platformio" and option in self._SYSENV_DIRS:
            override = os.environ.get(self._SYSENV_DIRS[option])
            if override:
                return override
        for candidate in self._walk(section):
            if self._parser.has_option(candidate, option):
                return self._parser.get(candidate, option)
        return self._DEFAULTS.get((section, option))

    def get(self, section: str, option: str, _depth: int = 0) -> str | None:
        """An option's value with interpolations expanded where possible."""
        value = self._raw(section, option)
        if value is None or "${" not in value:
            return value
        if _depth > 20:
            raise _Unresolvable(f"{section}.{option} recurses")

        def expand(match: re.Match[str]) -> str:
            ref_section, ref_option = match.group(1), match.group(2)
            if ref_section is None:
                if ref_option == "PROJECT_DIR":
                    return str(self.project_dir)
                # Build-time (SCons) variables stay as written.
                return match.group(0)
            if ref_section == "sysenv":
                return os.environ.get(ref_option, "")
            if ref_section == "this":
                if ref_option == "__env__":
                    if not section.startswith("env:"):
                        raise _Unresolvable("${this.__env__} outside an env section")
                    return section[4:]
                ref_section = section
            try:
                nested = self.get(ref_section, ref_option, _depth + 1)
            except _Unresolvable:
                return match.group(0)
            if nested is None:
                return match.group(0)
            return nested

        return _VARIABLE.sub(expand, value)

    def get_list(self, section: str, option: str) -> list[str]:
        try:
            value = self.get(section, option)
        except _Unresolvable:
            value = self._raw(section, option)
        return self.parse_multi_values(value) if value else []

    def get_dir(self, option: str) -> Path | None:
        """`workspace_dir` / `libdeps_dir`, or None if it cannot be resolved."""
        try:
            value = self.get("platformio", option)
        except _Unresolvable:
            return None
        if not value or "${" in value:
            return None
        path = Path(os.path.expanduser(value.strip()))
        return path if path.is_absolute() else self.project_dir / path


@dataclass(frozen=True)
class InstalledLibrary:
    """One library as PlatformIO's package manager recorded it."""

    name: str
    version: str
    owner: str | None = None
    uri: str | None = None
    commit: str | None = None
    #: Names this library's own manifest says it needs, as written there.
    requires: tuple[str, ...] = field(default=(), compare=False)

    @property
    def from_registry(self) -> bool:
        return self.uri is None and self.owner is not None

    @property
    def from_git(self) -> bool:
        return bool(self.uri) and _is_git_uri(str(self.uri))

    @property
    def purl(self) -> str:
        """Package URL for this library.

        purl-spec has no `platformio` type, so registry libraries are
        `generic` with the registry named, git libraries are identified by
        their repository and commit -- `github` where that is where they live
        -- and archives by the URL they were downloaded from.
        """
        if self.uri and self.from_git:
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
        if self.uri:
            return PackageURL(
                type="generic", name=self.name, version=self.version, qualifiers={"download_url": self.uri}
            ).to_string()
        if self.owner:
            return PackageURL(
                type="generic",
                namespace=self.owner,
                name=self.name,
                version=self.version,
                qualifiers={"repository_url": REGISTRY_URL},
            ).to_string()
        return PackageURL(type="generic", name=self.name, version=self.version).to_string()


def _is_git_uri(uri: str) -> bool:
    url = uri.split("#", 1)[0]
    if url.lower().endswith(_ARCHIVE_SUFFIXES):
        return False
    return url.startswith(("git+", "git@", "git://")) or url.endswith(".git")


def _strip_vcs_prefix(uri: str) -> str:
    """`git+https://host/repo.git#ref` -> `https://host/repo.git`."""
    url = uri.split("#", 1)[0]
    return url[4:] if url.startswith("git+") else url


def libdeps_dir(ini_path: Path) -> Path | None:
    """Where `pio pkg install` put libraries for this project.

    Resolved the way PlatformIO resolves it: `PLATFORMIO_LIBDEPS_DIR` /
    `PLATFORMIO_WORKSPACE_DIR`, then `[platformio] libdeps_dir` /
    `workspace_dir` with `~` and `${...}` expanded, then `.pio/libdeps`.
    None when the configuration names something that cannot be resolved here.
    """
    return ProjectConfig(ini_path).get_dir("libdeps_dir")


def _git_commit(git_dir: Path) -> str | None:
    """The full commit a git-installed library is checked out at."""
    try:
        head = (git_dir / "HEAD").read_text().strip()
    except OSError:
        return None
    if not head.startswith("ref: "):
        return head if _FULL_SHA.match(head) else None
    ref = head[5:]
    try:
        commit = (git_dir / ref).read_text().strip()
        return commit if _FULL_SHA.match(commit) else None
    except OSError:
        pass
    # After `git gc` the ref lives in packed-refs: "<sha> <ref>" per line.
    try:
        packed = (git_dir / "packed-refs").read_text()
    except OSError:
        return None
    for line in packed.splitlines():
        sha, _, name = line.partition(" ")
        if name.strip() == ref and _FULL_SHA.match(sha):
            return sha
    return None


def _manifest_requirements(library_dir: Path) -> tuple[str, ...]:
    """Dependency names from library.json, or library.properties' `depends`."""
    names: list[str] = []
    manifest = library_dir / "library.json"
    if manifest.is_file():
        try:
            dependencies = json.loads(manifest.read_text(encoding="utf-8")).get("dependencies") or []
        except (OSError, ValueError, AttributeError):
            dependencies = []
        if isinstance(dependencies, dict):
            names.extend(str(name) for name in dependencies)
        elif isinstance(dependencies, list):
            for dependency in dependencies:
                if isinstance(dependency, dict) and dependency.get("name"):
                    owner = dependency.get("owner")
                    names.append(f"{owner}/{dependency['name']}" if owner else str(dependency["name"]))
                elif isinstance(dependency, str):
                    names.append(dependency)
        return tuple(names)
    properties = library_dir / "library.properties"
    if properties.is_file():
        try:
            for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "depends":
                    # "ArduinoJson (>=6.0.0), Adafruit GFX Library"
                    names.extend(part.split("(", 1)[0].strip() for part in value.split(",") if part.strip())
        except OSError:
            pass
    return tuple(names)


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
        commit=_git_commit(library_dir / ".git") if uri and _is_git_uri(uri) else None,
        requires=_manifest_requirements(library_dir),
    )


def installed_libraries(ini_path: Path) -> list[InstalledLibrary]:
    """Every library installed for the project's environments, once each.

    Each `[env:...]` gets its own copy under `libdeps/<env>/`, so a library
    shared by three environments is on disk three times. It is one
    component, and "the same" means the same purl -- that is the bom-ref.
    Directories for environments no longer in the configuration are left
    over from an earlier build and are not read.
    """
    config = ProjectConfig(ini_path)
    root = config.get_dir("libdeps_dir")
    if root is None or not root.is_dir():
        return []
    envs = set(config.envs())
    found: list[InstalledLibrary] = []
    seen: set[str] = set()
    for env_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        if envs and env_dir.name not in envs:
            logger.debug(f"PlatformIO: {env_dir.name} is not an environment in {ini_path.name}, skipping")
            continue
        for library_dir in sorted(p for p in env_dir.iterdir() if p.is_dir()):
            library = _read_metadata(library_dir)
            if library is None:
                logger.debug(f"PlatformIO: no {METADATA_FILE} in {library_dir}, skipping")
                continue
            if library.purl not in seen:
                seen.add(library.purl)
                found.append(library)
    return found


def _env_lib_deps(config: ProjectConfig) -> list[str]:
    sections = [f"env:{env}" for env in config.envs()] or ["env"]
    entries: list[str] = []
    for section in sections:
        try:
            value = config.get(section, "lib_deps")
        except _Unresolvable:
            value = config._raw(section, "lib_deps")
        for entry in config.parse_multi_values(value or ""):
            if entry not in entries:
                entries.append(entry)
    return entries


def declared_lib_deps(ini_path: Path) -> list[str]:
    """Every `lib_deps` entry the project's environments end up with.

    Each environment's value is resolved through `extends`, `[env]` and
    interpolation exactly as PlatformIO would. An entry that still contains
    `${...}` referred to something not visible here.
    """
    return _env_lib_deps(ProjectConfig(ini_path))


def _entry_is_pinned(entry: str) -> bool:
    # Interpolation that could not be resolved: unknown, so not pinned.
    if "${" in entry:
        return False
    # A local path or symlink is the project's own code, not a resolution.
    if entry.startswith(("file://", "symlink://")) or entry.startswith(("/", "./", "../", "~")):
        return True
    if "://" in entry or entry.startswith("git@"):
        url, _, ref = entry.partition("#")
        if url.lower().endswith(_ARCHIVE_SUFFIXES):
            # An archive URL names one file.
            return True
        # Anything else is cloned. A git source pins only to a commit or a
        # release-shaped tag; a branch name, or none, follows whatever is
        # pushed next.
        return bool(_IMMUTABLE_REF.match(ref.strip()))
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


def _identity(entry: str) -> tuple[str | None, str]:
    """(owner, lowercased name or source URL) a lib_deps entry asks for."""
    if "://" in entry or entry.startswith("git@"):
        return None, _strip_vcs_prefix(entry).rstrip("/").lower()
    spec = entry.split("@", 1)[0].strip()
    owner, _, name = spec.rpartition("/")
    return (owner or None), name.strip().lower()


def _matches(library: InstalledLibrary, owner: str | None, name: str) -> bool:
    if "://" in name or name.startswith("git@"):
        return bool(library.uri) and _strip_vcs_prefix(str(library.uri)).rstrip("/").lower() == name
    if library.name.lower() != name:
        return False
    return owner is None or (library.owner or "").lower() == owner.lower()


def dependency_graph(ini_path: Path, libraries: list[InstalledLibrary]) -> tuple[list[str], dict[str, list[str]]]:
    """(direct dependencies, edges between libraries), as purls.

    Direct means named in `lib_deps`. Edges come from each library's own
    manifest, matched by name against what was installed; a name that was
    not installed (an optional or platform-specific dependency) has no edge.
    """
    try:
        wanted = [_identity(entry) for entry in declared_lib_deps(ini_path) if "${" not in entry]
    except (OSError, configparser.Error):
        wanted = []
    direct = [library.purl for library in libraries if any(_matches(library, o, n) for o, n in wanted)]
    edges: dict[str, list[str]] = {}
    for library in libraries:
        targets: list[str] = []
        for requirement in library.requires:
            owner, name = _identity(requirement)
            targets.extend(other.purl for other in libraries if other is not library and _matches(other, owner, name))
        edges[library.purl] = sorted(set(targets))
    return direct, edges
