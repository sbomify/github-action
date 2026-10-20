"""PlatformIO projects: platformio.ini plus what `pio pkg install` recorded.

The fixtures mirror what PlatformIO 6.2 writes: a `.piopm` beside each
registry library, and inside `.git/` for a library installed from git.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from sbomify_action._generation.generators.platformio import PlatformIOGenerator
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action._generation.registry import (
    RECOMMENDED_ACTION,
    records_a_resolution,
    resolution_was_inferred,
)
from sbomify_action._hash_enrichment.enricher import create_default_registry
from sbomify_action._hash_enrichment.models import normalize_package_name
from sbomify_action._hash_enrichment.parsers.platformio import PlatformIOParser, _registry_versions
from sbomify_action._platformio import (
    InstalledLibrary,
    declared_lib_deps,
    installed_libraries,
    lib_deps_are_pinned,
    libdeps_dir,
)

COMMIT = "5438181440c71cf30bbdc347b0b1597ae3ebf77d"

INI = """\
[env]
lib_deps =
    bblanchon/ArduinoJson@^7.0.0

[env:cyd]
platform = espressif32
lib_deps =
    ${env.lib_deps}
    https://github.com/lovyan03/LovyanGFX.git#1.2.7
    knolleary/PubSubClient@2.8 ; mqtt

[env:native]
platform = native
"""


def _registry_library(env_dir: Path, name: str, version: str, owner: str) -> None:
    library = env_dir / name
    library.mkdir(parents=True)
    spec = {"owner": owner, "id": 1, "name": name, "requirements": None, "uri": None}
    (library / ".piopm").write_text(json.dumps({"type": "library", "name": name, "version": version, "spec": spec}))
    # The author's manifest. Present on purpose: it must not be what is read.
    (library / "library.json").write_text(json.dumps({"name": name, "version": "0.0.0-author"}))


def _git_library(env_dir: Path, name: str, version: str, uri: str) -> None:
    git = env_dir / name / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text(f"{COMMIT}\n")
    spec = {"owner": None, "id": None, "name": name, "requirements": None, "uri": uri}
    (git / ".piopm").write_text(json.dumps({"type": "library", "name": name, "version": version, "spec": spec}))


def _project(tmp_path: Path, ini: str = INI) -> Path:
    ini_path = tmp_path / "platformio.ini"
    ini_path.write_text(ini)
    cyd = tmp_path / ".pio" / "libdeps" / "cyd"
    native = tmp_path / ".pio" / "libdeps" / "native"
    _registry_library(cyd, "ArduinoJson", "7.4.3", "bblanchon")
    _registry_library(cyd, "PubSubClient", "2.8.0", "knolleary")
    _git_library(cyd, "LovyanGFX", "1.2.7+sha.5438181", "git+https://github.com/lovyan03/LovyanGFX.git#1.2.7")
    # The same library again for another environment.
    _registry_library(native, "ArduinoJson", "7.4.3", "bblanchon")
    (cyd / "integrity.dat").write_text("bblanchon/ArduinoJson@^7.0.0\n")
    return ini_path


class TestInstalledLibraries:
    def test_each_library_is_read_once_across_environments(self, tmp_path):
        libraries = installed_libraries(_project(tmp_path))
        assert sorted(library.name for library in libraries) == ["ArduinoJson", "LovyanGFX", "PubSubClient"]

    def test_the_resolver_record_wins_over_the_author_manifest(self, tmp_path):
        libraries = {library.name: library for library in installed_libraries(_project(tmp_path))}
        assert libraries["ArduinoJson"].version == "7.4.3"
        assert libraries["ArduinoJson"].owner == "bblanchon"

    def test_git_libraries_carry_their_source_and_full_commit(self, tmp_path):
        libraries = {library.name: library for library in installed_libraries(_project(tmp_path))}
        lovyan = libraries["LovyanGFX"]
        assert lovyan.uri == "git+https://github.com/lovyan03/LovyanGFX.git#1.2.7"
        assert lovyan.commit == COMMIT
        assert not lovyan.from_registry

    def test_a_branch_checkout_resolves_through_the_ref(self, tmp_path):
        git = tmp_path / ".git"
        (git / "refs" / "heads").mkdir(parents=True)
        (git / "HEAD").write_text("ref: refs/heads/main\n")
        (git / "refs" / "heads" / "main").write_text(f"{COMMIT}\n")
        spec = {"owner": None, "uri": "git+https://example.com/lib.git"}
        (git / ".piopm").write_text(json.dumps({"type": "library", "name": "lib", "version": "1.0.0", "spec": spec}))
        from sbomify_action._platformio import _read_metadata

        library = _read_metadata(tmp_path)
        assert library is not None
        assert library.commit == COMMIT

    def test_directories_without_metadata_or_of_other_types_are_skipped(self, tmp_path):
        ini_path = _project(tmp_path)
        cyd = tmp_path / ".pio" / "libdeps" / "cyd"
        (cyd / "Hand-copied").mkdir()
        (cyd / "Broken").mkdir()
        (cyd / "Broken" / ".piopm").write_text("{not json")
        (cyd / "Tool").mkdir()
        (cyd / "Tool" / ".piopm").write_text(json.dumps({"type": "tool", "name": "x", "version": "1"}))
        assert len(installed_libraries(ini_path)) == 3

    def test_nothing_installed_is_an_empty_list(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        assert installed_libraries(ini_path) == []

    def test_a_relocated_libdeps_dir_is_honoured(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\nlibdeps_dir = deps\n\n[env:x]\nlib_deps = a/b@1.0.0\n")
        assert libdeps_dir(ini_path) == tmp_path / "deps"
        _registry_library(tmp_path / "deps" / "x", "b", "1.0.0", "a")
        assert [library.name for library in installed_libraries(ini_path)] == ["b"]

    def test_a_relocated_workspace_is_honoured(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[platformio]\nworkspace_dir = build\n")
        assert libdeps_dir(ini_path) == tmp_path / "build" / "libdeps"


class TestPurls:
    def test_registry_library(self):
        library = InstalledLibrary(name="ArduinoJson", version="7.4.3", owner="bblanchon")
        assert library.purl == (
            "pkg:generic/bblanchon/ArduinoJson@7.4.3?repository_url=https://registry.platformio.org"
        )

    def test_github_library_is_pinned_to_its_commit(self):
        library = InstalledLibrary(
            name="LovyanGFX",
            version="1.2.7+sha.5438181",
            uri="git+https://github.com/lovyan03/LovyanGFX.git#1.2.7",
            commit=COMMIT,
        )
        assert library.purl == f"pkg:github/lovyan03/lovyangfx@{COMMIT}"

    def test_other_git_hosts_keep_the_vcs_url(self):
        library = InstalledLibrary(
            name="lib", version="1.0.0", uri="git+https://git.example.com/team/lib.git#v1", commit=COMMIT
        )
        assert library.purl.startswith("pkg:generic/lib@1.0.0?vcs_url=")
        assert COMMIT in library.purl


class TestLibDepsPinning:
    def _ini(self, tmp_path: Path, lib_deps: str) -> Path:
        path = tmp_path / "platformio.ini"
        path.write_text(f"[env:x]\nlib_deps =\n{lib_deps}\n")
        return path

    def test_entries_are_read_from_every_env_section(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        assert declared_lib_deps(ini_path) == [
            "bblanchon/ArduinoJson@^7.0.0",
            "${env.lib_deps}",
            "https://github.com/lovyan03/LovyanGFX.git#1.2.7",
            "knolleary/PubSubClient@2.8",
        ]

    def test_a_range_is_not_pinned(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        assert not lib_deps_are_pinned(ini_path)

    def test_exact_versions_and_git_revisions_are_pinned(self, tmp_path):
        path = self._ini(
            tmp_path,
            "    bblanchon/ArduinoJson @ 7.4.3\n"
            "    knolleary/PubSubClient@=2.8\n"
            "    https://github.com/lovyan03/LovyanGFX.git#1.2.7\n"
            "    file://../local-lib\n",
        )
        assert lib_deps_are_pinned(path)

    def test_a_bare_name_is_not_pinned(self, tmp_path):
        assert not lib_deps_are_pinned(self._ini(tmp_path, "    bblanchon/ArduinoJson"))

    def test_a_git_url_without_a_revision_is_not_pinned(self, tmp_path):
        assert not lib_deps_are_pinned(self._ini(tmp_path, "    https://github.com/lovyan03/LovyanGFX.git"))

    def test_no_lib_deps_is_not_a_recorded_resolution(self, tmp_path):
        path = tmp_path / "platformio.ini"
        path.write_text("[env:x]\nplatform = native\n")
        assert not lib_deps_are_pinned(path)

    def test_the_pipeline_discloses_unpinned_lib_deps(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        assert resolution_was_inferred(str(ini_path))
        assert not records_a_resolution(str(ini_path))
        assert "platformio.ini" in RECOMMENDED_ACTION

    def test_the_pipeline_trusts_pinned_lib_deps(self, tmp_path):
        path = self._ini(tmp_path, "    bblanchon/ArduinoJson@7.4.3")
        assert not resolution_was_inferred(str(path))
        assert records_a_resolution(str(path))


class TestGenerator:
    def test_it_claims_platformio_ini_and_nothing_else(self, tmp_path):
        generator = PlatformIOGenerator()
        assert generator.supports(GenerationInput(lock_file=str(tmp_path / "platformio.ini"), output_file="o.json"))
        assert not generator.supports(GenerationInput(lock_file=str(tmp_path / "library.json"), output_file="o.json"))

    def test_it_rejects_an_unsupported_spec_version(self, tmp_path):
        generator = PlatformIOGenerator()
        assert not generator.supports(
            GenerationInput(lock_file=str(tmp_path / "platformio.ini"), output_file="o.json", spec_version="9.9")
        )

    def test_it_writes_one_component_per_installed_library(self, tmp_path):
        output = tmp_path / "out" / "sbom.json"
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(_project(tmp_path)), output_file=str(output), output_format="cyclonedx")
        )
        assert result.success
        document = json.loads(output.read_text())
        assert document["metadata"]["component"]["type"] == "firmware"
        components = {component["name"]: component for component in document["components"]}
        assert set(components) == {"ArduinoJson", "LovyanGFX", "PubSubClient"}
        assert components["ArduinoJson"]["group"] == "bblanchon"
        assert components["LovyanGFX"]["externalReferences"][0]["type"] == "vcs"
        assert components["LovyanGFX"]["purl"].endswith(COMMIT)

    def test_spdx_goes_through_the_shared_conversion(self, tmp_path):
        output = tmp_path / "sbom.spdx.json"
        with patch("sbomify_action._generation.generators.platformio.convert_to_spdx") as convert:
            result = PlatformIOGenerator().generate(
                GenerationInput(lock_file=str(_project(tmp_path)), output_file=str(output), output_format="spdx")
            )
        assert result.success
        assert result.spec_version == "2.3"
        convert.assert_called_once()
        # The staged CycloneDX document is cleaned up.
        assert not list(tmp_path.glob(".*.cdx.json"))

    def test_uninstalled_libraries_say_what_to_run(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text(INI)
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(ini_path), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
        )
        assert not result.success
        assert "pio pkg install" in (result.error_message or "")

    def test_a_project_without_lib_deps_fails_plainly(self, tmp_path):
        ini_path = tmp_path / "platformio.ini"
        ini_path.write_text("[env:x]\nplatform = native\n")
        result = PlatformIOGenerator().generate(
            GenerationInput(lock_file=str(ini_path), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
        )
        assert not result.success
        assert "declares no lib_deps" in (result.error_message or "")

    def test_it_is_registered(self):
        from sbomify_action._generation.generator import create_default_registry as create_generators

        names = [generator["name"] for generator in create_generators().list_generators()]
        assert "platformio" in names


def _response(status: int, body: dict) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = body
    return response


class TestRegistryHashes:
    SHA = "2ffda9c356d109224218da192fdeeab6f024ee8b25bed61a26dc56e38610288a"

    def test_the_registry_may_hold_a_shorter_version(self):
        assert _registry_versions("2.8.0") == ["2.8.0", "2.8"]
        assert _registry_versions("7.4.3") == ["7.4.3"]
        assert _registry_versions("1.0.0") == ["1.0.0", "1.0"]

    def test_registry_libraries_get_the_published_archive_hash(self, tmp_path):
        ini_path = _project(tmp_path)

        def fake_get(url, params, headers, timeout):
            name, version = url.rsplit("/", 1)[-1], params["version"]
            if (name, version) == ("PubSubClient", "2.8"):
                return _response(200, {"version": {"name": "2.8", "files": [{"checksum": {"sha256": self.SHA}}]}})
            if name == "ArduinoJson":
                return _response(200, {"version": {"name": version, "files": [{"checksum": {"sha256": "ab" * 32}}]}})
            return _response(404, {})

        with patch("sbomify_action._hash_enrichment.parsers.platformio.requests.get", side_effect=fake_get) as get:
            hashes = {h.name: h for h in PlatformIOParser().parse(ini_path)}

        assert hashes["PubSubClient"].value == self.SHA
        assert hashes["PubSubClient"].version == "2.8.0"  # matched against what was installed
        assert hashes["ArduinoJson"].value == "ab" * 32
        # Git libraries are pinned by commit in their purl; the registry is not asked.
        assert "LovyanGFX" not in hashes
        assert all("LovyanGFX" not in call.args[0] for call in get.call_args_list)

    def test_an_unreachable_registry_yields_no_hashes(self, tmp_path):
        ini_path = _project(tmp_path)
        with patch(
            "sbomify_action._hash_enrichment.parsers.platformio.requests.get",
            side_effect=requests.ConnectionError("offline"),
        ):
            assert PlatformIOParser().parse(ini_path) == []

    def test_a_version_mismatch_is_not_trusted(self, tmp_path):
        ini_path = _project(tmp_path)
        body = {"version": {"name": "9.9.9", "files": [{"checksum": {"sha256": "cd" * 32}}]}}
        with patch(
            "sbomify_action._hash_enrichment.parsers.platformio.requests.get", return_value=_response(200, body)
        ):
            assert PlatformIOParser().parse(ini_path) == []

    def test_the_parser_is_registered_for_platformio_ini(self):
        parser = create_default_registry().get_parser_for("platformio.ini")
        assert parser is not None
        assert parser.name == "platformio"

    def test_spdx_names_carry_the_owner(self):
        assert normalize_package_name("bblanchon/ArduinoJson", "platformio") == "arduinojson"
        assert normalize_package_name("ArduinoJson", "platformio") == "arduinojson"


def test_spdx_conversion_hands_syft_absolute_paths(tmp_path, monkeypatch):
    """syft runs in the project directory, so relative paths pointed nowhere."""
    from sbomify_action._generation import utils

    calls = []
    monkeypatch.setattr(utils, "ensure_runtime", lambda *a, **k: None)
    monkeypatch.setattr(utils, "run_command", lambda cmd, *a, **k: calls.append(cmd))
    monkeypatch.chdir(tmp_path)
    utils.convert_to_spdx(Path("staged.cdx.json"), Path("out.json"), tmp_path / "project")
    command = calls[0]
    assert command[2] == str(tmp_path / "staged.cdx.json")
    assert command[-1] == f"spdx-json={tmp_path / 'out.json'}"
