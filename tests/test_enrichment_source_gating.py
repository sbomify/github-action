"""A source is worth a network call only if it can fill something missing.

The early stop needed *all three* core fields -- description, licenses,
supplier -- before it would stop asking. clearlydefined sits at priority 75
and can essentially only supply licences, so it was consulted whenever
`description` or `supplier` was missing, neither of which it can supply,
and its licence arrived redundant.

Across a 251-project run that filled the persistent cache with 1,178
clearlydefined entries, 1,020 of them holding real licence data, while
contributing zero fields to the finished SBOMs. Those lookups are not free:
a cold one runs to a 25-second upstream deadline, and five consecutive
failures latch the source off for the rest of the run -- so the wasted calls
were also spending the budget that should have been there when licences
really were missing.
"""

from typing import NoReturn

import pytest
import requests
from packageurl import PackageURL

from sbomify_action._enrichment.metadata import NormalizedMetadata
from sbomify_action._enrichment.registry import SourceRegistry, _can_contribute, _still_missing


class _Source:
    def __init__(self, name, priority, returns, provides=None):
        self._name, self._priority, self._returns = name, priority, returns
        self._provides = provides
        self.called = False

    name = property(lambda self: self._name)
    priority = property(lambda self: self._priority)

    @property
    def provides(self):
        return self._provides

    def supports(self, _purl):
        return True

    def fetch(self, _purl, _session):
        self.called = True
        return self._returns


PURL = PackageURL.from_string("pkg:maven/org.example/thing@1.0.0")


def _registry(*sources):
    registry = SourceRegistry()
    for source in sources:
        registry.register(source)
    return registry


def test_a_licence_only_source_is_skipped_when_the_licence_is_present(monkeypatch):
    """The clearlydefined case: consulted for gaps it cannot fill."""
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.get", lambda *_a: (False, None))
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.set", lambda *_a: None)

    primary = _Source("deps.dev", 30, NormalizedMetadata(licenses=["MIT"], source="deps.dev"))
    licence_only = _Source(
        "clearlydefined.io", 75, NormalizedMetadata(licenses=["MIT"]), provides=frozenset({"licenses"})
    )

    _registry(primary, licence_only).fetch_metadata(PURL, requests.Session())

    assert primary.called
    assert not licence_only.called, "nothing it supplies was missing"


def test_it_is_still_consulted_when_the_licence_is_missing(monkeypatch):
    """Which is the case it exists for, and where the JVM needs it.

    36% of Java components in the survey carried no licence at all.
    """
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.get", lambda *_a: (False, None))
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.set", lambda *_a: None)

    primary = _Source("deps.dev", 30, NormalizedMetadata(description="a thing", source="deps.dev"))
    licence_only = _Source(
        "clearlydefined.io", 75, NormalizedMetadata(licenses=["Apache-2.0"]), provides=frozenset({"licenses"})
    )

    result = _registry(primary, licence_only).fetch_metadata(PURL, requests.Session())

    assert licence_only.called, "the licence was missing; this is exactly when to ask"
    assert result is not None and result.licenses == ["Apache-2.0"]


def test_a_source_that_declares_nothing_is_always_consulted(monkeypatch):
    """Undeclared means unknown, which must behave as it always did."""
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.get", lambda *_a: (False, None))
    monkeypatch.setattr("sbomify_action._enrichment.registry.cache.set", lambda *_a: None)

    primary = _Source("deps.dev", 30, NormalizedMetadata(licenses=["MIT"], source="deps.dev"))
    undeclared = _Source("ecosyste.ms", 40, NormalizedMetadata(description="x"))

    _registry(primary, undeclared).fetch_metadata(PURL, requests.Session())

    assert undeclared.called


def test_still_missing_reports_unfilled_fields():
    assert "licenses" in _still_missing(None)
    filled = NormalizedMetadata(licenses=["MIT"], description="d", supplier="s")
    missing = _still_missing(filled)
    assert "licenses" not in missing
    assert "homepage" in missing


def test_can_contribute_is_permissive_without_a_declaration():
    class Bare:
        name = "bare"

    assert _can_contribute(Bare(), {"licenses"})
    assert _can_contribute(Bare(), set())


def _requests_sent(monkeypatch, tmp_path, purl_str: str) -> list[str]:
    """Enrich one purl through every default source and return the URLs asked for.

    The claim is about the wire, not the answer. A local source may well have
    something to say about a package, now or later, so this records what was
    requested rather than asserting on what came back. Recording also survives
    a source that swallows the error: raising alone would let a suppressed
    exception read as a pass.
    """
    from sbomify_action._enrichment.enricher import Enricher, clear_all_caches

    monkeypatch.setenv("SBOMIFY_CACHE_DIR", str(tmp_path))
    # Sources also cache in memory, misses included, so a purl an earlier test
    # looked up would cost nothing here and read as a pass.
    clear_all_caches()

    requested: list[str] = []

    # `Session.get` and `Session.post` both go through `Session.request`,
    # so patching that one method catches every verb, and the URL is the
    # second positional argument rather than something to guess at.
    def record(_self: object, _method: object, url: object = None, **kwargs: object) -> NoReturn:
        requested.append(str(url if url is not None else kwargs.get("url")))
        raise RuntimeError("no network in this test")

    monkeypatch.setattr(requests.Session, "request", record)

    with Enricher() as enricher:
        enricher.fetch_metadata(purl_str)

    return requested


class TestUnpublishedPurlsNeverReachARegistry:
    """A package no registry publishes has nowhere to be looked up.

    It started with the type we mint: `_yocto/purl.py` gives a Yocto recipe
    `pkg:yocto/<recipe>@<version>`, which no registry carries. Measured on the
    published core-image-sato-sdk reference image: 2,206 purls, 478 distinct,
    421 of them pkg:yocto. Cold, those 421 cost about twelve minutes and
    enriched nothing, and all of it runs before the SBOM is uploaded.

    Rust and Java have the same shape inside a registry-backed type. A crate
    built from a git checkout or a path, or a Maven -SNAPSHOT, carries a purl
    that crates.io and Maven Central have never seen -- and a local crate
    called `utils` can match a stranger's crate there and come back with
    their licence.
    """

    @pytest.mark.parametrize(
        "purl_str",
        [
            pytest.param("pkg:yocto/openssl@3.3.1", id="yocto-recipe"),
            pytest.param(
                "pkg:cargo/my-fork@0.3.0?vcs_url=git%2Bhttps://github.com/acme/my-fork%4080f3c1a",
                id="cargo-git-crate",
            ),
            # CycloneDX input never gets here: sanitize_purls clears a file:
            # purl first. SPDX input has no such step, so the gate is what
            # stands between a path crate and crates.io.
            pytest.param("pkg:cargo/utils@0.1.0?download_url=file://../utils", id="cargo-path-crate"),
            pytest.param("pkg:maven/com.acme/billing@2.4.0-SNAPSHOT?type=jar", id="maven-snapshot"),
            pytest.param("pkg:npm/shared-ui@1.0.0?download_url=file:../shared-ui", id="npm-file-dep"),
            # The local reference can sit in the version instead of a qualifier.
            pytest.param("pkg:npm/shared-ui@file:../shared-ui", id="npm-file-version"),
            pytest.param("pkg:npm/shared-ui@../../packages/shared-ui", id="npm-path-version"),
        ],
    )
    def test_costs_no_http_request(self, monkeypatch, tmp_path, purl_str):
        assert _requests_sent(monkeypatch, tmp_path, purl_str) == []

    def test_the_yocto_gate_and_the_purls_it_mints_agree(self, monkeypatch, tmp_path):
        """Generated rather than spelled out, so the two cannot drift apart."""
        from sbomify_action._yocto.purl import generate_yocto_purl

        assert _requests_sent(monkeypatch, tmp_path, generate_yocto_purl("busybox", "1.36.1")) == []

    @pytest.mark.parametrize(
        "purl_str",
        [
            "pkg:cargo/serde@1.0.0",
            "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
            "pkg:pypi/requests@2.31.0",
            "pkg:npm/left-pad@1.3.0",
            # A real npm scope. sanitize_purls treats a `root` namespace as a
            # generator bug, which says nothing about where a package lives.
            "pkg:npm/%40root/asn1@1.0.2",
        ],
    )
    def test_a_published_package_is_still_looked_up(self, monkeypatch, tmp_path, purl_str):
        """The gate is for what no registry has, not a reason to stop enriching."""
        assert _requests_sent(monkeypatch, tmp_path, purl_str) != []

    def test_a_local_source_still_answers(self, monkeypatch):
        """Only the network is off limits. A source that answers from local data
        costs nothing and may know the package -- the lifecycle DB knows a
        Yocto python3 recipe by name."""
        monkeypatch.setattr("sbomify_action._enrichment.registry.cache.get", lambda *_a: (False, None))
        monkeypatch.setattr("sbomify_action._enrichment.registry.cache.set", lambda *_a: None)

        local = _Source("local-db", 5, NormalizedMetadata(cle_eol="2028-10-31", source="local-db"))
        local.offline = True
        network = _Source("deps.dev", 40, NormalizedMetadata(licenses=["MIT"], source="deps.dev"))

        snapshot = PackageURL.from_string("pkg:maven/com.acme/billing@2.4.0-SNAPSHOT")
        result = _registry(local, network).fetch_metadata(snapshot, requests.Session())

        assert local.called
        assert not network.called
        assert result is not None and result.cle_eol == "2028-10-31"

    def test_the_lifecycle_db_is_still_consulted_for_a_yocto_recipe(self):
        from sbomify_action._enrichment.enricher import create_default_registry

        sources = create_default_registry().get_sources_for(PackageURL.from_string("pkg:yocto/python3@3.12.4"))

        assert [s.name for s in sources] == ["sbomify-lifecycle-db"]
