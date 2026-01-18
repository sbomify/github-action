"""Lifecycle data for SBOM enrichment with CLE (Common Lifecycle Enumeration) fields.

This module centralizes lifecycle data for:
1. Linux distributions (used by license_db_generator and license_db source)
2. Language runtimes and frameworks (used by lifecycle enrichment source)

CLE fields follow ECMA-428 specification:
- release_date: First public stable release date for the cycle
- end_of_support: End of active/mainstream/bugfix support
- end_of_life: End of security support / extended support

See: https://sbomify.com/compliance/cle/

Data last updated: 2026-01-18
"""

from typing import Dict, List, Optional, TypedDict


class LifecycleDates(TypedDict, total=False):
    """Lifecycle dates for a single version/cycle."""

    release_date: Optional[str]  # ISO 8601 date or quarter string (e.g., "2026-Q1")
    end_of_support: Optional[str]  # ISO 8601 date or quarter string
    end_of_life: Optional[str]  # ISO 8601 date or quarter string


class PackageLifecycleEntry(TypedDict, total=False):
    """Lifecycle configuration for a package type."""

    name_patterns: List[str]  # Package name patterns to match (glob-style)
    purl_types: Optional[List[str]]  # PURL types to match, None = all types
    cycles: Dict[str, LifecycleDates]  # version cycle -> lifecycle dates
    version_extract: Optional[str]  # "major" or "major.minor" (default: major.minor)
    references: Optional[List[str]]  # Documentation references


# =============================================================================
# DISTRO_LIFECYCLE - Linux Distribution Lifecycle Data
# =============================================================================
#
# Schema:
#   release_date: ISO-8601 date (YYYY-MM-DD) or YYYY-MM when only month is known
#   end_of_support: When standard/active updates end (or same as EOL when upstream
#                   publishes only one date)
#   end_of_life: When all updates end (security support end)
#
# Sources and calculation methodology documented per-distro below.
# For rolling releases, all dates are None.

DISTRO_LIFECYCLE: Dict[str, Dict[str, LifecycleDates]] = {
    # -------------------------------------------------------------------------
    # Wolfi (Chainguard) - Rolling Release
    # Source: https://docs.chainguard.dev/open-source/wolfi/
    # Note: Wolfi is a rolling-release distribution; lifecycle is not expressed
    # as fixed version EOL dates. All fields are None.
    # -------------------------------------------------------------------------
    "wolfi": {
        "rolling": {
            "release_date": None,
            "end_of_support": None,
            "end_of_life": None,
        },
    },
    # -------------------------------------------------------------------------
    # Alpine Linux
    # Source: https://alpinelinux.org/releases/
    # Note: Alpine publishes a single per-branch end date. Alpine does not
    # separately publish EOS vs EOL for the branch, so the published end date
    # is used as both end_of_support and end_of_life.
    # -------------------------------------------------------------------------
    "alpine": {
        "3.13": {
            "release_date": "2021-01-14",
            "end_of_support": "2022-11-01",
            "end_of_life": "2022-11-01",
        },
        "3.14": {
            "release_date": "2021-06-15",
            "end_of_support": "2023-05-01",
            "end_of_life": "2023-05-01",
        },
        "3.15": {
            "release_date": "2021-11-24",
            "end_of_support": "2023-11-01",
            "end_of_life": "2023-11-01",
        },
        "3.16": {
            "release_date": "2022-05-23",
            "end_of_support": "2024-05-23",
            "end_of_life": "2024-05-23",
        },
        "3.17": {
            "release_date": "2022-11-22",
            "end_of_support": "2024-11-22",
            "end_of_life": "2024-11-22",
        },
        "3.18": {
            "release_date": "2023-05-09",
            "end_of_support": "2025-05-09",
            "end_of_life": "2025-05-09",
        },
        "3.19": {
            "release_date": "2023-12-07",
            "end_of_support": "2025-11-01",
            "end_of_life": "2025-11-01",
        },
        "3.20": {
            "release_date": "2024-05-22",
            "end_of_support": "2026-04-01",
            "end_of_life": "2026-04-01",
        },
        "3.21": {
            "release_date": "2024-12-05",
            "end_of_support": "2026-11-01",
            "end_of_life": "2026-11-01",
        },
    },
    # -------------------------------------------------------------------------
    # Rocky Linux
    # Source: https://docs.rockylinux.org/
    # Note: Rocky publishes both 'general support until' (EOS) and 'security
    # support through' (EOL) dates.
    # -------------------------------------------------------------------------
    "rocky": {
        "8": {
            "release_date": "2021-06-21",
            "end_of_support": "2024-05-01",  # General support end
            "end_of_life": "2029-05-01",  # Security support end
        },
        "9": {
            "release_date": "2022-07-14",
            "end_of_support": "2027-05-31",  # General support end
            "end_of_life": "2032-05-31",  # Security support end
        },
    },
    # -------------------------------------------------------------------------
    # AlmaLinux
    # Source: https://wiki.almalinux.org/release-notes/
    # Note: AlmaLinux publishes 'active support until' (EOS) and 'security
    # support until' (EOL) dates.
    # -------------------------------------------------------------------------
    "almalinux": {
        "8": {
            "release_date": "2021-03-30",
            "end_of_support": "2024-05-31",  # Active support end
            "end_of_life": "2029-05-31",  # Security support end
        },
        "9": {
            "release_date": "2022-05-26",
            "end_of_support": "2027-05-31",  # Active support end
            "end_of_life": "2032-05-31",  # Security support end
        },
    },
    # -------------------------------------------------------------------------
    # Amazon Linux
    # Source: https://aws.amazon.com/amazon-linux-2/faqs/
    # Note: AWS publishes an explicit end-of-support date but does not publish
    # separate EOS vs EOL semantics, so the published date is used for both.
    # AL2023 only specifies month ("until June 2029").
    # -------------------------------------------------------------------------
    "amazonlinux": {
        "2": {
            "release_date": "2017-12-19",  # AWS announcement date
            "end_of_support": "2026-06-30",
            "end_of_life": "2026-06-30",
        },
        "2023": {
            "release_date": None,  # Not explicitly published
            "end_of_support": "2029-06",  # Month precision only
            "end_of_life": "2029-06",
        },
    },
    # -------------------------------------------------------------------------
    # CentOS Stream
    # Source: https://www.centos.org/cl-vs-cs/
    # Note: CentOS publishes an 'expected end of life (EOL)' date. No separate
    # EOS date is published, so EOL is used for both.
    # -------------------------------------------------------------------------
    "centos": {
        "stream8": {
            "release_date": None,  # Not explicitly published
            "end_of_support": "2024-05-31",
            "end_of_life": "2024-05-31",
        },
        "stream9": {
            "release_date": None,  # Not explicitly published
            "end_of_support": "2027-05-31",
            "end_of_life": "2027-05-31",
        },
    },
    # -------------------------------------------------------------------------
    # Fedora
    # Source: https://fedorapeople.org/groups/schedule/
    # Note: Fedora schedules publish explicit EOL dates. Fedora publishes only
    # one end date per release, so it's used for both EOS and EOL.
    # Release dates are from 'Current Final Target date' in the schedule.
    # -------------------------------------------------------------------------
    "fedora": {
        "39": {
            "release_date": None,  # Not captured
            "end_of_support": "2024-11-26",
            "end_of_life": "2024-11-26",
        },
        "40": {
            "release_date": None,  # Not captured
            "end_of_support": "2025-05-13",
            "end_of_life": "2025-05-13",
        },
        "41": {
            "release_date": "2024-10-29",
            "end_of_support": "2025-12-15",
            "end_of_life": "2025-12-15",
        },
        "42": {
            "release_date": "2025-04-15",
            # EOL date not yet captured from Fedora sources
            # See: https://fedorapeople.org/groups/schedule/f-42/f-42-key-tasks.html
            "end_of_support": None,
            "end_of_life": None,
        },
    },
    # -------------------------------------------------------------------------
    # openSUSE Leap
    # Source: https://en.opensuse.org/Lifetime
    # Note: openSUSE Leap has ~18 months support per release.
    # -------------------------------------------------------------------------
    "opensuse-leap": {
        "15.5": {
            "release_date": "2023-06-07",
            "end_of_support": "2024-12-31",
            "end_of_life": "2024-12-31",
        },
        "15.6": {
            "release_date": "2024-06-12",
            "end_of_support": "2025-12-31",
            "end_of_life": "2025-12-31",
        },
    },
    # -------------------------------------------------------------------------
    # Oracle Linux
    # Source: https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
    # Note: Oracle Linux follows RHEL lifecycle with extended support.
    # -------------------------------------------------------------------------
    "oracle": {
        "8": {
            "release_date": "2019-07-18",
            "end_of_support": "2024-05-01",  # Premier support end
            "end_of_life": "2029-07-01",  # Extended support end
        },
        "9": {
            "release_date": "2022-07-06",
            "end_of_support": "2027-05-31",  # Premier support end
            "end_of_life": "2032-05-31",  # Extended support end
        },
    },
    # -------------------------------------------------------------------------
    # Ubuntu
    # Source: https://ubuntu.com/about/release-cycle
    # Note: Ubuntu publishes 'Standard security maintenance' (EOS) and
    # 'Expanded security maintenance' (EOL) dates at month precision.
    # -------------------------------------------------------------------------
    "ubuntu": {
        "20.04": {
            "release_date": "2020-04",  # Month precision
            "end_of_support": "2025-05",  # Standard security maintenance end
            "end_of_life": "2030-04",  # Expanded security maintenance end
        },
        "22.04": {
            "release_date": "2022-04",
            "end_of_support": "2027-06",
            "end_of_life": "2032-04",
        },
        "24.04": {
            "release_date": "2024-04",
            "end_of_support": "2029-05",
            "end_of_life": "2034-04",
        },
    },
    # -------------------------------------------------------------------------
    # Debian
    # Source: https://wiki.debian.org/LTS
    # Note: Debian publishes 'Regular security support' (EOS) and 'Long Term
    # Support' (EOL/LTS) dates.
    # -------------------------------------------------------------------------
    "debian": {
        "10": {
            "release_date": "2019-07-06",
            "end_of_support": "2022-09-10",  # Regular security support end
            "end_of_life": "2024-06-30",  # LTS end
        },
        "11": {
            "release_date": "2021-08-14",
            "end_of_support": "2024-08-14",  # Regular security support end
            "end_of_life": "2026-08-31",  # LTS end
        },
        "12": {
            "release_date": "2023-06-10",
            "end_of_support": "2026-06-10",  # Regular security support end
            "end_of_life": "2028-06-30",  # LTS end
        },
        "13": {
            "release_date": "2025-08-09",
            "end_of_support": "2028-08-09",  # Full Debian support end
            "end_of_life": "2030-06-30",  # LTS end
        },
    },
}


# =============================================================================
# PACKAGE_LIFECYCLE - Language Runtime and Framework Lifecycle Data
# =============================================================================
#
# Schema per package:
#   name_patterns: List of package name patterns to match (case-insensitive)
#                  Supports glob patterns: "python3.*" matches "python3.12"
#   purl_types: Optional list of PURL types to match (e.g., ["pypi", "deb"])
#               None means match all PURL types
#   cycles: Dict mapping version cycle to lifecycle dates
#   version_extract: How to extract cycle from version ("major" or "major.minor")
#                    Default is "major.minor"
#   references: List of documentation URLs
#
# Definitions:
#   release_date: First public stable release date for the cycle when available;
#                 otherwise null or quarter string (e.g., "2026-Q1")
#   end_of_support: End of active/mainstream/bugfix support, when the project
#                   stops providing regular bugfix releases (may still receive
#                   security fixes)
#   end_of_life: End of security support / extended support; after this, upstream
#                no longer provides security fixes
#
# Data as of: 2026-01-18

PACKAGE_LIFECYCLE: Dict[str, PackageLifecycleEntry] = {
    # -------------------------------------------------------------------------
    # Python
    # Source: https://devguide.python.org/versions/
    #         https://peps.python.org/pep-0373/ (Python 2.7)
    # Note: Python provides ~18-24 months of bugfix support after release,
    # then security-only fixes until EOL. Starting with 3.13, bugfix support
    # is 24 months.
    #
    # Common PURLs across ecosystems:
    #   PyPI:     pkg:pypi/python@3.12.1, pkg:pypi/cpython@3.12.1
    #   Alpine:   pkg:apk/alpine/python3@3.12.1, pkg:apk/alpine/python3.12@3.12.1
    #   Debian:   pkg:deb/debian/python3@3.12.1, pkg:deb/debian/python3.12@3.12.1
    #             pkg:deb/debian/python3.12-minimal@3.12.1
    #             pkg:deb/debian/libpython3.12-stdlib@3.12.1
    #   Ubuntu:   pkg:deb/ubuntu/python3@3.12.1, pkg:deb/ubuntu/python3.12@3.12.1
    #   Fedora:   pkg:rpm/fedora/python3@3.12.1
    #   Docker:   python:3.12, python:3.12-slim, python:3.12-alpine
    # -------------------------------------------------------------------------
    "python": {
        "name_patterns": [
            "python",
            "python2",
            "python2.*",
            "python3",
            "python3.*",
            "cpython",
            "libpython*",  # Debian stdlib packages
        ],
        "purl_types": None,  # Match all types (pypi, deb, rpm, apk, etc.)
        "version_extract": "major.minor",
        "references": [
            "https://devguide.python.org/versions/",
            "https://peps.python.org/pep-0373/",
        ],
        "cycles": {
            "2.7": {
                "release_date": None,
                "end_of_support": "2020-01-01",
                "end_of_life": "2020-04-20",
            },
            "3.10": {
                "release_date": "2021-10-04",
                "end_of_support": "2023-04-04",
                "end_of_life": "2026-10-31",
            },
            "3.11": {
                "release_date": "2022-10-24",
                "end_of_support": "2024-04-24",
                "end_of_life": "2027-10-31",
            },
            "3.12": {
                "release_date": "2023-10-02",
                "end_of_support": "2025-04-02",
                "end_of_life": "2028-10-31",
            },
            "3.13": {
                "release_date": "2024-10-07",
                "end_of_support": "2026-10-07",
                "end_of_life": "2029-10-31",
            },
            "3.14": {
                "release_date": "2025-10-07",
                "end_of_support": "2027-10-07",
                "end_of_life": "2030-10-31",
            },
        },
    },
    # -------------------------------------------------------------------------
    # Django
    # Source: https://www.djangoproject.com/download/
    # Note: Django provides bugfix support until EOS, then security-only
    # until EOL. LTS releases have extended support windows.
    # -------------------------------------------------------------------------
    "django": {
        "name_patterns": ["django", "Django"],
        "purl_types": ["pypi"],
        "version_extract": "major.minor",
        "references": [
            "https://www.djangoproject.com/download/",
        ],
        "cycles": {
            "4.2": {
                "release_date": None,
                "end_of_support": "2023-12-04",
                "end_of_life": "2026-04-30",
            },
            "5.2": {
                "release_date": None,
                "end_of_support": "2025-12-03",
                "end_of_life": "2028-04-30",
            },
            "6.0": {
                "release_date": None,
                "end_of_support": "2026-08-31",
                "end_of_life": "2027-04-30",
            },
        },
    },
    # -------------------------------------------------------------------------
    # Ruby on Rails
    # Source: https://rubyonrails.org/2025/10/29/new-rails-releases-and-end-of-support-announcement
    # Note: Rails provides bugfix support for ~12 months, then security-only
    # for another ~6-12 months typically.
    #
    # Common PURLs across ecosystems:
    #   RubyGems:  pkg:gem/rails@8.0.1, pkg:gem/railties@8.0.1
    #              pkg:gem/actionpack@8.0.1, pkg:gem/activerecord@8.0.1
    #              pkg:gem/activesupport@8.0.1, pkg:gem/actionmailer@8.0.1
    #              pkg:gem/actioncable@8.0.1, pkg:gem/activestorage@8.0.1
    #              pkg:gem/actionview@8.0.1, pkg:gem/activejob@8.0.1
    #   Debian:    pkg:deb/debian/rails@8.0.1, pkg:deb/debian/ruby-rails@8.0.1
    # -------------------------------------------------------------------------
    "rails": {
        "name_patterns": [
            "rails",
            "railties",
            "actionpack",
            "activerecord",
            "activesupport",
            "actionmailer",
            "actioncable",
            "activestorage",
            "actionview",
            "activejob",
            "actionmailbox",
            "actiontext",
            "activemodel",
            "ruby-rails",
        ],
        "purl_types": ["gem"],
        "version_extract": "major.minor",
        "references": [
            "https://rubyonrails.org/2025/10/29/new-rails-releases-and-end-of-support-announcement",
        ],
        "cycles": {
            "7.0": {
                "release_date": "2021-12-15",
                "end_of_support": "2025-10-29",
                "end_of_life": "2025-10-29",
            },
            "7.1": {
                "release_date": "2023-10-05",
                "end_of_support": "2025-10-29",
                "end_of_life": "2025-10-29",
            },
            "7.2": {
                "release_date": None,
                "end_of_support": None,
                "end_of_life": "2026-08-09",
            },
            "8.0": {
                "release_date": "2024-11-07",
                "end_of_support": "2026-05-07",
                "end_of_life": "2026-11-07",
            },
            "8.1": {
                "release_date": "2025-10-22",
                "end_of_support": "2026-10-10",
                "end_of_life": "2027-10-10",
            },
        },
    },
    # -------------------------------------------------------------------------
    # Laravel
    # Source: https://laravel.com/docs/12.x/releases
    # Note: Laravel provides ~6 months bugfix support, ~12 months security.
    # Quarter strings preserved for future releases.
    # -------------------------------------------------------------------------
    "laravel": {
        "name_patterns": ["laravel/framework", "laravel"],
        "purl_types": ["composer"],
        "version_extract": "major",
        "references": [
            "https://laravel.com/docs/12.x/releases",
        ],
        "cycles": {
            "10": {
                "release_date": "2023-02-14",
                "end_of_support": "2025-02-06",
                "end_of_life": "2026-02-04",
            },
            "11": {
                "release_date": "2024-03-12",
                "end_of_support": "2025-09-03",
                "end_of_life": "2026-03-12",
            },
            "12": {
                "release_date": "2025-02-24",
                "end_of_support": "2026-09-03",
                "end_of_life": "2027-03-12",
            },
            "13": {
                "release_date": "2026-Q1",
                "end_of_support": "2026-Q3",
                "end_of_life": "2027-Q1",
            },
        },
    },
    # -------------------------------------------------------------------------
    # PHP
    # Source: https://www.php.net/supported-versions.php
    #         https://www.php.net/eol.php
    # Note: PHP provides ~2 years of active support, then ~1 year of security-only
    # support. Older branches only show EOL date (end_of_support is None).
    #
    # Common PURLs across ecosystems:
    #   Composer: pkg:composer/php@8.4.1 (rarely used directly)
    #   Alpine:   pkg:apk/alpine/php@8.4.1, pkg:apk/alpine/php84@8.4.1
    #             pkg:apk/alpine/php84-fpm@8.4.1, pkg:apk/alpine/php84-cli@8.4.1
    #             pkg:apk/alpine/php83@8.3.6, pkg:apk/alpine/php83-common@8.3.6
    #   Debian:   pkg:deb/debian/php@8.4.1, pkg:deb/debian/php8.3@8.3.6
    #             pkg:deb/debian/php8.3-fpm@8.3.6, pkg:deb/debian/php8.3-cli@8.3.6
    #             pkg:deb/debian/php-fpm@8.3.6, pkg:deb/debian/php-cli@8.3.6
    #   Ubuntu:   pkg:deb/ubuntu/php@8.3.6, pkg:deb/ubuntu/php8.3@8.3.6
    #   Fedora:   pkg:rpm/fedora/php@8.3.6, pkg:rpm/fedora/php-fpm@8.3.6
    #   Docker:   php:8.4, php:8.4-fpm, php:8.4-alpine, php:8.4-fpm-alpine
    # -------------------------------------------------------------------------
    "php": {
        "name_patterns": [
            "php",
            "php-cli",
            "php-fpm",
            "php-cgi",
            "php-common",
            "php7",
            "php7.*",
            "php8",
            "php8.*",
            "php74",
            "php74-*",
            "php80",
            "php80-*",
            "php81",
            "php81-*",
            "php82",
            "php82-*",
            "php83",
            "php83-*",
            "php84",
            "php84-*",
            "php85",
            "php85-*",
            "libphp*",  # Shared libraries
        ],
        "purl_types": None,  # Match all types (composer, deb, rpm, apk, etc.)
        "version_extract": "major.minor",
        "references": [
            "https://www.php.net/supported-versions.php",
            "https://www.php.net/eol.php",
        ],
        "cycles": {
            "7.4": {
                "release_date": "2019-11-28",
                "end_of_support": None,
                "end_of_life": "2022-11-28",
            },
            "8.0": {
                "release_date": "2020-11-26",
                "end_of_support": None,
                "end_of_life": "2023-11-26",
            },
            "8.1": {
                "release_date": "2021-11-25",
                "end_of_support": None,
                "end_of_life": "2025-12-31",
            },
            "8.2": {
                "release_date": "2022-12-08",
                "end_of_support": "2024-12-31",
                "end_of_life": "2026-12-31",
            },
            "8.3": {
                "release_date": "2023-11-23",
                "end_of_support": "2025-12-31",
                "end_of_life": "2027-12-31",
            },
            "8.4": {
                "release_date": "2024-11-21",
                "end_of_support": "2026-12-31",
                "end_of_life": "2028-12-31",
            },
            "8.5": {
                "release_date": "2025-11-20",
                "end_of_support": "2027-12-31",
                "end_of_life": "2029-12-31",
            },
        },
    },
    # -------------------------------------------------------------------------
    # Go (Golang)
    # Source: https://go.dev/doc/devel/release
    # Note: Go's release policy supports a major release until there are two
    # newer major releases. EOS/EOL are the same date (when support ends).
    #
    # Common PURLs across ecosystems:
    #   Go modules: pkg:golang/golang.org/x/text@1.23.0 (libraries, not runtime)
    #   Alpine:     pkg:apk/alpine/go@1.23.4
    #   Debian:     pkg:deb/debian/golang@1.23.4, pkg:deb/debian/golang-go@1.23.4
    #               pkg:deb/debian/golang-1.23@1.23.4, pkg:deb/debian/golang-1.23-go@1.23.4
    #               pkg:deb/debian/golang-1.23-src@1.23.4
    #   Ubuntu:     pkg:deb/ubuntu/golang@1.23.4, pkg:deb/ubuntu/golang-1.23-go@1.23.4
    #   Fedora:     pkg:rpm/fedora/golang@1.23.4
    #   Docker:     golang:1.23, golang:1.23-alpine, golang:1.23-bookworm
    # -------------------------------------------------------------------------
    "golang": {
        "name_patterns": [
            "go",
            "golang",
            "golang-go",
            "golang-src",
            "golang-doc",
            "golang-1.*",  # Debian versioned packages
            "golang-1.*-go",
            "golang-1.*-src",
            "golang-1.*-doc",
        ],
        "purl_types": None,  # Match all types (golang, deb, rpm, apk, etc.)
        "version_extract": "major.minor",
        "references": [
            "https://go.dev/doc/devel/release",
        ],
        "cycles": {
            "1.22": {
                "release_date": "2024-02-06",
                "end_of_support": "2025-02-11",
                "end_of_life": "2025-02-11",
            },
            "1.23": {
                "release_date": "2024-08-13",
                "end_of_support": "2025-08-12",
                "end_of_life": "2025-08-12",
            },
            "1.24": {
                "release_date": "2025-02-11",
                "end_of_support": None,
                "end_of_life": None,
            },
            "1.25": {
                "release_date": "2025-08-12",
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
    # -------------------------------------------------------------------------
    # Rust
    # Source: https://rust-lang.org/policies/security/
    #         https://blog.rust-lang.org/releases/
    # Note: Rust only supports the most recent stable release. When a new stable
    # is released, the previous version is immediately unsupported. EOS/EOL are
    # the same date (next stable release date).
    #
    # Common PURLs across ecosystems:
    #   Cargo:    pkg:cargo/serde@1.91.0 (crates, not runtime itself)
    #   Alpine:   pkg:apk/alpine/rust@1.91.0, pkg:apk/alpine/cargo@1.91.0
    #   Debian:   pkg:deb/debian/rustc@1.91.0, pkg:deb/debian/cargo@1.91.0
    #             pkg:deb/debian/rust-all@1.91.0, pkg:deb/debian/rust-src@1.91.0
    #             pkg:deb/debian/libstd-rust-1.91@1.91.0, pkg:deb/debian/libstd-rust-dev@1.91.0
    #   Ubuntu:   pkg:deb/ubuntu/rustc@1.91.0, pkg:deb/ubuntu/cargo@1.91.0
    #             pkg:deb/ubuntu/rustc-1.77@1.77.0 (versioned)
    #   Fedora:   pkg:rpm/fedora/rust@1.91.0, pkg:rpm/fedora/cargo@1.91.0
    #   Docker:   rust:1.91, rust:1.91-slim, rust:1.91-alpine
    # -------------------------------------------------------------------------
    "rust": {
        "name_patterns": [
            "rust",
            "rustc",
            "rustc-*",  # Ubuntu versioned packages
            "cargo",
            "cargo-*",  # Ubuntu versioned packages
            "rust-all",
            "rust-src",
            "rust-doc",
            "rust-gdb",
            "rust-lldb",
            "libstd-rust*",  # Debian stdlib packages
        ],
        "purl_types": None,  # Match all types (cargo, deb, rpm, apk, etc.)
        "version_extract": "major.minor",
        "references": [
            "https://rust-lang.org/policies/security/",
            "https://blog.rust-lang.org/releases/",
        ],
        "cycles": {
            "1.90": {
                "release_date": "2025-09-18",
                "end_of_support": "2025-10-30",
                "end_of_life": "2025-10-30",
            },
            "1.91": {
                "release_date": "2025-10-30",
                "end_of_support": "2025-12-11",
                "end_of_life": "2025-12-11",
            },
            "1.92": {
                "release_date": "2025-12-11",
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
    # -------------------------------------------------------------------------
    # React
    # Source: https://react.dev/blog/
    # Note: React does not publish fixed end-of-support/end-of-life dates for
    # major versions. Only release dates are tracked.
    #
    # Common PURLs across ecosystems:
    #   npm:      pkg:npm/react@19.0.0, pkg:npm/react-dom@19.0.0
    #             pkg:npm/react-native@0.76.0 (different versioning, not tracked)
    # -------------------------------------------------------------------------
    "react": {
        "name_patterns": [
            "react",
            "react-dom",  # Usually same version as react
        ],
        "purl_types": ["npm"],
        "version_extract": "major",
        "references": [
            "https://react.dev/blog/2024/12/05/react-19",
            "https://react.dev/blog/2022/03/29/react-v18",
            "https://legacy.reactjs.org/blog/2020/10/20/react-v17.html",
        ],
        "cycles": {
            "17": {
                "release_date": "2020-10-20",
                "end_of_support": None,
                "end_of_life": None,
            },
            "18": {
                "release_date": "2022-03-29",
                "end_of_support": None,
                "end_of_life": None,
            },
            "19": {
                "release_date": "2024-12-05",
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
    # -------------------------------------------------------------------------
    # Vue.js
    # Source: https://v2.vuejs.org/eol/
    #         https://vuejs.org/guide/introduction.html
    # Note: Vue 2 reached EOL on Dec 31, 2023. Vue 3 is current and does not
    # have a published EOL date.
    #
    # Common PURLs across ecosystems:
    #   npm:      pkg:npm/vue@3.4.0, pkg:npm/vue@2.7.14
    #             pkg:npm/@vue/runtime-core@3.4.0, pkg:npm/@vue/compiler-sfc@3.4.0
    # -------------------------------------------------------------------------
    "vue": {
        "name_patterns": [
            "vue",
            "@vue/runtime-core",  # Vue 3 core packages
            "@vue/compiler-sfc",
            "@vue/reactivity",
            "@vue/shared",
        ],
        "purl_types": ["npm"],
        "version_extract": "major",
        "references": [
            "https://v2.vuejs.org/eol/",
            "https://vuejs.org/guide/introduction.html",
        ],
        "cycles": {
            "2": {
                "release_date": None,
                "end_of_support": "2023-12-31",
                "end_of_life": "2023-12-31",
            },
            "3": {
                "release_date": None,
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
}


def get_package_lifecycle_entry(package_name: str) -> Optional[PackageLifecycleEntry]:
    """
    Find the lifecycle entry that matches a package name.

    Args:
        package_name: Package name to match

    Returns:
        PackageLifecycleEntry or None if no match found
    """
    import fnmatch

    name_lower = package_name.lower()

    for entry_key, entry in PACKAGE_LIFECYCLE.items():
        patterns = entry.get("name_patterns", [])
        for pattern in patterns:
            if fnmatch.fnmatch(name_lower, pattern.lower()):
                return entry

    return None


def extract_version_cycle(version: str, version_extract: Optional[str] = None) -> Optional[str]:
    """
    Extract the version cycle from a full version string.

    Args:
        version: Full version string (e.g., "3.12.7", "4.2.9", "19.0.1")
        version_extract: "major" or "major.minor" (default: "major.minor")

    Returns:
        Version cycle string (e.g., "3.12", "4.2", "19") or None
    """
    if not version:
        return None

    # Remove common prefixes
    v = version.lstrip("v")

    # Split on dots
    parts = v.split(".")

    if not parts:
        return None

    # Handle version_extract mode
    if version_extract == "major":
        # Return just the major version
        # Handle cases like "3.12" where there's no patch
        return parts[0] if parts[0].isdigit() else None
    else:
        # Default: major.minor
        if len(parts) >= 2:
            major, minor = parts[0], parts[1]
            # Handle minor versions with suffixes (e.g., "12-rc1")
            minor = minor.split("-")[0].split("+")[0]
            if major.isdigit() and minor.isdigit():
                return f"{major}.{minor}"
        elif len(parts) == 1 and parts[0].isdigit():
            # Single number version (e.g., "19") - return as-is
            return parts[0]

    return None


def get_package_lifecycle(
    package_name: str,
    version: str,
    purl_type: Optional[str] = None,
) -> Optional[LifecycleDates]:
    """
    Get lifecycle dates for a package version.

    Args:
        package_name: Package name (e.g., "django", "python3")
        version: Package version (e.g., "4.2.9", "3.12.1")
        purl_type: Optional PURL type to filter matches (e.g., "pypi", "npm")

    Returns:
        LifecycleDates dict or None if not found
    """
    entry = get_package_lifecycle_entry(package_name)
    if not entry:
        return None

    # Check PURL type filter
    allowed_types = entry.get("purl_types")
    if allowed_types is not None and purl_type is not None:
        if purl_type.lower() not in [t.lower() for t in allowed_types]:
            return None

    # Extract version cycle
    version_extract = entry.get("version_extract", "major.minor")
    cycle = extract_version_cycle(version, version_extract)
    if not cycle:
        return None

    # Look up cycle in the entry's cycles
    cycles = entry.get("cycles", {})
    return cycles.get(cycle)


def get_distro_lifecycle(distro_name: str, version: str) -> Optional[LifecycleDates]:
    """
    Get lifecycle dates for an operating system version.

    Args:
        distro_name: OS name (e.g., "debian", "ubuntu", "alpine")
        version: OS version (e.g., "12.12", "22.04", "3.20")

    Returns:
        LifecycleDates dict or None if not found
    """
    import re

    distro_lower = distro_name.lower()

    # Map common OS name variations to our canonical names
    distro_mappings = {
        "alma": "almalinux",
        "amazon": "amazonlinux",
        "amzn": "amazonlinux",
        "ol": "oracle",  # Oracle Linux
        "oraclelinux": "oracle",
    }
    distro_key = distro_mappings.get(distro_lower, distro_lower)

    distro_data = DISTRO_LIFECYCLE.get(distro_key)
    if not distro_data:
        return None

    # Normalize version string
    # Handle complex versions like "2023.10.20260105 (Amazon Linux)" -> "2023"
    # or "9.7 (Blue Onyx)" -> "9"
    version_clean = version.split("(")[0].strip()  # Remove parenthetical suffixes

    # Try exact match first
    if version_clean in distro_data:
        return distro_data[version_clean]

    # Try progressively shorter version prefixes
    # e.g., "12.12" -> "12", "3.20.1" -> "3.20" -> "3"
    parts = version_clean.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in distro_data:
            return distro_data[prefix]

    # For Amazon Linux, try extracting just the year (2023, 2)
    if distro_key == "amazonlinux":
        year_match = re.match(r"^(\d{4}|\d)", version_clean)
        if year_match:
            year = year_match.group(1)
            if year in distro_data:
                return distro_data[year]

    # For CentOS, version "9" should map to "stream9"
    # (CentOS Stream is the only supported CentOS now)
    if distro_key == "centos":
        stream_version = f"stream{version_clean}"
        if stream_version in distro_data:
            return distro_data[stream_version]

    return None
