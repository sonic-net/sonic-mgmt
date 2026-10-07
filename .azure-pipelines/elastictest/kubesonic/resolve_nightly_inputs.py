#!/usr/bin/env python3
"""Resolve the trusted KubeSonic nightly profile and physical testbed."""

import json
import subprocess
import sys
from pathlib import Path

from resolve_manual_inputs import (
    _COMMIT_PATTERN,
    _NAME_PATTERN,
    SUITE_OPTION,
    ResolutionError,
    _fetch_profile,
    _get_elastictest_token,
    _query_testbeds,
    _required,
    _resolve_named_profile_path,
    _select_exact_testbed,
    _set_variable,
    _testbed_duts,
    _validate_profile,
)

NIGHTLY_TOPOLOGIES = {"m0", "mx"}
NIGHTLY_NAME_PREFIXES = ("testbed-bjw-can-720dt-",)
NIGHTLY_DUT_COUNT = 1


def _validate_nightly_testbed(testbed):
    reasons = []
    name = str(testbed.get("name", ""))
    topology = str(testbed.get("topo", ""))
    dut_count = len(_testbed_duts(testbed))

    if topology not in NIGHTLY_TOPOLOGIES:
        reasons.append(
            "topology must be one of {}".format(
                ", ".join(sorted(NIGHTLY_TOPOLOGIES))
            )
        )
    if not any(name.startswith(prefix) for prefix in NIGHTLY_NAME_PREFIXES):
        reasons.append(
            "name must start with {}".format(
                " or ".join(NIGHTLY_NAME_PREFIXES)
            )
        )
    if dut_count != NIGHTLY_DUT_COUNT:
        reasons.append(
            "must contain exactly {} DUT".format(NIGHTLY_DUT_COUNT)
        )
    if reasons:
        raise ResolutionError(
            "Nightly testbed {} violates trusted policy: {}".format(
                name or "<unnamed>",
                ", ".join(reasons),
            )
        )
    return testbed


def _write_summary(
    source_commit,
    profile_path,
    selected_testbed,
    resolved_profile,
):
    summary_path = Path.cwd() / "kubesonic-nightly-summary.md"
    selectors = "<br>".join(
        f"`{selector}`" for selector in resolved_profile["selectors"]
    )
    summary_path.write_text(
        "\n".join(
            [
                "# KubeSonic nightly request",
                "",
                "| Field | Resolved value |",
                "|---|---|",
                f"| Source commit | `{source_commit}` |",
                f"| Test profile | `{profile_path}` |",
                f"| Testbed | `{selected_testbed['name']}` |",
                f"| Topology | `{selected_testbed['topo']}` |",
                f"| Test selectors | {selectors} |",
                f"| Pytest options | `{SUITE_OPTION}` |",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"##vso[task.uploadsummary]{summary_path}")


def main():
    try:
        if _required("PIPELINE_REF") != "refs/heads/internal":
            raise ResolutionError(
                "Run this pipeline from refs/heads/internal"
            )

        source_commit = _required("SOURCE_COMMIT")
        if not _COMMIT_PATTERN.fullmatch(source_commit):
            raise ResolutionError(
                "SOURCE_COMMIT must be a full immutable commit"
            )

        test_profile = _required("TEST_PROFILE")
        requested_testbed = _required("TESTBED")
        if (
            requested_testbed == "auto"
            or not _NAME_PATTERN.fullmatch(requested_testbed)
        ):
            raise ResolutionError(
                "TESTBED must be an exact name containing only letters, "
                "numbers, dots, underscores, and hyphens"
            )

        azure_token = _required("AZURE_DEVOPS_TOKEN")
        collection_uri = _required("SYSTEM_COLLECTION_URI")
        project_id = _required("SYSTEM_TEAM_PROJECT_ID")
        repository_id = _required("BUILD_REPOSITORY_ID")

        profile_path = _resolve_named_profile_path(test_profile)
        profile = _fetch_profile(
            collection_uri,
            project_id,
            repository_id,
            azure_token,
            source_commit,
            profile_path,
        )
        resolved_profile = _validate_profile(profile)

        elastictest_token = _get_elastictest_token(
            _required("ELASTICTEST_MSAL_CLIENT_ID"),
            _required("SONIC_AUTOMATION_UMI"),
        )
        selected_testbed = _validate_nightly_testbed(
            _select_exact_testbed(
                _query_testbeds(elastictest_token),
                requested_testbed,
            )
        )

        specific_param = json.dumps(
            [
                {
                    "name": "k8s_container",
                    "param": SUITE_OPTION,
                }
            ],
            separators=(",", ":"),
        )
        _set_variable("resolvedSourceCommit", source_commit)
        _set_variable(
            "resolvedTestScripts",
            ",".join(resolved_profile["selectors"]),
        )
        _set_variable("resolvedSpecificParam", specific_param)
        _set_variable("resolvedTestbedName", selected_testbed["name"])
        _set_variable("resolvedTopology", selected_testbed["topo"])
        _write_summary(
            source_commit,
            profile_path,
            selected_testbed,
            resolved_profile,
        )

        print(
            f"Resolved {profile_path} at {source_commit} to "
            f"{selected_testbed['name']} ({selected_testbed['topo']})"
        )
        return 0
    except (
        ResolutionError,
        OSError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(
            f"KubeSonic nightly resolution failed: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
