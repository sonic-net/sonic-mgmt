#!/usr/bin/env python3
"""Resolve an exact KubeSonic testbed through live Elastictest inventory."""

import subprocess
import sys
from pathlib import Path

from resolve_manual_inputs import (
    ResolutionError,
    _get_elastictest_token,
    _query_testbeds,
    _required,
    _select_exact_testbed,
    _set_variable,
)


def _write_summary(selected_testbed):
    summary_path = Path.cwd() / "kubesonic-testbed-summary.md"
    summary_path.write_text(
        "\n".join(
            [
                "# KubeSonic testbed resolution",
                "",
                "| Field | Resolved value |",
                "|---|---|",
                f"| Testbed | `{selected_testbed['name']}` |",
                f"| Topology | `{selected_testbed['topo']}` |",
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"##vso[task.uploadsummary]{summary_path}")


def main():
    try:
        requested_testbed = _required("TESTBED")
        elastictest_token = _get_elastictest_token(
            _required("ELASTICTEST_MSAL_CLIENT_ID"),
            _required("SONIC_AUTOMATION_UMI"),
        )
        selected_testbed = _select_exact_testbed(
            _query_testbeds(elastictest_token),
            requested_testbed,
        )

        _set_variable("resolvedTestbedName", selected_testbed["name"])
        _set_variable("resolvedTopology", selected_testbed["topo"])
        _write_summary(selected_testbed)
        print(
            f"Resolved {selected_testbed['name']} to topology "
            f"{selected_testbed['topo']}"
        )
        return 0
    except (
        ResolutionError,
        OSError,
        subprocess.CalledProcessError,
        ValueError,
    ) as error:
        print(f"KubeSonic testbed resolution failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
