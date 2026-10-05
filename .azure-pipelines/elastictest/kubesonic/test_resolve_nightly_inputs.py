#!/usr/bin/env python3
"""Focused tests for the KubeSonic nightly profile resolver."""

import json
import os
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import resolve_nightly_inputs as RESOLVER


PROFILE_PATH = (
    Path(__file__).parents[3]
    / "tests/k8s_container/kubesonic_profiles/nightly-default.json"
)


def _resolved_profile():
    return {
        "selectors": [
            "k8s_container/test_gnmi.py",
            "k8s_container/test_example.py",
        ],
        "parameter_tokens": [
            "--k8s-container-test",
            "--k8s-gnmi-role=golden",
        ],
        "topologies": ["m0", "mx"],
        "name_prefixes": ["testbed-bjw-can-720dt-"],
        "dut_count": 1,
    }


class NightlyProfileTests(unittest.TestCase):
    def test_checked_in_profile_is_valid(self):
        profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))

        resolved = RESOLVER._validate_profile(profile)

        self.assertEqual(
            resolved["selectors"],
            ["k8s_container/test_gnmi.py"],
        )
        self.assertEqual(
            resolved["parameter_tokens"],
            ["--k8s-container-test", "--k8s-gnmi-role=golden"],
        )

    @mock.patch.dict(
        os.environ,
        {
            "PIPELINE_REF": "refs/heads/internal",
            "SOURCE_COMMIT": "a" * 40,
            "TEST_CONFIG": "nightly-default",
            "TESTBED": "testbed-bjw-can-720dt-3",
            "AZURE_DEVOPS_TOKEN": "token",
            "SYSTEM_COLLECTION_URI": "https://dev.azure.com/mssonic/",
            "SYSTEM_TEAM_PROJECT_ID": "project-id",
            "BUILD_REPOSITORY_ID": "repository-id",
            "ELASTICTEST_MSAL_CLIENT_ID": "client-id",
            "SONIC_AUTOMATION_UMI": "managed-identity",
        },
        clear=True,
    )
    def test_main_sets_profile_testbed_and_source_variables(self):
        profile = {"version": 1}
        resolved_profile = _resolved_profile()
        selected = {
            "name": "testbed-bjw-can-720dt-3",
            "topo": "m0",
        }
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_fetch_profile",
                    return_value=profile,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_validate_profile",
                    return_value=resolved_profile,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_get_elastictest_token",
                    return_value="elastictest-token",
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_query_testbeds",
                    return_value=[selected],
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_select_testbed",
                    return_value=(selected, 1),
                )
            )
            set_variable = stack.enter_context(
                mock.patch.object(RESOLVER, "_set_variable")
            )
            write_summary = stack.enter_context(
                mock.patch.object(RESOLVER, "_write_summary")
            )
            result = RESOLVER.main()

        self.assertEqual(result, 0)
        self.assertEqual(
            set_variable.call_args_list,
            [
                mock.call("resolvedSourceCommit", "a" * 40),
                mock.call(
                    "resolvedTestScripts",
                    "k8s_container/test_gnmi.py,"
                    "k8s_container/test_example.py",
                ),
                mock.call(
                    "resolvedSpecificParam",
                    '[{"name":"k8s_container","param":'
                    '"--k8s-container-test --k8s-gnmi-role=golden"}]',
                ),
                mock.call(
                    "resolvedTestbedName",
                    "testbed-bjw-can-720dt-3",
                ),
                mock.call("resolvedTopology", "m0"),
            ],
        )
        write_summary.assert_called_once_with(
            "a" * 40,
            "/tests/k8s_container/kubesonic_profiles/nightly-default.json",
            selected,
            resolved_profile,
        )

    @mock.patch.dict(
        os.environ,
        {
            "PIPELINE_REF": "refs/heads/internal",
            "SOURCE_COMMIT": "a" * 40,
            "TEST_CONFIG": "nightly-default",
            "TESTBED": "auto",
            "AZURE_DEVOPS_TOKEN": "token",
            "SYSTEM_COLLECTION_URI": "https://dev.azure.com/mssonic/",
            "SYSTEM_TEAM_PROJECT_ID": "project-id",
            "BUILD_REPOSITORY_ID": "repository-id",
            "ELASTICTEST_MSAL_CLIENT_ID": "client-id",
            "SONIC_AUTOMATION_UMI": "managed-identity",
        },
        clear=True,
    )
    def test_main_rejects_auto_testbed_selection(self):
        with mock.patch.object(RESOLVER, "_fetch_profile") as fetch_profile:
            result = RESOLVER.main()

        self.assertEqual(result, 2)
        fetch_profile.assert_not_called()


if __name__ == "__main__":
    unittest.main()
