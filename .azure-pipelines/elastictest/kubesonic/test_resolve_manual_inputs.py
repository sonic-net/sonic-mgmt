#!/usr/bin/env python3
"""Focused tests for the KubeSonic manual input resolver."""

import importlib.util
import io
import os
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("resolve_manual_inputs.py")
SPEC = importlib.util.spec_from_file_location("resolve_manual_inputs", SCRIPT)
RESOLVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESOLVER)


def _profile():
    return {
        "version": 2,
        "description": "Run one reviewed Kubernetes container test.",
        "selectors": ["k8s_container/test_gnmi.py"],
    }


def _testbed(name, topology="m0", **overrides):
    value = {
        "name": name,
        "topo": topology,
        "status": "READY",
        "locked_by": None,
        "nightly_test": False,
        "comment": "",
        "testbed_type": "PHYSICAL",
        "dut": ["dut-1"],
    }
    value.update(overrides)
    return value


class ProfileValidationTests(unittest.TestCase):
    def test_profile_resolves_selectors_only(self):
        resolved = RESOLVER._validate_profile(_profile())

        self.assertEqual(
            resolved["selectors"],
            ["k8s_container/test_gnmi.py"],
        )

    def test_profile_requires_description(self):
        profile = _profile()
        profile["description"] = ""

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "description"
        ):
            RESOLVER._validate_profile(profile)

    def test_profile_rejects_runtime_parameters(self):
        profile = _profile()
        profile["parameters"] = {"k8s-container-test": True}

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "Unsupported profile fields"
        ):
            RESOLVER._validate_profile(profile)

    def test_selector_stays_under_k8s_container(self):
        profile = _profile()
        profile["selectors"] = ["../platform_tests/test_reboot.py"]

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "Selectors must"
        ):
            RESOLVER._validate_profile(profile)


class ProfilePathTests(unittest.TestCase):
    def test_manual_run_requires_one_changed_profile(self):
        path = RESOLVER._resolve_changed_profile_path(
            ["/tests/k8s_container/kubesonic_profiles/gnmi-golden.json"],
        )

        self.assertEqual(
            path,
            "/tests/k8s_container/kubesonic_profiles/gnmi-golden.json",
        )

    def test_manual_run_rejects_zero_changed_profiles(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "exactly one changed"
        ):
            RESOLVER._resolve_changed_profile_path(
                ["/tests/k8s_container/test_gnmi.py"],
            )

    def test_manual_run_rejects_multiple_changed_profiles(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "exactly one changed"
        ):
            RESOLVER._resolve_changed_profile_path(
                [
                    "/tests/k8s_container/kubesonic_profiles/one.json",
                    "/tests/k8s_container/kubesonic_profiles/two.json",
                ],
            )

    def test_named_profile_resolves_under_trusted_root(self):
        self.assertEqual(
            RESOLVER._resolve_named_profile_path("nightly-default"),
            "/tests/k8s_container/kubesonic_profiles/nightly-default.json",
        )


class PullRequestTests(unittest.TestCase):
    @mock.patch.object(RESOLVER, "_request_json")
    def test_active_pr_resolves_source_commit(self, request_json):
        request_json.return_value = {
            "status": "active",
            "targetRefName": "refs/heads/internal",
            "repository": {"id": "repository-id"},
            "lastMergeSourceCommit": {"commitId": "a" * 40},
        }

        _, source_commit = RESOLVER._resolve_pull_request(
            "https://dev.azure.com/mssonic/",
            "project-id",
            "repository-id",
            "token",
            123,
        )

        self.assertEqual(source_commit, "a" * 40)

    @mock.patch.object(RESOLVER, "_request_json")
    def test_completed_pr_resolves_merge_commit(self, request_json):
        request_json.return_value = {
            "status": "completed",
            "targetRefName": "refs/heads/internal",
            "repository": {"id": "repository-id"},
            "lastMergeCommit": {"commitId": "b" * 40},
        }

        _, source_commit = RESOLVER._resolve_pull_request(
            "https://dev.azure.com/mssonic/",
            "project-id",
            "repository-id",
            "token",
            123,
        )

        self.assertEqual(source_commit, "b" * 40)

    @mock.patch.object(RESOLVER, "_request_json")
    def test_abandoned_pr_is_rejected(self, request_json):
        request_json.return_value = {
            "status": "abandoned",
            "targetRefName": "refs/heads/internal",
            "repository": {"id": "repository-id"},
        }

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "active or completed"
        ):
            RESOLVER._resolve_pull_request(
                "https://dev.azure.com/mssonic/",
                "project-id",
                "repository-id",
                "token",
                123,
            )


class PullRequestChangeTests(unittest.TestCase):
    @mock.patch.object(RESOLVER, "_request_json")
    def test_deleted_profile_is_rejected(self, request_json):
        request_json.side_effect = [
            {"value": [{"id": 1}]},
            {
                "changeEntries": [
                    {
                        "changeType": "edit",
                        "item": {
                            "path": (
                                "/tests/k8s_container/kubesonic_profiles/"
                                "gnmi-golden.json"
                            )
                        },
                    },
                    {
                        "changeType": "delete",
                        "item": {
                            "path": (
                                "/tests/k8s_container/kubesonic_profiles/"
                                "retired-example.json"
                            )
                        },
                    },
                ]
            },
        ]

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "deleted profile"
        ):
            RESOLVER._changed_paths(
                "https://dev.azure.com/mssonic/",
                "project-id",
                "repository-id",
                "token",
                123,
            )

    @mock.patch.object(RESOLVER, "_request_json")
    def test_rename_profile_is_rejected(self, request_json):
        request_json.side_effect = [
            {"value": [{"id": 1}]},
            {
                "changeEntries": [
                    {
                        "changeType": "edit",
                        "item": {
                            "path": (
                                "/tests/k8s_container/kubesonic_profiles/"
                                "gnmi-golden.json"
                            )
                        },
                    },
                    {
                        "changeType": "rename, edit",
                        "originalPath": (
                            "/tests/k8s_container/kubesonic_profiles/"
                            "retired-example.json"
                        ),
                        "item": {
                            "path": (
                                "/tests/k8s_container/"
                                "retired-example.json"
                            )
                        },
                    },
                ]
            },
        ]

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "renamed profile"
        ):
            RESOLVER._changed_paths(
                "https://dev.azure.com/mssonic/",
                "project-id",
                "repository-id",
                "token",
                123,
            )

    @mock.patch.object(RESOLVER, "_request_json")
    def test_source_rename_profile_is_rejected(self, request_json):
        request_json.side_effect = [
            {"value": [{"id": 1}]},
            {
                "changeEntries": [
                    {
                        "changeType": "sourceRename",
                        "sourceServerItem": (
                            "/tests/k8s_container/kubesonic_profiles/"
                            "retired-example.json"
                        ),
                        "item": {
                            "path": (
                                "/tests/k8s_container/"
                                "retired-example.json"
                            )
                        },
                    },
                ]
            },
        ]

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "renamed profile"
        ):
            RESOLVER._changed_paths(
                "https://dev.azure.com/mssonic/",
                "project-id",
                "repository-id",
                "token",
                123,
            )

    @mock.patch.object(RESOLVER, "_request_json")
    def test_target_rename_profile_is_rejected(self, request_json):
        request_json.side_effect = [
            {"value": [{"id": 1}]},
            {
                "changeEntries": [
                    {
                        "changeType": "targetRename",
                        "item": {
                            "path": (
                                "/tests/k8s_container/"
                                "kubesonic_profiles/new-example.json"
                            )
                        },
                    },
                ]
            },
        ]

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "renamed profile"
        ):
            RESOLVER._changed_paths(
                "https://dev.azure.com/mssonic/",
                "project-id",
                "repository-id",
                "token",
                123,
            )


class RequestTests(unittest.TestCase):
    @mock.patch.object(RESOLVER.time, "sleep")
    @mock.patch.object(RESOLVER, "urlopen")
    def test_request_retries_transient_http_failure(self, urlopen, sleep):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok": true}'
        urlopen.side_effect = [
            RESOLVER.HTTPError(
                "https://example.test",
                503,
                "Unavailable",
                {},
                io.BytesIO(b"temporary"),
            ),
            response,
        ]

        result = RESOLVER._request_json(
            "https://example.test",
            "token",
        )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(1)


class TestbedSelectionTests(unittest.TestCase):
    def test_exact_testbed_derives_inventory_facts(self):
        selected = RESOLVER._select_exact_testbed(
            [
                _testbed(
                    "testbed-bjw-can-720dt-3",
                    "t1",
                    dut=["dut-1", "dut-2"],
                )
            ],
            "testbed-bjw-can-720dt-3",
        )

        self.assertEqual(selected["topo"], "t1")
        self.assertEqual(selected["dut"], ["dut-1", "dut-2"])

    def test_exact_testbed_accepts_keyed_dut_inventory(self):
        selected = RESOLVER._select_exact_testbed(
            [
                _testbed(
                    "testbed-bjw-can-720dt-3",
                    dut={
                        "bjw-can-720dt-3": {
                            "name": "bjw-can-720dt-3",
                        }
                    },
                )
            ],
            "testbed-bjw-can-720dt-3",
        )

        self.assertEqual(selected["name"], "testbed-bjw-can-720dt-3")

    def test_exact_testbed_rejects_reserved_tag(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "excluded by comment tag"
        ):
            RESOLVER._select_exact_testbed(
                [
                    _testbed(
                        "testbed-bjw-can-720dt-3",
                        comment="AIBE test only",
                    )
                ],
                "testbed-bjw-can-720dt-3",
            )

    def test_exact_testbed_rejects_unknown_name(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "Unknown physical testbed"
        ):
            RESOLVER._select_exact_testbed(
                [_testbed("testbed-bjw-can-720dt-3")],
                "testbed-bjw-can-720dt-4",
            )

    def test_exact_testbed_rejects_unavailable_locked_or_nightly(self):
        unavailable = _testbed(
            "testbed-bjw-can-720dt-3",
            status="UNAVAILABLE",
        )
        locked = _testbed(
            "testbed-bjw-can-720dt-4",
            status="LOCKED",
            locked_by="another-plan",
        )
        nightly = _testbed(
            "testbed-bjw-can-720dt-5",
            nightly_test=True,
        )

        for testbed, reason in (
            (unavailable, "status is UNAVAILABLE"),
            (locked, "locked by another-plan"),
            (nightly, "reserved for nightly"),
        ):
            with self.subTest(name=testbed["name"]):
                with self.assertRaisesRegex(
                    RESOLVER.ResolutionError, reason
                ):
                    RESOLVER._select_exact_testbed(
                        [testbed],
                        testbed["name"],
                    )

    def test_exact_testbed_rejects_unsafe_topology(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError,
            "topology contains unsupported characters",
        ):
            RESOLVER._select_exact_testbed(
                [_testbed("testbed-bjw-can-720dt-3", "m0;bad")],
                "testbed-bjw-can-720dt-3",
            )


class TestbedQueryTests(unittest.TestCase):
    @mock.patch.object(RESOLVER, "_request_json")
    def test_query_reads_every_inventory_page(self, request_json):
        request_json.side_effect = [
            {
                "success": True,
                "data": [
                    {"name": f"testbed-{index}"} for index in range(2000)
                ],
                "total": 2001,
            },
            {
                "success": True,
                "data": [{"name": "testbed-2000"}],
                "total": 2001,
            },
        ]

        testbeds = RESOLVER._query_testbeds("token")

        self.assertEqual(len(testbeds), 2001)
        self.assertEqual(request_json.call_count, 2)
        self.assertEqual(request_json.call_args_list[1].args[2]["page"], 2)


class MainTests(unittest.TestCase):
    @mock.patch.dict(
        os.environ,
        {
            "PIPELINE_REF": "refs/heads/internal",
            "PR_ID": "123",
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
    def test_main_infers_profile_and_sets_fixed_suite_option(self):
        source_commit = "a" * 40
        profile_path = (
            "/tests/k8s_container/kubesonic_profiles/gnmi-golden.json"
        )
        selected = _testbed("testbed-bjw-can-720dt-3")
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_resolve_pull_request",
                    return_value=({"status": "active"}, source_commit),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_changed_paths",
                    return_value=[profile_path],
                )
            )
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_fetch_profile",
                    return_value=_profile(),
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
                mock.call("resolvedSourceCommit", source_commit),
                mock.call(
                    "resolvedTestScripts",
                    "k8s_container/test_gnmi.py",
                ),
                mock.call(
                    "resolvedSpecificParam",
                    '[{"name":"k8s_container","param":'
                    '"--k8s-container-test"}]',
                ),
                mock.call(
                    "resolvedTestbedName",
                    "testbed-bjw-can-720dt-3",
                ),
                mock.call("resolvedTopology", "m0"),
            ],
        )
        write_summary.assert_called_once_with(
            123,
            source_commit,
            profile_path,
            selected,
            {"selectors": ["k8s_container/test_gnmi.py"]},
        )


if __name__ == "__main__":
    unittest.main()
