#!/usr/bin/env python3
"""Focused tests for the KubeSonic manual input resolver."""

import importlib.util
import io
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("resolve_manual_inputs.py")
SPEC = importlib.util.spec_from_file_location("resolve_manual_inputs", SCRIPT)
RESOLVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESOLVER)


def _profile():
    return {
        "version": 1,
        "selectors": ["k8s_container/test_gnmi.py"],
        "parameters": {
            "k8s-container-test": True,
            "k8s-gnmi-role": "golden",
        },
        "requirements": {
            "topologies": ["m0", "mx"],
            "name_prefixes": ["testbed-bjw-can-720dt-"],
            "dut_count": 1,
        },
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
    def test_profile_resolves_structured_parameters(self):
        resolved = RESOLVER._validate_profile(_profile())

        self.assertEqual(resolved["selectors"], ["k8s_container/test_gnmi.py"])
        self.assertEqual(
            resolved["parameter_tokens"],
            ["--k8s-container-test", "--k8s-gnmi-role=golden"],
        )
        self.assertEqual(resolved["topologies"], ["m0", "mx"])

    def test_profile_requires_explicit_suite_opt_in(self):
        profile = _profile()
        profile["parameters"]["k8s-container-test"] = False

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "k8s-container-test"
        ):
            RESOLVER._validate_profile(profile)

    def test_profile_rejects_shell_values(self):
        profile = _profile()
        profile["parameters"]["k8s-gnmi-role"] = "golden;echo"

        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "Unsupported value"
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
    def test_from_pr_requires_one_changed_profile(self):
        path = RESOLVER._resolve_profile_path(
            "from-pr",
            ["/tests/k8s_container/kubesonic_profiles/gnmi-golden.json"],
        )

        self.assertEqual(
            path, "/tests/k8s_container/kubesonic_profiles/gnmi-golden.json"
        )

    def test_named_profile_resolves_under_trusted_root(self):
        self.assertEqual(
            RESOLVER._resolve_profile_path("gnmi-golden", []),
            "/tests/k8s_container/kubesonic_profiles/gnmi-golden.json",
        )

    def test_from_pr_rejects_ambiguous_profiles(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "exactly one changed"
        ):
            RESOLVER._resolve_profile_path(
                "from-pr",
                [
                    "/tests/k8s_container/kubesonic_profiles/one.json",
                    "/tests/k8s_container/kubesonic_profiles/two.json",
                ],
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
    def setUp(self):
        self.requirements = RESOLVER._validate_profile(_profile())

    def test_exact_testbed_derives_topology(self):
        selected, count = RESOLVER._select_testbed(
            [_testbed("testbed-bjw-can-720dt-3", "m0")],
            "testbed-bjw-can-720dt-3",
            self.requirements,
            "0" * 40,
        )

        self.assertEqual(selected["topo"], "m0")
        self.assertEqual(count, 1)

    def test_auto_excludes_nightly_locked_and_tagged_testbeds(self):
        selected, count = RESOLVER._select_testbed(
            [
                _testbed(
                    "testbed-bjw-can-720dt-1",
                    nightly_test=True,
                ),
                _testbed(
                    "testbed-bjw-can-720dt-2",
                    locked_by="another-plan",
                    status="LOCKED",
                ),
                _testbed(
                    "testbed-bjw-can-720dt-3",
                    comment="AIBE test only",
                ),
                _testbed("testbed-bjw-can-720dt-4", "mx"),
            ],
            "auto",
            self.requirements,
            "0" * 40,
        )

        self.assertEqual(selected["name"], "testbed-bjw-can-720dt-4")
        self.assertEqual(count, 1)

    def test_auto_selection_is_deterministic(self):
        testbeds = [
            _testbed("testbed-bjw-can-720dt-2", "mx"),
            _testbed("testbed-bjw-can-720dt-3", "m0"),
        ]

        first, count = RESOLVER._select_testbed(
            testbeds,
            "auto",
            self.requirements,
            "0000000100000000000000000000000000000000",
        )
        second, _ = RESOLVER._select_testbed(
            list(reversed(testbeds)),
            "auto",
            self.requirements,
            "0000000100000000000000000000000000000000",
        )

        self.assertEqual(count, 2)
        self.assertEqual(first["name"], second["name"])

    def test_exact_testbed_reports_ineligible_reason(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "reserved for nightly"
        ):
            RESOLVER._select_testbed(
                [
                    _testbed(
                        "testbed-bjw-can-720dt-3",
                        nightly_test=True,
                    )
                ],
                "testbed-bjw-can-720dt-3",
                self.requirements,
                "0" * 40,
            )

    def test_shared_exact_testbed_derives_unlisted_safe_topology(self):
        selected = RESOLVER._select_exact_testbed(
            [_testbed("testbed-bjw-can-720dt-3", "t1")],
            "testbed-bjw-can-720dt-3",
        )

        self.assertEqual(selected["topo"], "t1")

    def test_shared_exact_testbed_rejects_reserved_tag(self):
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

    def test_shared_exact_testbed_rejects_unknown_name(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError, "Unknown physical testbed"
        ):
            RESOLVER._select_exact_testbed(
                [_testbed("testbed-bjw-can-720dt-3")],
                "testbed-bjw-can-720dt-4",
            )

    def test_shared_exact_testbed_rejects_unavailable_or_locked(self):
        unavailable = _testbed(
            "testbed-bjw-can-720dt-3",
            status="UNAVAILABLE",
        )
        locked = _testbed(
            "testbed-bjw-can-720dt-4",
            status="LOCKED",
            locked_by="another-plan",
        )

        for testbed, reason in (
            (unavailable, "status is UNAVAILABLE"),
            (locked, "locked by another-plan"),
        ):
            with self.subTest(name=testbed["name"]):
                with self.assertRaisesRegex(
                    RESOLVER.ResolutionError, reason
                ):
                    RESOLVER._select_exact_testbed(
                        [testbed],
                        testbed["name"],
                    )

    def test_shared_exact_testbed_rejects_unsafe_topology(self):
        with self.assertRaisesRegex(
            RESOLVER.ResolutionError,
            "topology contains unsupported characters",
        ):
            RESOLVER._select_exact_testbed(
                [_testbed("testbed-bjw-can-720dt-3", "m0;bad")],
                "testbed-bjw-can-720dt-3",
            )

    def test_auto_excludes_unsafe_inventory_values(self):
        selected, count = RESOLVER._select_testbed(
            [
                _testbed("testbed-bjw-can-720dt-1$(bad)"),
                _testbed(
                    "testbed-bjw-can-720dt-2",
                    topology="m0;bad",
                ),
                _testbed("testbed-bjw-can-720dt-3"),
            ],
            "auto",
            self.requirements,
            "0" * 40,
        )

        self.assertEqual(selected["name"], "testbed-bjw-can-720dt-3")
        self.assertEqual(count, 1)


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


if __name__ == "__main__":
    unittest.main()
