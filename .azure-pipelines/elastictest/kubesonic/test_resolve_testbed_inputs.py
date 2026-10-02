#!/usr/bin/env python3
"""Focused tests for the shared exact-testbed resolver entry point."""

import os
import unittest
from contextlib import ExitStack
from unittest import mock

import resolve_testbed_inputs as RESOLVER


class ExactTestbedEntryPointTests(unittest.TestCase):
    @mock.patch.dict(
        os.environ,
        {
            "TESTBED": "testbed-bjw-can-720dt-3",
            "ELASTICTEST_MSAL_CLIENT_ID": "client-id",
            "SONIC_AUTOMATION_UMI": "managed-identity",
        },
        clear=True,
    )
    def test_main_sets_resolved_testbed_and_topology(self):
        selected = {
            "name": "testbed-bjw-can-720dt-3",
            "topo": "m0",
        }
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    RESOLVER,
                    "_get_elastictest_token",
                    return_value="token",
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
                    "_select_exact_testbed",
                    return_value=selected,
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
                mock.call(
                    "resolvedTestbedName",
                    "testbed-bjw-can-720dt-3",
                ),
                mock.call("resolvedTopology", "m0"),
            ],
        )
        write_summary.assert_called_once_with(selected)


if __name__ == "__main__":
    unittest.main()
