"""Collection and upstream-boundary contracts for the exact-16 package."""

import ast
import importlib.util
from pathlib import Path
import re
import unittest

import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPO_ROOT / "tests" / "evpn_mh"

EXPECTED_CASES = {
    "test_remote_broadcast_traffic",
    "test_remote_multicast_traffic",
    "test_unknown_unicast",
    "test_inter_subnet_ping",
    "test_intra_subnet_ping",
    "test_local_bias",
    "test_remote_unicast_for_ecmp",
    "test_portchannel_deconf",
    "test_portchannel_flap",
    "test_interface_to_spine_flap",
    "test_vlan_member_flap",
    "test_portchannel_shut_noshut",
    "test_portchannel_member_flap",
    "test_config_reload",
    "test_continuous_traffic_reboot_df",
    "test_ipv6_traffic",
}


def _test_functions(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def _public_candidate_paths():
    roots = (PACKAGE_ROOT,)
    exact_files = (
        REPO_ROOT / "ansible" / "roles" / "test" / "files"
        / "ptftests" / "evpn_mh_remote.py",
        REPO_ROOT / "ansible" / "roles" / "test" / "files"
        / "ptftests" / "py3" / "evpn_mh_traffic.py",
        REPO_ROOT / "docs" / "testplan" / "evpn_mh"
        / "evpn_mh_16cases.md",
    )
    accepted = {".py", ".yml", ".yaml", ".md"}
    paths = []
    for root in roots:
        if not root.exists():
            continue
        paths.extend(
            path for path in root.rglob("*")
            if path.is_file() and path.suffix in accepted
            and "__pycache__" not in path.parts
        )
    paths.extend(path for path in exact_files if path.is_file())
    return tuple(sorted(set(paths)))


class CollectionContractTests(unittest.TestCase):
    def test_segment_locality_parser_does_not_match_boolean_substrings(self):
        path = PACKAGE_ROOT / "state.py"
        spec = importlib.util.spec_from_file_location(
            "evpn_mh_state_contract_test", path)
        state = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(state)

        self.assertTrue(state.segment_is_local({"local": True}))
        self.assertFalse(state.segment_is_remote({"local": True}))
        self.assertTrue(state.segment_is_remote({"local": False}))
        self.assertFalse(state.segment_is_local({"local": False}))
        for value in ("TRUE", "FALSE"):
            self.assertFalse(state.segment_is_local({"type": value}))
            self.assertFalse(state.segment_is_remote({"type": value}))
        self.assertTrue(state.segment_is_local({"type": "L"}))
        self.assertTrue(state.segment_is_remote({"type": "R"}))
        self.assertFalse(state.segment_is_df({"type": "LN"}))

    def test_exact_sixteen_function_names_are_preserved(self):
        discovered = set()
        for filename in ("test_traffic.py", "test_resiliency.py"):
            discovered.update(_test_functions(PACKAGE_ROOT / filename))
        self.assertEqual(discovered, EXPECTED_CASES)
        self.assertEqual(len(discovered), 16)

    def test_functional_collection_ignores_feature_unit_tests(self):
        conftest = (PACKAGE_ROOT / "conftest.py").read_text(encoding="utf-8")
        self.assertIn(
            'collect_ignore_glob = ["unit_tests/test_*.py"]',
            conftest,
        )
        self.assertEqual(
            len(tuple((PACKAGE_ROOT / "unit_tests").glob("test_*.py"))),
            6,
        )

    def test_reboot_event_contract_is_validated_before_worker_start(self):
        profiles = yaml.safe_load(
            (PACKAGE_ROOT / "files" / "traffic_profiles.yml").read_text(
                encoding="utf-8"
            )
        )["profiles"]
        self.assertGreater(
            float(profiles["df_reboot_continuous"]["event_window_seconds"]),
            0,
        )
        tree = ast.parse(
            (PACKAGE_ROOT / "test_resiliency.py").read_text(encoding="utf-8")
        )
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "test_continuous_traffic_reboot_df"
        )
        calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
        window_call = next(
            node for node in calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "traffic_event_window"
        )
        start_call = next(
            node for node in calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "start_traffic_profile"
        )
        self.assertLess(window_call.lineno, start_call.lineno)
        guarded = [
            node for node in ast.walk(function)
            if isinstance(node, ast.Try)
            and start_call in tuple(ast.walk(node))
            and any(
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "finish_traffic_profile"
                for final in node.finalbody for child in ast.walk(final)
            )
        ]
        self.assertTrue(guarded, "reboot traffic worker lacks guaranteed cleanup")
        function_source = ast.get_source_segment(
            (PACKAGE_ROOT / "test_resiliency.py").read_text(encoding="utf-8"),
            function,
        )
        self.assertIn("observer.is_alive()", function_source)
        start_marker = next(
            node for node in calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "_mark_traffic_event"
            and len(node.args) > 1
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "event_start_file"
        )
        reboot_call = next(
            node for node in calls
            if isinstance(node.func, ast.Name) and node.func.id == "reboot"
        )
        df_bindings = [
            node for node in calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "_df_role"
            and start_marker.lineno < node.lineno < reboot_call.lineno
        ]
        self.assertGreaterEqual(len(df_bindings), 2)
        gate_call = next(
            node for node in calls
            if isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "reboot_observation_gate"
            and node.func.attr == "set"
        )
        self.assertLess(max(node.lineno for node in df_bindings),
                        gate_call.lineno)
        self.assertLess(gate_call.lineno, reboot_call.lineno)
        self.assertIn("reboot_observation_gate.wait", function_source)

    def test_case12_rechecks_df_immediately_before_member_mutation(self):
        path = PACKAGE_ROOT / "test_resiliency.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "test_portchannel_shut_noshut"
        )
        calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
        member_down = next(
            node for node in calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "interface_down"
        )
        baseline = max(
            node.lineno for node in calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "_wait_forwarding"
            and node.lineno < member_down.lineno
        )
        df_rechecks = [
            node for node in calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "_df_role"
            and baseline < node.lineno < member_down.lineno
        ]
        self.assertTrue(
            df_rechecks,
            "case12 can mutate a member using a stale pre-setup DF role",
        )

    def test_other_df_targets_are_rechecked_at_mutation_boundary(self):
        path = PACKAGE_ROOT / "test_resiliency.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        functions = {
            node.name: node for node in tree.body
            if isinstance(node, ast.FunctionDef)
        }

        local_bias = functions["test_local_bias"]
        local_calls = [
            node for node in ast.walk(local_bias) if isinstance(node, ast.Call)
        ]
        first_preference = min(
            node.lineno for node in local_calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "_set_df_preference"
        )
        local_baseline = max(
            node.lineno for node in local_calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "_wait_forwarding"
            and node.lineno < first_preference
        )
        self.assertTrue(any(
            isinstance(node.func, ast.Name)
            and node.func.id == "_df_role"
            and local_baseline < node.lineno < first_preference
            for node in local_calls
        ), "local-bias can apply preferences to a stale DF target")

        config_reload_case = functions["test_config_reload"]
        reload_calls = [
            node for node in ast.walk(config_reload_case)
            if isinstance(node, ast.Call)
        ]
        reload_mutation = next(
            node for node in reload_calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "config_reload"
        )
        capability = max(
            node.lineno for node in reload_calls
            if isinstance(node.func, ast.Name)
            and node.func.id == "uses_frrcfgd"
            and node.lineno < reload_mutation.lineno
        )
        self.assertTrue(any(
            isinstance(node.func, ast.Name)
            and node.func.id == "_df_role"
            and capability < node.lineno < reload_mutation.lineno
            for node in reload_calls
        ), "config reload can target a stale pre-capability-check DF")

    def test_member_flap_grades_event_and_post_recovery_dataplane(self):
        profiles = yaml.safe_load(
            (PACKAGE_ROOT / "files" / "traffic_profiles.yml").read_text(
                encoding="utf-8"
            )
        )["profiles"]
        self.assertGreater(
            float(profiles["member_flap_continuous"]["event_window_seconds"]),
            0,
        )
        path = PACKAGE_ROOT / "test_resiliency.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "test_portchannel_member_flap"
        )
        function_source = ast.get_source_segment(source, function)
        self.assertIn('"receive_groups": [[surviving_leg]]', function_source)
        self.assertIn('"forbidden_endpoints": [leg]', function_source)
        self.assertGreaterEqual(
            function_source.count(
                '"receive_groups": [[surviving_leg, leg]]'), 2)
        self.assertGreaterEqual(
            function_source.count('"forbidden_endpoints": []'), 2)
        normal_path = function_source.split("\n        finally:", 1)[0]

        def positions(needle):
            found = []
            cursor = 0
            while True:
                position = normal_path.find(needle, cursor)
                if position < 0:
                    return found
                found.append(position)
                cursor = position + len(needle)

        # Variable names distinguish all three phase-specific PTF workers.
        start_positions = (
            normal_path.index(
                '_mark_traffic_event(transition_job, "event_start_file")'),
            normal_path.index(
                '_mark_traffic_event(outage_job, "event_start_file")'),
            normal_path.index(
                '_mark_traffic_event(recovery_job, "event_start_file")'),
        )
        close_positions = positions("_close_traffic_event(")
        self.assertEqual(len(close_positions), 3)
        transition_worker_position = normal_path.index(
            "transition_job = start_traffic_profile(")
        operational_up_position = normal_path.index(
            "wait_interface(dut, member, True, 30)")
        lacp_selected_position = normal_path.index(
            "ptf_bond_member_operational,")
        shutdown_position = normal_path.index(
            "set_interface_admin(dut, member, False)")
        recover_position = normal_path.index("_restore_physical_lag_member(")
        overlay_position = normal_path.index("wait_evpn_mh_overlay(")
        self.assertLess(transition_worker_position, operational_up_position)
        self.assertLess(operational_up_position, lacp_selected_position)
        self.assertLess(lacp_selected_position, start_positions[0])
        self.assertLess(start_positions[0], shutdown_position)
        self.assertLess(shutdown_position, close_positions[0])
        self.assertLess(close_positions[0], start_positions[1])
        self.assertLess(start_positions[1], close_positions[1])
        self.assertLess(close_positions[1], start_positions[2])
        self.assertLess(start_positions[2], recover_position)
        self.assertLess(recover_position, overlay_position)
        self.assertLess(overlay_position, close_positions[2])
        finish_position = function_source.index("finish_traffic_profile")
        recovery_position = function_source.index(
            'ptfhost, "remote_broadcast"', finish_position)
        self.assertLess(finish_position, recovery_position)

        marker = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_mark_traffic_event"
        )
        marker_source = ast.get_source_segment(source, marker)
        self.assertIn("ack_marker", marker_source)
        self.assertIn("wait_until", marker_source)
        self.assertIn("PTF worker did not acknowledge", marker_source)

    def test_disruptions_prove_live_preconditions_before_mutation(self):
        path = PACKAGE_ROOT / "test_resiliency.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        functions = {
            node.name: ast.get_source_segment(source, node)
            for node in tree.body if isinstance(node, ast.FunctionDef)
        }

        deconf = functions["test_portchannel_deconf"]
        deconf_mutation = deconf.index("mutation_started = True")
        self.assertLess(deconf.index("_wait_forwarding("), deconf_mutation)
        self.assertLess(
            deconf.index("wait_interface(dut, portchannel, True, 30)"),
            deconf_mutation,
        )
        self.assertLess(
            deconf.index("_local_es_present(dut, evpn_mh_topology, segment)"),
            deconf_mutation,
        )

        aggregate = functions["test_portchannel_flap"]
        aggregate_shutdown = aggregate.index(
            "set_interface_admin(evpn_mh_control_plane[role], "
            "portchannel, False)")
        self.assertLess(
            aggregate.index("wait_interface(dut, portchannel, True, 30)"),
            aggregate_shutdown,
        )
        self.assertLess(
            aggregate.index("ptf_bond_member_operational,"),
            aggregate_shutdown,
        )

        underlay = functions["test_interface_to_spine_flap"]
        underlay_shutdown = underlay.index(
            "set_interface_admin(dut, uplink, False)")
        self.assertLess(
            underlay.index("wait_interface(dut, uplink, True, 30)"),
            underlay_shutdown,
        )
        self.assertLess(
            underlay.index("== expected_paths + 1"), underlay_shutdown)

        vlan = functions["test_vlan_member_flap"]
        vlan_delete = vlan.index("sudo config vlan member del")
        self.assertLess(
            vlan.index("assert _config_key_exists(dut, key)"), vlan_delete)

    def test_spine_path_rollback_is_registered_before_shutdown(self):
        path = PACKAGE_ROOT / "test_resiliency.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "test_interface_to_spine_flap"
        )
        function_source = ast.get_source_segment(source, function)
        normalized_source = re.sub(r"\s+", "", function_source)
        append_position = function_source.index("down.append(uplink)")
        shutdown_position = function_source.index(
            "set_interface_admin(dut, uplink, False)")
        self.assertLess(append_position, shutdown_position)
        self.assertIn("restore_interfaces(dut,reversed(down)", normalized_source)

    def test_checkpoint_restore_persists_before_deleting_recovery_artifact(self):
        path = PACKAGE_ROOT / "conftest.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        fixture = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "evpn_mh_config_checkpoint"
        )
        fixture_source = ast.get_source_segment(source, fixture)
        self.assertIsNotNone(fixture_source)
        teardown = fixture_source.split("\n    yield\n", 1)[1]
        normalized = re.sub(r"\s+", " ", teardown)
        normalized = normalized.replace('" "', "").replace("' '", "")

        ordered_markers = (
            "sudo config rollback",
            "_checkpoint_runtime_ready",
            "sudo config save -y",
            "_checkpoint_restore_ready",
            "sudo config delete-checkpoint",
        )
        positions = [normalized.index(marker) for marker in ordered_markers]
        self.assertEqual(positions, sorted(positions))

        # Every failure before deletion retains the named checkpoint and
        # moves to the next DUT.  The recovery artifact is deleted only after
        # exact live and persistent-state verification succeeds.
        self.assertGreaterEqual(normalized.count("checkpoint preserved"), 4)
        delete_position = normalized.index("sudo config delete-checkpoint")
        for marker in (
            "rollback failed; checkpoint preserved",
            "health; checkpoint preserved",
            "could not be persisted; checkpoint",
            "differs after restore; checkpoint",
        ):
            marker_position = normalized.index(marker)
            self.assertLess(marker_position, delete_position)
            branch_tail = normalized[marker_position:delete_position]
            self.assertIn("continue", branch_tail)

        helper = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_checkpoint_restore_ready"
        )
        helper_source = ast.get_source_segment(source, helper)
        self.assertIn("_canonical_persistent_config_db", helper_source)
        self.assertIn('expected_config["persistent"]', helper_source)
        self.assertIn("except RuntimeError", helper_source)
        runtime_helper = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_checkpoint_runtime_ready"
        )
        runtime_source = ast.get_source_segment(source, runtime_helper)
        self.assertNotIn("show version", runtime_source)
        self.assertIn("_bgp_peer_states", runtime_source)
        self.assertIn("_swss_process_states", runtime_source)
        self.assertIn("_critical_services_ready", runtime_source)

    def test_stock_health_checkpoint_wraps_every_owned_mutation(self):
        """Checkpoint setup/teardown must enclose every owned mutation."""
        path = PACKAGE_ROOT / "conftest.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        fixtures = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name.startswith("evpn_mh_")
        }

        def dependencies(name):
            return tuple(
                argument.arg for argument in fixtures[name].args.args
                if argument.arg in fixtures
            )

        checkpoint = "evpn_mh_config_checkpoint"
        eos = "evpn_mh_eos_configured"
        self.assertNotIn(eos, dependencies(checkpoint))
        self.assertIn(checkpoint, dependencies(eos))
        self.assertIn(
            checkpoint, dependencies("evpn_mh_dualtor_wiring"))

        def transitively_depends_on(name, dependency):
            direct = dependencies(name)
            return dependency in direct or any(
                transitively_depends_on(item, dependency)
                for item in direct
            )

        owned_mutations = (
            "evpn_mh_clean_start",
            "evpn_mh_dualtor_wiring",
            "evpn_mh_vxlan_paths",
            "evpn_mh_eos_configured",
            "evpn_mh_dut_configured",
            "evpn_mh_ptf_lag",
        )
        for mutation in owned_mutations:
            self.assertTrue(
                transitively_depends_on(mutation, checkpoint),
                "{} can mutate outside the SONiC checkpoint".format(mutation),
            )

        # Model pytest's dependency ordering for this pair.  A dependency is
        # set up first and torn down last, so EOS restoration must precede the
        # checkpoint's stock SONiC BGP/SWSS health comparison.
        setup_order = []

        def schedule(name):
            for dependency in dependencies(name):
                if dependency not in setup_order:
                    schedule(dependency)
            if name not in setup_order:
                setup_order.append(name)

        schedule("evpn_mh_ptf_lag")
        for mutation in owned_mutations:
            self.assertLess(
                setup_order.index(checkpoint), setup_order.index(mutation))
        teardown_order = tuple(reversed(setup_order))
        for mutation in owned_mutations:
            self.assertLess(
                teardown_order.index(mutation),
                teardown_order.index(checkpoint),
            )

        checkpoint_source = ast.get_source_segment(
            path.read_text(encoding="utf-8"), fixtures[checkpoint])
        eos_source = ast.get_source_segment(
            path.read_text(encoding="utf-8"), fixtures[eos])
        self.assertLess(
            checkpoint_source.index("_bgp_peer_states"),
            checkpoint_source.index("\n    yield"),
        )
        self.assertIn("restore_eos_config", eos_source.split("finally:", 1)[1])

    def test_eos_transit_is_proven_before_direct_peer_shutdown(self):
        path = PACKAGE_ROOT / "conftest.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        fixture = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "evpn_mh_eos_configured"
        )
        calls = sorted(
            (node for node in ast.walk(fixture) if isinstance(node, ast.Call)),
            key=lambda node: (node.lineno, node.col_offset),
        )
        phase_names = [
            call.func.id for call in calls
            if isinstance(call.func, ast.Name)
            and call.func.id in {
                "configure_eos_transit",
                "wait_until",
                "shutdown_eos_direct_peers",
                "configure_eos_remote_overlay",
            }
        ]
        self.assertEqual(phase_names, [
            "configure_eos_transit",
            "wait_until",
            "shutdown_eos_direct_peers",
            "wait_until",
            "wait_until",
            "configure_eos_remote_overlay",
        ])
        wait_callbacks = [
            call.args[3].id for call in calls
            if isinstance(call.func, ast.Name)
            and call.func.id == "wait_until"
            and len(call.args) > 3
            and isinstance(call.args[3], ast.Name)
        ]
        self.assertEqual(wait_callbacks, [
            "eos_transit_ready",
            "eos_transit_ready",
            "_dut_transit_paths_ready",
        ])

    def test_df_preference_cleanup_attempts_and_verifies_both_duts(self):
        path = PACKAGE_ROOT / "test_resiliency.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        helper = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_restore_df_preferences"
        )
        helper_source = ast.get_source_segment(source, helper)
        self.assertGreaterEqual(helper_source.count("for role, preference"), 2)
        self.assertIn("_set_df_preference", helper_source)
        self.assertIn("_df_preference", helper_source)
        self.assertIn("failures.append", helper_source)
        self.assertIn("DF preference cleanup failed", helper_source)

        local_bias = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "test_local_bias"
        )
        finally_calls = [
            child.func.id
            for node in ast.walk(local_bias) if isinstance(node, ast.Try)
            for final in node.finalbody for child in ast.walk(final)
            if isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
        ]
        self.assertIn("_restore_df_preferences", finally_calls)

    def test_portchannel_restore_uses_selected_segment_auto_esi(self):
        resiliency_path = PACKAGE_ROOT / "test_resiliency.py"
        source = resiliency_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(resiliency_path))
        testcase = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "test_portchannel_deconf"
        )
        testcase_source = ast.get_source_segment(source, testcase)
        self.assertIn("portchannel_config_snapshot", testcase_source)
        self.assertIn("restore_portchannel_config", testcase_source)

        operations_path = PACKAGE_ROOT / "operations.py"
        operations_source = operations_path.read_text(encoding="utf-8")
        operations_tree = ast.parse(
            operations_source, filename=str(operations_path)
        )
        restore = next(
            node for node in operations_tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "restore_portchannel_config"
        )
        restore_source = ast.get_source_segment(operations_source, restore)
        self.assertIn("auto-system-mac", restore_source)
        self.assertNotIn('topology["esi"]', testcase_source)
        self.assertNotIn('segment["esi"]', testcase_source)

    def test_forwarding_wait_retries_only_ptf_wrapper_failures(self):
        path = PACKAGE_ROOT / "test_resiliency.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_wait_forwarding"
        )

        class RetryablePtfFailure(Exception):
            pass

        attempts = []

        def wait_until(_timeout, _interval, _delay, callback):
            for _index in range(2):
                if callback():
                    return True
            return False

        namespace = {
            "RunAnsibleModuleFail": RetryablePtfFailure,
            "wait_until": wait_until,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     filename=str(path), mode="exec"), namespace)

        def transient_run(*_args, **_kwargs):
            attempts.append("run")
            if len(attempts) == 1:
                raise RetryablePtfFailure("transient loss")

        namespace["_run"] = transient_run
        self.assertTrue(namespace["_wait_forwarding"](
            object(), "profile", {}, {}
        ))
        self.assertEqual(attempts, ["run", "run"])

        for error_type in (ValueError, KeyError, TypeError, RuntimeError):
            attempts = []

            def deterministic_run(*_args, **_kwargs):
                attempts.append("run")
                raise error_type("invalid profile")

            namespace["_run"] = deterministic_run
            with self.assertRaises(error_type):
                namespace["_wait_forwarding"](
                    object(), "profile", {}, {}
                )
            self.assertEqual(attempts, ["run"])

    def test_two_es_bum_and_single_homed_contract(self):
        traffic = (PACKAGE_ROOT / "test_traffic.py").read_text(
            encoding="utf-8")
        profiles = yaml.safe_load(
            (PACKAGE_ROOT / "files" / "traffic_profiles.yml").read_text(
                encoding="utf-8"))
        runtime = ast.parse(traffic)
        helper = next(
            node for node in runtime.body
            if isinstance(node, ast.FunctionDef) and node.name == "_df_runtime"
        )
        helper_source = ast.get_source_segment(traffic, helper)
        self.assertIn('receive_groups = [["sh1"]]', helper_source)
        self.assertIn('topology["ethernet_segments"]', helper_source)
        self.assertIn("forbidden_endpoints.append", helper_source)
        for name in (
                "remote_broadcast", "remote_multicast",
                "remote_unknown_unicast"):
            groups = profiles["profiles"][name]["flows"][0]["receive_groups"]
            self.assertEqual(groups, [["sh1"], ["h1"], ["h2"]])
        resiliency = (PACKAGE_ROOT / "test_resiliency.py").read_text(
            encoding="utf-8")
        self.assertNotIn('"h5"', resiliency)
        self.assertIn('source_endpoint = "sh1"', resiliency)

    def test_rebased_binding_has_only_two_sonic_duts_and_stock_markers(self):
        topology_text = (PACKAGE_ROOT / "topology.py").read_text(encoding="utf-8")
        self.assertIn('TOPOLOGY_NAME = "dualtor-aa"', topology_text)
        self.assertIn(
            'REQUIRED_DUT_ROLES = ("mh_leaf0", "mh_leaf1")',
            topology_text,
        )
        third_sonic_access = re.compile(
            r"\bduts\s*\[\s*[\"']remote_leaf[\"']\s*\]"
        )
        for path in _public_candidate_paths():
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(
                third_sonic_access.search(text),
                "{} treats the remote EOS role as a SONiC DUT".format(path),
            )
        for filename in ("test_traffic.py", "test_resiliency.py"):
            text = (PACKAGE_ROOT / filename).read_text(encoding="utf-8")
            self.assertIn('pytest.mark.topology("dualtor")', text)
            self.assertIn("pytest.mark.dualtor_skip_setup_mux_ports", text)

    def test_entire_public_candidate_has_no_credentials_or_retired_material(self):
        retired_topology = "-".join(("t0", "evpn", "mh"))
        retired_profile = "_".join(("mh", "leaf2", "routed", "bum"))
        forbidden = (
            "ansible" + "_password",
            "BEGIN " + "PRIVATE KEY",
            "ssh" + "pass",
            retired_topology,
            retired_profile,
        )
        paths = _public_candidate_paths()
        self.assertGreaterEqual(len(paths), 20)
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, "{} contains {}".format(path, marker))


if __name__ == "__main__":
    unittest.main()
