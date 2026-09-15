"""Focused unit coverage for shared transceiver peer resolution."""
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pytest

from tests.common.platform import interface_utils
from tests.transceiver import conftest as transceiver_conftest
from tests.transceiver.common import topology


class FakeDut:
    """Minimal DUT shape needed by the shared loaders and resolver."""

    def __init__(self, hostname, asic_index=0):
        self.hostname = hostname
        self.facts = {"platform": "test-platform", "hwsku": "test-hwsku"}
        self._asic_index = asic_index
        self._asic_error = None

    def get_port_asic_instance(self, _port):
        if self._asic_error:
            pytest.fail(self._asic_error)
        return SimpleNamespace(asic_index=self._asic_index)


class TestGetDevConn(unittest.TestCase):
    def test_asic_filter_preserves_peer_entries(self):
        dut = FakeDut("dut-a", asic_index=1)
        ethernet0_peer = {"peerdevice": "dut-b", "peerport": "Ethernet8"}
        graph = {
            "device_conn": {
                "dut-a": {
                    "Ethernet0": ethernet0_peer,
                    "Ethernet4": {
                        "peerdevice": "dut-c",
                        "peerport": "Ethernet12",
                    },
                }
            }
        }

        with patch.object(
            interface_utils,
            "get_port_map",
            return_value={"Ethernet0": [1]},
        ):
            portmap, connections = interface_utils.get_dev_conn(dut, graph, 1)

        self.assertEqual(portmap, {"Ethernet0": [1]})
        self.assertEqual(connections, {"Ethernet0": ethernet0_peer})
        self.assertIs(connections["Ethernet0"], ethernet0_peer)


class TestResolveRemotePeer(unittest.TestCase):
    def setUp(self):
        self.local = FakeDut("dut-a")

    def test_same_dut_peer_uses_selected_host_and_breakout_primary(self):
        graph_result = (
            {"Ethernet0": [0]},
            {"Ethernet0": {"peerdevice": "dut-a", "peerport": "Ethernet12"}},
        )
        mapping_loader = Mock(return_value=({"Ethernet12": "Ethernet8"}, None))

        with patch.object(
            topology,
            "get_dev_conn",
            return_value=graph_result,
        ) as get_dev_conn:
            peer, error = topology.resolve_remote_peer(
                self.local,
                {"dut-a": self.local},
                {},
                "Ethernet0",
                mapping_loader,
            )

        self.assertIsNone(error)
        self.assertIs(peer.host, self.local)
        self.assertEqual(peer.device, "dut-a")
        self.assertEqual(peer.port, "Ethernet12")
        self.assertEqual(peer.primary_port, "Ethernet8")
        get_dev_conn.assert_called_once_with(self.local, {}, 0)
        mapping_loader.assert_called_once_with("dut-a")

    def test_cross_dut_peer_uses_remote_host_and_remote_mapping(self):
        remote = FakeDut("dut-b", asic_index=1)
        graph_result = (
            {"Ethernet0": [0]},
            {
                "Ethernet0": {
                    "peerdevice": "dut-b",
                    "peerport": "Ethernet20",
                }
            },
        )
        mapping_loader = Mock(
            return_value=({"Ethernet20": "Ethernet16"}, None)
        )

        with patch.object(topology, "get_dev_conn", return_value=graph_result):
            peer, error = topology.resolve_remote_peer(
                self.local,
                {"dut-a": self.local, "dut-b": remote},
                {},
                "Ethernet0",
                mapping_loader,
            )

        self.assertIsNone(error)
        self.assertIs(peer.host, remote)
        self.assertEqual(peer.device, "dut-b")
        self.assertEqual(peer.port, "Ethernet20")
        self.assertEqual(peer.primary_port, "Ethernet16")
        mapping_loader.assert_called_once_with("dut-b")

    def test_missing_peer_host_returns_error_before_mapping_lookup(self):
        graph_result = (
            {"Ethernet0": [0]},
            {
                "Ethernet0": {
                    "peerdevice": "missing-dut",
                    "peerport": "Ethernet8",
                }
            },
        )
        mapping_loader = Mock()

        with patch.object(topology, "get_dev_conn", return_value=graph_result):
            peer, error = topology.resolve_remote_peer(
                self.local,
                {"dut-a": self.local},
                {},
                "Ethernet0",
                mapping_loader,
            )

        self.assertIsNone(peer)
        self.assertIn("missing-dut is not available as a DUT host", error)
        mapping_loader.assert_not_called()

    def test_mapping_loader_error_is_propagated(self):
        graph_result = (
            {"Ethernet0": [0]},
            {"Ethernet0": {"peerdevice": "dut-a", "peerport": "Ethernet8"}},
        )
        mapping_loader = Mock(return_value=(None, "mapping query failed"))

        with patch.object(topology, "get_dev_conn", return_value=graph_result):
            peer, error = topology.resolve_remote_peer(
                self.local,
                {"dut-a": self.local},
                {},
                "Ethernet0",
                mapping_loader,
            )

        self.assertIsNone(peer)
        self.assertIn("mapping query failed", error)

    def test_asic_lookup_pytest_failure_is_returned_as_error(self):
        self.local._asic_error = "Ethernet999 is not mapped to an ASIC"

        peer, error = topology.resolve_remote_peer(
            self.local,
            {"dut-a": self.local},
            {},
            "Ethernet999",
            Mock(),
        )

        self.assertIsNone(peer)
        self.assertIn("ASIC lookup failed", error)
        self.assertIn("Ethernet999 is not mapped to an ASIC", error)


class TestLazyPerDutLoaders(unittest.TestCase):
    def setUp(self):
        self.local = FakeDut("dut-a")
        self.remote = FakeDut("dut-b")
        self.unused = FakeDut("dut-unused")

    def test_mapping_loader_queries_only_requested_peer_and_caches_it(self):
        selected_mapping = {"Ethernet0": "Ethernet0"}
        remote_mapping = {"Ethernet12": "Ethernet8"}

        with patch.object(
            transceiver_conftest,
            "get_lport_to_first_subport_mapping",
            return_value=remote_mapping,
        ) as get_mapping:
            loader = transceiver_conftest._build_lport_mapping_loader(
                self.local,
                [self.local, self.remote, self.unused],
                selected_mapping,
            )
            local_result = loader("dut-a")
            first_remote_result = loader("dut-b")
            second_remote_result = loader("dut-b")

        self.assertEqual(local_result, (selected_mapping, None))
        self.assertEqual(first_remote_result, (remote_mapping, None))
        self.assertEqual(second_remote_result, (remote_mapping, None))
        get_mapping.assert_called_once_with(self.remote)

    def test_mapping_loader_returns_soft_error_for_unknown_host(self):
        loader = transceiver_conftest._build_lport_mapping_loader(
            self.local,
            [self.local, self.remote, self.unused],
            {"Ethernet0": "Ethernet0"},
        )

        mapping, error = loader("missing-dut")

        self.assertIsNone(mapping)
        self.assertEqual(error, "DUT host is unavailable")

    def test_attribute_loader_queries_only_requested_peer_and_caches_it(self):
        selected_attributes = {"Ethernet0": {}}
        remote_attributes = {"Ethernet8": {}}
        request = Mock()

        with patch.object(
            transceiver_conftest,
            "_load_port_attributes",
            return_value=(remote_attributes, None, False),
        ) as load_attributes:
            loader = transceiver_conftest._build_port_attributes_loader(
                request,
                "/inventory",
                self.local,
                [self.local, self.remote, self.unused],
                selected_attributes,
            )
            local_result = loader("dut-a")
            first_remote_result = loader("dut-b")
            second_remote_result = loader("dut-b")

        self.assertEqual(local_result, (selected_attributes, None))
        self.assertEqual(first_remote_result, (remote_attributes, None))
        self.assertEqual(second_remote_result, (remote_attributes, None))
        load_attributes.assert_called_once_with(
            request,
            "/inventory",
            self.remote,
        )

    def test_peer_template_validation_failure_is_a_soft_loader_error(self):
        request = Mock()
        selected_attributes = {"Ethernet0": {}}

        with patch.object(
            transceiver_conftest,
            "_load_port_attributes",
            return_value=(
                None,
                "template validation failures: missing DOM attribute",
                False,
            ),
        ):
            loader = transceiver_conftest._build_port_attributes_loader(
                request,
                "/inventory",
                self.local,
                [self.local, self.remote],
                selected_attributes,
            )
            attributes, error = loader("dut-b")

        self.assertIsNone(attributes)
        self.assertIn("template validation failures", error)


class TestCanonicalAttributeValidation(unittest.TestCase):
    def _load_with_mocks(
        self,
        request,
        dut,
        base_attributes,
        merged_attributes,
        compliance=None,
    ):
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    transceiver_conftest.os.path,
                    "isdir",
                    return_value=True,
                )
            )
            stack.enter_context(
                patch.object(
                    transceiver_conftest.os.path,
                    "isfile",
                    return_value=True,
                )
            )
            dut_info_loader = stack.enter_context(
                patch.object(transceiver_conftest, "DutInfoLoader")
            )
            attribute_manager = stack.enter_context(
                patch.object(transceiver_conftest, "AttributeManager")
            )
            template_validator = stack.enter_context(
                patch.object(transceiver_conftest, "TemplateValidator")
            )
            dut_loader = dut_info_loader.return_value
            dut_loader.build_base_port_attributes.return_value = (
                base_attributes
            )
            attribute_builder = attribute_manager.return_value
            attribute_builder.build_port_attributes.return_value = (
                merged_attributes
            )
            if compliance is not None:
                validator = template_validator.return_value
                validator.validate.return_value = compliance
            result = transceiver_conftest._load_port_attributes(
                request,
                "/inventory",
                dut,
            )
        return result, template_validator

    def test_selected_dut_hard_fails_non_skippable_loader_error(self):
        with patch.object(
            transceiver_conftest,
            "_load_port_attributes",
            return_value=(None, "invalid selected-DUT inventory", False),
        ):
            with self.assertRaises(pytest.fail.Exception):
                transceiver_conftest.port_attributes_dict.__wrapped__(
                    Mock(),
                    "/inventory",
                    FakeDut("dut-a"),
                )

    def test_selected_dut_skips_skippable_loader_error(self):
        with patch.object(
            transceiver_conftest,
            "_load_port_attributes",
            return_value=(None, "selected DUT has no configured ports", True),
        ):
            with self.assertRaises(pytest.skip.Exception):
                transceiver_conftest.port_attributes_dict.__wrapped__(
                    Mock(),
                    "/inventory",
                    FakeDut("dut-a"),
                )

    def test_template_validation_runs_for_canonical_dut_load(self):
        request = Mock()
        request.config.getoption.return_value = False
        dut = FakeDut("dut-b")
        base_attributes = {"Ethernet8": {"BASE_ATTRIBUTES": {}}}
        merged_attributes = {"Ethernet8": {"DOM_ATTRIBUTES": {}}}
        compliance = {
            "results": [
                {
                    "status": "NON_COMPLIANT",
                    "port": "Ethernet8",
                    "deployment": "400G_STRAIGHT",
                    "missing_required": [
                        "DOM_ATTRIBUTES.shutdown_rx_power_threshold"
                    ],
                }
            ]
        }

        result, template_validator = self._load_with_mocks(
            request,
            dut,
            base_attributes,
            merged_attributes,
            compliance,
        )
        attributes, error, skippable = result

        self.assertIsNone(attributes)
        self.assertFalse(skippable)
        self.assertIn("Ethernet8 missing required", error)
        template_validator.return_value.validate.assert_called_once_with(
            merged_attributes
        )

    def test_skip_option_bypasses_template_validation_only(self):
        request = Mock()
        request.config.getoption.return_value = True
        dut = FakeDut("dut-b")
        base_attributes = {"Ethernet8": {"BASE_ATTRIBUTES": {}}}
        merged_attributes = {"Ethernet8": {"DOM_ATTRIBUTES": {}}}

        result, template_validator = self._load_with_mocks(
            request,
            dut,
            base_attributes,
            merged_attributes,
        )
        attributes, error, skippable = result

        self.assertEqual(attributes, merged_attributes)
        self.assertIsNone(error)
        self.assertFalse(skippable)
        template_validator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
