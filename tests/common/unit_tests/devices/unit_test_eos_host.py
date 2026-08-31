"""
Unit tests for tests/common/devices/eos.py (EosHost) get_dut_iface_mac /
get_bridge_mac.

EosHost extends AnsibleHostBase, whose __init__ needs a live ansible_adhoc
fixture. To unit test the pure MAC-retrieval logic without a real cEOS
device (or Ansible), instantiate via EosHost.__new__(EosHost) -- bypassing
__init__ -- and shadow the eos_command/eos_config bound methods with
MagicMocks as instance attributes. get_dut_iface_mac/get_bridge_mac only
ever touch those two methods, so this fully exercises the logic added by
(and, for get_dut_iface_mac, reverted from) PR #21312:

  * get_dut_iface_mac() must be back to its pre-#21312 behavior: read
    'show interfaces <if> | json' once and return physicalAddress, with no
    switchport/routed config changes -- see issue #27395.
  * get_bridge_mac() carries the #21312 switchport-toggle behavior MACsec
    needs, and must always attempt to restore 'no switchport' once
    'switchport' has been applied, even if the intervening read raises.

Follows the repo unit-test convention (unit_test_*.py, unittest.mock).
"""

import os
import sys
from unittest.mock import MagicMock, call

import pytest

# Make the repo root importable so ``tests.common.devices.eos`` resolves
# regardless of the pytest invocation directory.
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(_TEST_DIR)))
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.common.devices.eos import EosHost  # noqa: E402

INTERFACE = "Ethernet1"


def make_host():
    """Instantiate an EosHost without running its Ansible-dependent __init__."""
    host = EosHost.__new__(EosHost)
    host.hostname = "eos_test"
    return host


def show_interfaces_output(forwarding_model, physical_address):
    """Shape a 'show interfaces <if> | json' eos_command() return value."""
    return {
        "stdout": [{
            "interfaces": {
                INTERFACE: {
                    "forwardingModel": forwarding_model,
                    "physicalAddress": physical_address,
                }
            }
        }]
    }


SWITCHPORT_PARENTS = ["interface {}".format(INTERFACE)]


class TestGetDutIfaceMac:
    """get_dut_iface_mac() must be back to pre-#21312 semantics: a single
    read, no config changes, regardless of forwardingModel."""

    def test_routed_interface_returns_first_read_no_config_calls(self):
        host = make_host()
        host.eos_command = MagicMock(
            return_value=show_interfaces_output("routed", "AA:AA:AA:AA:AA:01"))
        host.eos_config = MagicMock()

        mac = host.get_dut_iface_mac(INTERFACE)

        assert mac == "AA:AA:AA:AA:AA:01"
        assert host.eos_command.call_count == 1
        host.eos_config.assert_not_called()

    def test_switched_interface_returns_physical_address_no_config_calls(self):
        host = make_host()
        host.eos_command = MagicMock(
            return_value=show_interfaces_output("bridged", "BB:BB:BB:BB:BB:02"))
        host.eos_config = MagicMock()

        mac = host.get_dut_iface_mac(INTERFACE)

        assert mac == "BB:BB:BB:BB:BB:02"
        assert host.eos_command.call_count == 1
        host.eos_config.assert_not_called()

    def test_malformed_output_returns_none(self):
        host = make_host()
        host.eos_command = MagicMock(return_value={"stdout": [{}]})
        host.eos_config = MagicMock()

        assert host.get_dut_iface_mac(INTERFACE) is None
        host.eos_config.assert_not_called()


class TestGetBridgeMac:
    """get_bridge_mac() carries the #21312 switchport-toggle behavior that
    MACsec relies on to observe the bridge/system MAC of a routed port."""

    def test_already_switched_interface_no_toggle(self):
        host = make_host()
        host.eos_command = MagicMock(
            return_value=show_interfaces_output("bridged", "CC:CC:CC:CC:CC:03"))
        host.eos_config = MagicMock()

        mac = host.get_bridge_mac(INTERFACE)

        assert mac == "CC:CC:CC:CC:CC:03"
        assert host.eos_command.call_count == 1
        host.eos_config.assert_not_called()

    def test_routed_interface_toggles_switchport_and_restores(self):
        host = make_host()
        host.eos_command = MagicMock(side_effect=[
            show_interfaces_output("routed", "AA:AA:AA:AA:AA:01"),
            show_interfaces_output("routed", "DD:DD:DD:DD:DD:04"),
        ])
        host.eos_config = MagicMock()

        mac = host.get_bridge_mac(INTERFACE)

        # The bridge MAC is the second (switchport-mode) read, not the
        # first (routed-mode) read.
        assert mac == "DD:DD:DD:DD:DD:04"
        assert host.eos_command.call_count == 2
        assert host.eos_config.call_args_list == [
            call(lines=["switchport"], parents=SWITCHPORT_PARENTS),
            call(lines=["no switchport"], parents=SWITCHPORT_PARENTS),
        ]

    def test_restoration_attempted_even_if_second_read_raises(self):
        host = make_host()
        host.eos_command = MagicMock(side_effect=[
            show_interfaces_output("routed", "AA:AA:AA:AA:AA:01"),
            Exception("simulated eos_command failure"),
        ])
        host.eos_config = MagicMock()

        # The method's broad except swallows the failure and returns None,
        # matching get_dut_iface_mac's existing error-handling contract.
        assert host.get_bridge_mac(INTERFACE) is None

        # 'no switchport' must still have been attempted: the interface
        # must never be left stranded in switchport mode.
        assert host.eos_config.call_args_list == [
            call(lines=["switchport"], parents=SWITCHPORT_PARENTS),
            call(lines=["no switchport"], parents=SWITCHPORT_PARENTS),
        ]

    def test_restoration_failure_is_reported_not_hidden(self):
        host = make_host()
        host.eos_command = MagicMock(
            return_value=show_interfaces_output("routed", "AA:AA:AA:AA:AA:01"))
        # 'switchport' succeeds; 'no switchport' itself fails.
        host.eos_config = MagicMock(side_effect=[None, Exception("restore failed")])

        # The failure must not be silently swallowed: get_bridge_mac still
        # reports failure the same way every other error path does (log +
        # None), rather than returning a MAC as if nothing went wrong.
        assert host.get_bridge_mac(INTERFACE) is None
        assert host.eos_config.call_count == 2

    def test_malformed_output_returns_none(self):
        host = make_host()
        host.eos_command = MagicMock(return_value={"stdout": [{}]})
        host.eos_config = MagicMock()

        assert host.get_bridge_mac(INTERFACE) is None
        host.eos_config.assert_not_called()


if __name__ == "__main__":
    sys.exit(pytest.main([os.path.abspath(__file__), "-v"]))
