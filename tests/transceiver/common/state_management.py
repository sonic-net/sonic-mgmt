"""State Preservation and Restoration helpers for transceiver System tests.

Lives at the location reserved by
``docs/testplan/transceiver/diagrams/file_organization.md`` for the
"State Preservation and Restoration helpers".

Implements the post-session / post-test restoration described in
``docs/testplan/transceiver/system_test_plan.md`` (§ State Preservation and
Restoration): bring every port back to its known-good steady state — admin-up
+ oper-up, high power mode (low-power off), and CMIS DataPath Activated.

This is the restorative counterpart to
:mod:`tests.transceiver.common.verification` (which is diagnostic): it reuses
``verification._check_cmis_state`` to decide whether a CMIS datapath needs
recycling and ``prerequisites.check_links_up`` for the final recovery verdict,
and issues port shutdown/startup through
:mod:`tests.transceiver.common.cli_helpers`.
"""
import logging

from tests.common.platform.interface_utils import get_dut_interfaces_status
from tests.transceiver.attribute_parser.attribute_keys import EEPROM_ATTRIBUTES_KEY
from tests.transceiver.common import cli_helpers
from tests.transceiver.common.prerequisites import check_links_up
from tests.transceiver.common.verification import _check_cmis_state

logger = logging.getLogger(__name__)


def _port_namespace(duthost, port):
    """Return the ASIC network namespace owning ``port``.

    Resolved the same way as the System tests
    (``tests/transceiver/system/link_behavior/test_port_link_toggle.py`` and the
    EEPROM tests): map the port to its ASIC instance, then to that ASIC's
    namespace.  On a single-ASIC DUT this is ``""``, so ``cli_helpers`` emits no
    ``-n`` flag and the command stays ``config interface startup <port>``.
    """
    return duthost.get_namespace_from_asic_id(
        duthost.get_port_asic_instance(port).asic_index
    )


def _is_oper_up(duthost, port):
    intf_status = get_dut_interfaces_status(duthost)
    s = intf_status.get(port, {}) or {}
    return s.get("admin") == "up" and s.get("oper") == "up"


def _is_lpmode_high(duthost, port):
    """Return True iff sfputil reports low-power mode is OFF (i.e. high power)."""
    out = duthost.shell(f"sudo sfputil show lpmode -p {port}", module_ignore_errors=True)
    if out.get("rc", 1) != 0:
        return True  # can't tell - don't try to "fix" what we can't observe
    for line in (out.get("stdout_lines") or []):
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == port:
            return parts[1].lower() == "off"
    return True


def post_state_restoration(duthost, port_attributes_dict):
    """Restore every port in ``port_attributes_dict`` to known-good state.

    Per ``system_test_plan.md`` post-session State Restoration:
      * admin-up + oper-up,
      * high power mode (low-power off),
      * DataPath Activated.

    The function is restorative, not diagnostic - it does the minimum
    needed to bring each port back, then reports which ports it touched
    and which ones still failed to recover.

    Returns:
        dict: ``{
            'admin_up_restored': [str],     # ports we issued 'startup' on
            'lpmode_high_restored': [str],  # ports we toggled out of LPMode
            'datapath_recycled': [str],     # ports we shutdown+startup'd to
                                            # force a CMIS datapath re-init
            'still_failing': [str],         # 'port: reason' for ports that
                                            # didn't recover after all of
                                            # the above
        }``
    """
    summary = {
        "admin_up_restored": [],
        "lpmode_high_restored": [],
        "datapath_recycled": [],
        "still_failing": [],
    }
    if not port_attributes_dict:
        return summary

    shared_state = {}

    # Pass 1: admin-up everything that's down.
    for port in sorted(port_attributes_dict.keys()):
        if not _is_oper_up(duthost, port):
            logger.info("Restoration: issuing 'config interface startup %s'", port)
            cli_helpers.config_interface_startup(
                duthost, port, namespace=_port_namespace(duthost, port)
            )
            summary["admin_up_restored"].append(port)

    # Pass 2: turn off low-power mode on anything still in LPMode.
    for port in sorted(port_attributes_dict.keys()):
        if not _is_lpmode_high(duthost, port):
            logger.info("Restoration: turning off LPMode on %s", port)
            duthost.shell(f"sudo sfputil lpmode off {port}", module_ignore_errors=True)
            summary["lpmode_high_restored"].append(port)

    # Pass 3: for CMIS active-optical ports, recycle the datapath if still
    # not DPActivated.
    for port in sorted(port_attributes_dict.keys()):
        eeprom_attrs = port_attributes_dict[port].get(EEPROM_ATTRIBUTES_KEY, {})
        if not eeprom_attrs.get("cmis_active_optical"):
            continue
        # Bust the cache so we re-read after the above admin/LPMode actions.
        shared_state.pop("transceiver_status", None)
        cmis_result = _check_cmis_state(duthost, port, shared_state)
        if not cmis_result["passed"]:
            logger.info("Restoration: recycling datapath on %s (shutdown+startup)", port)
            namespace = _port_namespace(duthost, port)
            cli_helpers.config_interface_shutdown(duthost, port, namespace=namespace)
            cli_helpers.config_interface_startup(duthost, port, namespace=namespace)
            summary["datapath_recycled"].append(port)

    # Final pass: who is still not recovered?
    final_link = check_links_up(duthost, port_attributes_dict)
    if not final_link["passed"]:
        summary["still_failing"].extend(final_link["down"])

    return summary
