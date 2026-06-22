"""
This module contains gNOI tests specific to SmartSwitch/DPU platforms.
"""
import logging

import pytest

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    gnmi_tls, ptf_grpc, ptf_gnoi, setup_gnoi_tls_server
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.ptf_gnoi import PtfGnoi
from tests.common.utilities import wait_until
from tests.conftest import get_specified_dpus
from tests.common.platform.device_utils import reboot_dpu_and_wait_for_start_up


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnoi_tls_server"),
]


REBOOT_MESSAGE = "gnoi test reboot"

# How long to wait for a DPU's gNOI server to answer System.Time after a reboot.
DPU_REBOOT_READY_TIMEOUT = 600


def get_npu_duthost(duthosts):
    """
    Return the NPU (non-DPU) host on a SmartSwitch testbed.

    ``duthosts`` can include the individual DPU SONiC instances in addition to
    the NPU. The NPU runs the gNOI server that handles/forwards DPU-targeted RPCs
    and performs the DPU bring-up, so it must be selected explicitly rather than
    picked at random.
    """
    npu_duthost = next(
        (dut for dut in duthosts
         if not dut.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_dpu")),
        None)
    pytest_assert(npu_duthost is not None, "No NPU (non-DPU) host found in duthosts")
    return npu_duthost


def _dpu_gnoi_time_ok(dpu_gnoi):
    """Return True iff the DPU's gNOI server answers System.Time."""
    try:
        dpu_gnoi.system_time()
        return True
    except Exception as exc:
        logging.debug("DPU gNOI System.Time not ready yet: %s", exc)
        return False


def test_gnoi_system_reboot_halt_dpus(duthosts, ptfhost, request, ptf_gnoi):  # noqa: F811
    """
    Test gNOI System.Reboot (HALT) for SmartSwitch DPUs.

    For each specified DPU, route a gNOI System.Reboot to the DPU through the
    NPU's gNOI server (SmartSwitch DPU routing headers), bring the DPU back up
    from the NPU, and verify recovery by polling the DPU's gNOI System.Time.
    """
    npu_duthost = get_npu_duthost(duthosts)

    dpuhost_names = get_specified_dpus(request)
    if not dpuhost_names:
        pytest.skip("No DPUs specified (-H/--dpu-pattern), skipping HALT reboot test.")
    logging.info("dpuhost_names: %s", dpuhost_names)

    for dpuhost_name in dpuhost_names:
        # The DPU index is the trailing number of the DPU host name.
        dpu_index = int(dpuhost_name.split('-')[-1])
        pytest_assert(0 <= dpu_index <= 8,
                      "Invalid dpu_index {}, must be between 0 and 8".format(dpu_index))

        # gNOI client that routes RPCs to this DPU through the NPU gNOI server.
        dpu_gnoi = PtfGnoi(ptf_gnoi.grpc_client.with_ss_target("dpu", dpu_index))

        # Sanity: the DPU's gNOI server is reachable before we reboot it.
        pytest_assert(wait_until(60, 5, 0, _dpu_gnoi_time_ok, dpu_gnoi),
                      "DPU {} gNOI server is not reachable before reboot".format(dpu_index))

        # Trigger the HALT reboot. System.Reboot may tear down the channel as the
        # DPU goes down, so a transport error here is expected, not a failure.
        try:
            dpu_gnoi.system_reboot(method="HALT", message=REBOOT_MESSAGE)
            logging.info("System.Reboot(HALT) request sent for DPU %s", dpu_index)
        except Exception as exc:
            logging.info("System.Reboot(HALT) returned a transport error "
                         "(expected as the DPU goes down): %s", exc)

        # Bring the DPU back up from the NPU and wait for midplane reachability.
        pytest_assert(reboot_dpu_and_wait_for_start_up(npu_duthost, dpuhost_name, dpu_index),
                      "DPU {} (index {}) failed to reboot/come back".format(dpuhost_name, dpu_index))

        # Confirm recovery at the gNOI layer: the DPU answers System.Time again.
        pytest_assert(
            wait_until(DPU_REBOOT_READY_TIMEOUT, 10, 0, _dpu_gnoi_time_ok, dpu_gnoi),
            "DPU {} gNOI server did not come back (System.Time) after reboot".format(dpu_index))

        logging.info("DPU %s (index %s) rebooted and recovered", dpuhost_name, dpu_index)
