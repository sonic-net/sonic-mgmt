import logging
import pytest

from tests.common.helpers.dut_utils import (
    get_dpu_names_and_ssh_ports,
    enable_nat_for_dpus,
)
from tests.conftest import get_specified_dpus


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]


def test_enable_nat_for_dpus(duthosts, ansible_adhoc, request):
    """Unconditionally enable NAT/iptables rules for DPU SSH access."""
    dpuhost_names = get_specified_dpus(request)
    if not dpuhost_names:
        logger.info("No DPU hosts specified, skipping NAT setup")
        return

    for duthost in duthosts:
        dpu_name_ssh_port_dict = get_dpu_names_and_ssh_ports(
            duthost, dpuhost_names, ansible_adhoc
        )
        logger.info(
            f"Enabling NAT for {duthost.hostname} with ports: {dpu_name_ssh_port_dict}"
        )
        enable_nat_for_dpus(duthost, dpu_name_ssh_port_dict, request)
