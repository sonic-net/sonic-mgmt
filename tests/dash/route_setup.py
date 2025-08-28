"""
Fixtures to setup/teardown static routes on NPU and DPU needed to run tests
"""

import logging
import pytest

from tests.dash.conftest import get_interface_ip
import configs.privatelink_config as pl
from tests.dash.constants import LOCAL_DUT_INTF, REMOTE_DUT_INTF
logger = logging.getLogger(__name__)


@pytest.fixture(scope="function", autouse=True)
def dpu_setup(dpuhosts, dpu_index, skip_config):
    if skip_config:

        return
    dpuhost = dpuhosts[dpu_index]
    intfs = dpuhost.shell("show ip int")["stdout"]
    dpu_cmds = list()
    if "Loopback0" not in intfs:
        dpu_cmds.append("config loopback add Loopback0")
        dpu_cmds.append(f"config int ip add Loopback0 {pl.APPLIANCE_VIP}/32")

    # explicitly add mgmt IP route so the default route doesn't disrupt SSH access
    dpu_cmds.append(
        'who am i | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | xargs -I{} sudo ip route replace {}/32 via 169.254.200.254'  # noqa W605
    )
    dpu_cmds.append(f"ip route replace default via {dpuhost.npu_data_port_ip}")
    dpuhost.shell_cmds(cmds=dpu_cmds)


@pytest.fixture(scope="function", autouse=True)
def add_npu_static_routes(
    duthost, dash_pl_config, skip_config, skip_cleanup, dpu_index, dpuhosts, dpu_setup
):
    dpuhost = dpuhosts[dpu_index]
    if not skip_config:
        cmds = []
        vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[LOCAL_DUT_INTF]).ip + 1
        pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[REMOTE_DUT_INTF]).ip + 1

        cmds.append(f"config route add prefix {pl.APPLIANCE_VIP}/32 nexthop {dpuhost.dpu_data_port_ip}")
        cmds.append(f"ip route replace {pl.VM1_PA}/32 via {vm_nexthop_ip}")

        return_tunnel_endpoints = pl.TUNNEL1_ENDPOINT_IPS + pl.TUNNEL2_ENDPOINT_IPS
        for tunnel_ip in return_tunnel_endpoints:
            cmds.append(f"ip route replace {tunnel_ip}/32 via {vm_nexthop_ip}")
        nsg_tunnel_endpoints = pl.TUNNEL3_ENDPOINT_IPS + pl.TUNNEL4_ENDPOINT_IPS
        for tunnel_ip in nsg_tunnel_endpoints:
            cmds.append(f"ip route replace {tunnel_ip}/32 via {pe_nexthop_ip}")

        cmds.append(f"ip route replace {pl.PE_PA}/32 via {pe_nexthop_ip}")
        logger.info(f"Adding static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        cmds = []
        cmds.append(f"ip route del {pl.APPLIANCE_VIP}/32 via {dpuhost.dpu_data_port_ip}")
        cmds.append(f"ip route del {pl.VM1_PA}/32 via {vm_nexthop_ip}")
        for tunnel_ip in return_tunnel_endpoints:
            cmds.append(f"ip route replace {tunnel_ip}/32 via {vm_nexthop_ip}")
        cmds.append(f"ip route del {pl.PE_PA}/32 via {pe_nexthop_ip}")
        logger.info(f"Removing static routes: {cmds}")
        duthost.shell_cmds(cmds=cmds)
