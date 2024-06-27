import logging

import pytest

from tests.bfd.bfd_helpers import ensure_interface_is_up, clear_bfd_configs
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until
from tests.platform_tests.link_flap.link_flap_utils import check_orch_cpu_utilization

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    parser.addoption("--num_sessions", action="store", default=5)
    parser.addoption("--num_sessions_scale", action="store", default=128)


@pytest.fixture(scope='module')
def get_function_completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope="function")
def bfd_cleanup_db(request, duthosts, enum_supervisor_dut_hostname):
    orch_cpu_threshold = 10
    # Make Sure Orch CPU < orch_cpu_threshold before starting test.
    logger.info(
        "Make Sure orchagent CPU utilization is less that %d before starting the test",
        orch_cpu_threshold,
    )
    duts = duthosts.frontend_nodes
    for dut in duts:
        assert wait_until(
            100, 2, 0, check_orch_cpu_utilization, dut, orch_cpu_threshold
        ), "Orch CPU utilization exceeds orch cpu threshold {} before starting the test".format(orch_cpu_threshold)

    yield

    orch_cpu_threshold = 10
    # Orchagent CPU should consume < orch_cpu_threshold at last.
    logger.info(
        "watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold
    )
    for dut in duts:
        assert wait_until(
            120, 4, 0, check_orch_cpu_utilization, dut, orch_cpu_threshold
        ), "Orch CPU utilization exceeds orch cpu threshold {} after finishing the test".format(orch_cpu_threshold)

    logger.info("Verifying swss container status on RP")
    rp = duthosts[enum_supervisor_dut_hostname]
    container_status = True
    if hasattr(request.config, "rp_asic_ids"):
        for id in request.config.rp_asic_ids:
            docker_output = rp.shell(
                "docker ps | grep swss{} | awk '{{print $NF}}'".format(id)
            )["stdout"]
            if len(docker_output) == 0:
                container_status = False
    if not container_status:
        config_reload(rp)

    if hasattr(request.config, "src_dut") and hasattr(request.config, "dst_dut"):
        clear_bfd_configs(request.config.src_dut, request.config.src_asic.asic_index, request.config.src_prefix)
        clear_bfd_configs(request.config.dst_dut, request.config.dst_asic.asic_index, request.config.dst_prefix)
    elif hasattr(request.config, "dut"):
        clear_bfd_configs(request.config.dut, request.config.src_asic.asic_index, request.config.src_prefix)
        clear_bfd_configs(request.config.dut, request.config.dst_asic.asic_index, request.config.dst_prefix)

    logger.info("Bringing up portchannels or respective members")
    portchannels_on_dut = None
    if hasattr(request.config, "portchannels_on_dut"):
        portchannels_on_dut = request.config.portchannels_on_dut
        selected_interfaces = request.config.selected_portchannels
    elif hasattr(request.config, "selected_portchannel_members"):
        portchannels_on_dut = request.config.portchannels_on_dut
        selected_interfaces = request.config.selected_portchannel_members
    else:
        logger.info(
            "None of the portchannels are selected to flap. So skipping portchannel interface check"
        )
        selected_interfaces = []

    if selected_interfaces:
        if portchannels_on_dut == "src":
            dut = request.config.src_dut
        elif portchannels_on_dut == "dst":
            dut = request.config.dst_dut
        else:
            dut = request.config.dut

        if portchannels_on_dut == "src":
            asic = request.config.src_asic
        elif portchannels_on_dut == "dst":
            asic = request.config.dst_asic
        else:
            asic = request.config.asic

        for interface in selected_interfaces:
            ensure_interface_is_up(dut, asic, interface)
