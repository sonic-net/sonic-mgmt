import logging

import pytest

from tests.bfd.bfd_helpers import ensure_interface_is_up
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until
from tests.platform_tests.link_flap.link_flap_utils import check_orch_cpu_utilization

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    parser.addoption("--num_sessions", action="store", default=5)
    parser.addoption("--num_sessions_scale", action="store", default=128)


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
        ), "Orch CPU utilization {} > orch cpu threshold {} before starting the test".format(
            dut.shell("show processes cpu | grep orchagent | awk '{print $9}'")[
                "stdout"
            ],
            orch_cpu_threshold,
        )

    yield
    orch_cpu_threshold = 10
    # Orchagent CPU should consume < orch_cpu_threshold at last.
    logger.info(
        "watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold
    )
    for dut in duts:
        assert wait_until(
            120, 4, 0, check_orch_cpu_utilization, dut, orch_cpu_threshold
        ), "Orch CPU utilization {} > orch cpu threshold {} after the test".format(
            dut.shell("show processes cpu | grep orchagent | awk '{print $9}'")[
                "stdout"
            ],
            orch_cpu_threshold,
        )

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

    logger.info(
        "Clearing BFD configs on {}, {}".format(
            request.config.src_dut, request.config.dst_dut
        )
    )
    command = (
        "sonic-db-cli -n asic{} CONFIG_DB HSET \"STATIC_ROUTE|{}\" bfd 'false'".format(
            request.config.src_asic.asic_index, request.config.src_prefix
        ).replace("\\", "")
    )
    request.config.src_dut.shell(command)
    command = (
        "sonic-db-cli -n asic{} CONFIG_DB HSET \"STATIC_ROUTE|{}\" bfd 'false'".format(
            request.config.dst_asic.asic_index, request.config.dst_prefix
        ).replace("\\", "")
    )
    request.config.dst_dut.shell(command)

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
        dut = (
            request.config.src_dut
            if portchannels_on_dut == "src"
            else request.config.dst_dut
        )
        asic = (
            request.config.src_asic
            if portchannels_on_dut == "src"
            else request.config.dst_asic
        )
        for interface in selected_interfaces:
            ensure_interface_is_up(dut, asic, interface)
