import logging

import pytest

from tests.bfd.bfd_helpers import clear_bfd_configs, ensure_interfaces_are_up
from tests.common.config_reload import config_reload
# from tests.common.utilities import wait_until
# from tests.platform_tests.link_flap.link_flap_utils import check_orch_cpu_utilization

logger = logging.getLogger(__name__)


class BfdCleanupContext(object):
    def __init__(self):
        self.src_dut = None
        self.src_asic = None
        self.src_prefix = None
        self.dst_dut = None
        self.dst_asic = None
        self.dst_prefix = None
        self.rp_asic_ids = []
        self.allow_empty_static_routes_on_removal = False
        self.restore_targets = []

    def set_bfd_endpoints(self, selection):
        self.src_dut = selection.get("src_dut")
        self.src_asic = selection.get("src_asic")
        self.src_prefix = selection.get("src_prefix")
        self.dst_dut = selection.get("dst_dut")
        self.dst_asic = selection.get("dst_asic")
        self.dst_prefix = selection.get("dst_prefix")

    def register_restore(self, dut, asic, interfaces):
        if not interfaces:
            return

        self.restore_targets.append(
            {
                "dut": dut,
                "asic": asic,
                "interfaces": list(interfaces),
            }
        )


def pytest_addoption(parser):
    parser.addoption("--num_sessions", action="store", default=5)
    parser.addoption("--num_sessions_scale", action="store", default=128)


@pytest.fixture(scope='module')
def get_function_completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope="function")
def bfd_cleanup_db(duthosts, enum_supervisor_dut_hostname):
    # Temporarily disable orchagent CPU check before starting test as it is not stable
    # orch_cpu_threshold = 10
    # # Make Sure Orch CPU < orch_cpu_threshold before starting test.
    # logger.info(
    #     "Make Sure orchagent CPU utilization is less that %d before starting the test",
    #     orch_cpu_threshold,
    # )
    # duts = duthosts.frontend_nodes
    # for dut in duts:
    #     assert wait_until(
    #         100, 2, 0, check_orch_cpu_utilization, dut, orch_cpu_threshold
    #     ), "Orch CPU utilization exceeds orch cpu threshold {} before starting the test".format(orch_cpu_threshold)

    cleanup_context = BfdCleanupContext()
    yield cleanup_context

    # Temporarily disable orchagent CPU check after finishing test as it is not stable
    # orch_cpu_threshold = 10
    # # Orchagent CPU should consume < orch_cpu_threshold at last.
    # logger.info(
    #     "watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold
    # )
    # for dut in duts:
    #     assert wait_until(
    #         120, 4, 0, check_orch_cpu_utilization, dut, orch_cpu_threshold
    #     ), "Orch CPU utilization exceeds orch cpu threshold {} after finishing the test".format(orch_cpu_threshold)

    rp = duthosts[enum_supervisor_dut_hostname]
    container_status = True
    if cleanup_context.rp_asic_ids:
        logger.info("Verifying swss container status on RP")
        for asic_id in cleanup_context.rp_asic_ids:
            docker_output = rp.shell(
                "docker ps | grep swss{} | awk '{{print $NF}}'".format(asic_id)
            )["stdout"]
            if len(docker_output) == 0:
                container_status = False

    if not container_status:
        logger.error("swss container is not running on RP, so running config reload")
        config_reload(rp, safe_reload=True)

    if cleanup_context.src_dut and cleanup_context.dst_dut:
        clear_bfd_configs(
            cleanup_context.src_dut,
            cleanup_context.src_asic.asic_index,
            cleanup_context.src_prefix,
        )
        clear_bfd_configs(
            cleanup_context.dst_dut,
            cleanup_context.dst_asic.asic_index,
            cleanup_context.dst_prefix,
        )

    if cleanup_context.restore_targets:
        logger.info("Bringing up registered interfaces")
        for restore_target in cleanup_context.restore_targets:
            ensure_interfaces_are_up(
                restore_target["dut"],
                restore_target["asic"],
                restore_target["interfaces"],
            )
    else:
        logger.info(
            "No interfaces were registered for cleanup. So skipping interface check"
        )
