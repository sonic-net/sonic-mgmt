import pytest

from tests.snappi_tests.ecn.ecn_args.ecn_args import add_ecn_args
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, snappi_port_selection, tgen_port_info, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config  # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list, disable_pfcwd                                # noqa: F401
from tests.snappi_tests.files.helper import enable_debug_shell       # noqa: F401
from tests.snappi_tests.ecn.files.ecn_counterpoll_helpers import (
    disable_wred_ecn_counterpoll_entries,
    enable_wred_ecn_counterpoll_for_snappi_ports,
)


@pytest.fixture(scope="module")
def enable_wred_ecn_counterpoll(get_snappi_ports):  # noqa: F811
    """
    Enable WRED ECN counterpoll for (duthost, ASIC) pairs used by snappi_ports.

    Counter types already enabled are left unchanged. Only counter types enabled
    by this fixture are disabled on teardown.
    """
    enabled_by_us = enable_wred_ecn_counterpoll_for_snappi_ports(get_snappi_ports)
    yield enabled_by_us
    disable_wred_ecn_counterpoll_entries(enabled_by_us)


def pytest_addoption(parser):
    '''
    Add option to ECN pytest
    Args:
        parser: pytest parser object
    Returns:
        None
    '''
    add_ecn_args(parser)
