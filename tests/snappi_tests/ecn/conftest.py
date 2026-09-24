import pytest
import logging
import random
from tabulate import tabulate  # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config, \
    is_snappi_multidut, get_snappi_ports_multi_dut, get_snappi_ports_single_dut   # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list, disable_pfcwd   # noqa: F401
from tests.snappi_tests.files.helper import multidut_port_info, setup_ports_and_dut, enable_debug_shell  # noqa: F401
from tests.snappi_tests.ecn.files.bpfabric_helper import run_fabric_ecn_marking_test, run_backplane_ecn_marking_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.cisco_data import is_cisco_device

from tests.snappi_tests.ecn.ecn_args.ecn_args import add_ecn_args


def pytest_addoption(parser):
    '''
    Add option to ECN pytest
    Args:
        parser: pytest parser object
    Returns:
        None
    '''
    add_ecn_args(parser)
