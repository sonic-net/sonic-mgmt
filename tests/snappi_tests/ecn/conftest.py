from tests.snappi_tests.ecn.ecn_args.ecn_args import add_ecn_args    # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut                                      # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, snappi_port_selection, tgen_port_info, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config  # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list, disable_pfcwd                                # noqa: F401
from tests.snappi_tests.files.helper import enable_debug_shell       # noqa: F401
from tests.common.reboot import reboot                               # noqa: F401
from tests.common.utilities import wait_until                        # noqa: F401
from tests.common.snappi_tests.common_helpers import pfc_class_enable_vector, config_wred, \
    enable_ecn, config_ingress_lossless_buffer_alpha, stop_pfcwd, disable_packet_aging,\
    config_capture_pkt, traffic_flow_mode, calc_pfc_pause_flow_rate, get_all_port_stats  # noqa: F401
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config, generate_test_flows, \
    generate_pause_flows, run_traffic                                # noqa: F401


def pytest_addoption(parser):
    '''
    Add option to ECN pytest
    Args:
        parser: pytest parser object
    Returns:
        None
    '''
    add_ecn_args(parser)
