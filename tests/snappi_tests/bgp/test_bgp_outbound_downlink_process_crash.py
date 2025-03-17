import pytest
import logging
from tests.common.helpers.assertions import pytest_require                                          # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts_multidut                                                                    # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api, multidut_snappi_ports_for_bgp                                                      # noqa: F401
from tests.snappi_tests.variables import t1_t2_device_hostnames, t1_snappi_ports                    # noqa: F401
from tests.snappi_tests.bgp.files.bgp_outbound_helper import (
     get_hw_platform, run_bgp_outbound_process_restart_test)                                        # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams                           # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

ITERATION = 1
ROUTE_RANGES = [{
                    'IPv4': [
                        ['100.1.1.1', 24, 500],
                        ['200.1.1.1', 24, 500]
                    ],
                    'IPv6': [
                        ['5000::1', 64, 500],
                        ['4000::1', 64, 500]
                    ],
                },
                {
                    'IPv4': [
                        ['100.1.1.1', 24, 2500],
                        ['200.1.1.1', 24, 2500]
                    ],
                    'IPv6': [
                        ['5000::1', 64, 2500],
                        ['4000::1', 64, 2500]
                    ],
            }]


def test_bgp_outbound_downlink_process_crash(snappi_api,                                     # noqa: F811
                                             multidut_snappi_ports_for_bgp,                       # noqa: F811
                                             conn_graph_facts,                             # noqa: F811
                                             fanout_graph_facts_multidut,                           # noqa: F811
                                             duthosts,                                  # noqa: F811
                                             creds):                                # noqa: F811
    """
    Gets the packet loss duration on killing certain processes in downlink

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        creds (dict): DUT credentials
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "T2 Downlink Process Crash"
    snappi_extra_params.multi_dut_params.process_names = {
                                                            'swss': "/usr/bin/orchagent",
                                                            'syncd': "/usr/bin/syncd",
                                                        }
    ansible_dut_hostnames = []
    for duthost in duthosts:
        ansible_dut_hostnames.append(duthost.hostname)

    hw_platform = get_hw_platform(ansible_dut_hostnames)
    if hw_platform is None:
        pytest_require(False, "Unknown HW Platform")
    logger.info("HW Platform: {}".format(hw_platform))

    for duthost in duthosts:
        if t1_t2_device_hostnames[hw_platform][1] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost1 = duthost
        elif t1_t2_device_hostnames[hw_platform][2] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost2 = duthost
        else:
            continue
    snappi_extra_params.multi_dut_params.t1_hostname = t1_t2_device_hostnames[hw_platform][0]
    snappi_extra_params.multi_dut_params.host_name = t1_t2_device_hostnames[hw_platform][2]
    snappi_extra_params.multi_dut_params.multi_dut_ports = list(multidut_snappi_ports_for_bgp)
    snappi_extra_params.multi_dut_params.multi_dut_ports.extend(t1_snappi_ports[hw_platform])
    snappi_extra_params.multi_dut_params.hw_platform = hw_platform
    run_bgp_outbound_process_restart_test(api=snappi_api,
                                          creds=creds,
                                          snappi_extra_params=snappi_extra_params)
