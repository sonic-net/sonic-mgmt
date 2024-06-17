import pytest
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                            # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts                                                                              # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     cvg_api, multidut_snappi_ports                                                                 # noqa: F401
from tests.snappi_tests.variables import t1_t2_device_hostnames                                     # noqa: F401
from tests.snappi_tests.multidut.bgp.files.bgp_outbound_helper import (
     run_bgp_outbound)                                                                              # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams                           # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

FLAP_EVENT = {
        'hostname': 'sonic-t1',
        'port_name': 'Ethernet120'
    }
ITERATION = 1
ROUTE_RANGES = [
                    {
                        'IPv4': [
                            ['100.1.1.1', 24, 15000],
                            ['200.1.1.1', 24, 15000]
                        ],
                        'IPv6': [
                            ['5000::1', 124, 1000],
                            ['4000::1', 124, 1000]
                        ],
                    },
                    {
                        'IPv4': [
                            ['100.1.1.1', 24, 1000],
                            ['200.1.1.1', 24, 10000]
                        ],
                        'IPv6': [
                            ['5000::1', 124, 10000],
                            ['4000::1', 124, 10000]
                        ],
                    }
                ]


@pytest.mark.parametrize('traffic_type', ['IPv4'])
@pytest.mark.parametrize('route_range', [ROUTE_RANGES[0]])
def test_bgp_outbound_flap_interconnectivity(cvg_api,                                     # noqa: F811
                                             multidut_snappi_ports,                       # noqa: F811
                                             conn_graph_facts,                             # noqa: F811
                                             fanout_graph_facts,                           # noqa: F811
                                             duthosts,
                                             traffic_type,                                 # noqa: F811
                                             route_range):
    """
    Test if IEEE 802.3X pause (a.k.a., global pause) will impact any priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGE = route_range
    snappi_extra_params.iteration = ITERATION
    # Mention the duthost hostname and the port that needs to be flapped for the test
    snappi_extra_params.multi_dut_params.flap_event = FLAP_EVENT

    if (len(t1_t2_device_hostnames) < 3) or (len(duthosts) < 3):
        pytest_assert(False, "Need minimum of 3 devices : One T1 and Two T2 line cards")

    ansible_dut_hostnames = []
    for duthost in duthosts:
        ansible_dut_hostnames.append(duthost.hostname)

    for device_hostname in t1_t2_device_hostnames:
        if device_hostname not in ansible_dut_hostnames:
            logger.info('!!!!! Attention: {} not in : {} derived from ansible dut hostnames'.
                        format(device_hostname, ansible_dut_hostnames))
            pytest_assert(False, "Mismatch between the dut hostnames in ansible and in variables.py files")

    for duthost in duthosts:
        if t1_t2_device_hostnames[0] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost1 = duthost
        elif t1_t2_device_hostnames[1] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost2 = duthost
        elif t1_t2_device_hostnames[2] in duthost.hostname:
            snappi_extra_params.multi_dut_params.duthost3 = duthost
        else:
            pytest_assert(False, "t1 or Uplink or downlink prefix is not found")

    dut1_snappi_ports = multidut_snappi_ports(snappi_extra_params.multi_dut_params.duthost1)
    dut2_snappi_ports = multidut_snappi_ports(snappi_extra_params.multi_dut_params.duthost2)
    snappi_extra_params.multi_dut_params.multi_dut_ports = dut1_snappi_ports
    for port in dut2_snappi_ports:
        snappi_extra_params.multi_dut_params.multi_dut_ports.append(port)

    run_bgp_outbound(cvg_api=cvg_api,
                     traffic_type=traffic_type,
                     service_down=False,
                     snappi_extra_params=snappi_extra_params)
