import pytest
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                            # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts_multidut                                                                     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api, multidut_snappi_ports_for_bgp                                                       # noqa: F401
from tests.snappi_tests.variables import t1_t2_device_hostnames                        # noqa: F401
from tests.snappi_tests.multidut.bgp.files.bgp_outbound_helper import (
     run_bgp_outbound_link_flap_test)                                                               # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams                           # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

FLAP_DETAILS = {
        'device_name': 'Ixia',
        'port_name': 'Snappi_Uplink_PO_1_Link_1'
    }

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


def test_bgp_outbound_uplink_po_flap(snappi_api,                                     # noqa: F811
                                     multidut_snappi_ports_for_bgp,                       # noqa: F811
                                     conn_graph_facts,                             # noqa: F811
                                     fanout_graph_facts_multidut,                   # noqa: F811
                                     duthosts,
                                     creds):
    """
    Gets the packet loss duration on flapping portchannel in uplink side

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        creds (pytest fixture): DUT credentials
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "T2 Uplink Portchannel Flap"
    snappi_extra_params.multi_dut_params.flap_details = FLAP_DETAILS

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
            continue

    snappi_extra_params.multi_dut_params.multi_dut_ports = multidut_snappi_ports_for_bgp
    run_bgp_outbound_link_flap_test(api=snappi_api,
                                    creds=creds,
                                    snappi_extra_params=snappi_extra_params)
