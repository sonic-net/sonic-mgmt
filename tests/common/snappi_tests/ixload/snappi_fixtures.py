"""
This module contains the snappi fixture in the snappi_tests directory.
"""
import pytest
import time
import logging
import snappi
import sys
import random
import snappi_convergence
import pdb

from tests.common.helpers.assertions import pytest_require
from ipaddress import ip_address, IPv4Address, IPv6Address
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.common_helpers import get_addrs_in_subnet, get_peer_snappi_chassis, \
    get_ipv6_addrs_in_subnet
from tests.common.snappi_tests.snappi_helpers import SnappiFanoutManager, get_snappi_port_location
from tests.common.snappi_tests.port import SnappiPortConfig, SnappiPortType
from tests.common.helpers.assertions import pytest_assert
from tests.snappi_tests.variables import dut_ip_start, snappi_ip_start, prefix_length, \
    dut_ipv6_start, snappi_ipv6_start, v6_prefix_length, pfcQueueGroupSize, \
    pfcQueueValueDict          # noqa: F401


logger = logging.getLogger(__name__)




@pytest.fixture(scope="module")
def snappi_api_serv_ip(tbinfo):
    """
    In a Snappi testbed, there is no PTF docker.
    Hence, we use ptf_ip field to store snappi API server.
    This fixture returns the IP address of the snappi API server.
    Args:
       tbinfo (pytest fixture): fixture provides information about testbed
    Returns:
        snappi API server IP
    """
    return tbinfo['ptf_ip']


@pytest.fixture(scope="module")
def snappi_api_serv_port(duthosts, rand_one_dut_hostname):
    """
    This fixture returns the TCP Port of the Snappi API server.
    Args:
        duthost (pytest fixture): The duthost fixture.
    Returns:
        snappi API server port.
    """
    duthost = duthosts[rand_one_dut_hostname]
    print(100*'1')
    import pprint
    pprint.pprint(duthost.host.options['variable_manager']._hostvars)
    print(100*'2')
    return (duthost.host.options['variable_manager'].
            _hostvars[duthost.hostname]['snappi_ixl_server']['rest_port'])


@pytest.fixture(scope="module")
def snappi_ixl_serv_start(duthosts, rand_one_dut_hostname):
    """
    This fixture returns the TCP Port of the Snappi API server.
    Args:
        duthost (pytest fixture): The duthost fixture.
    Returns:
        snappi API server port.
    """
    duthost = duthosts[rand_one_dut_hostname]
    print(100*'1')
    import pprint
    pprint.pprint(duthost.host.options['variable_manager']._hostvars)
    print(100*'2')
    return (duthost.host.options['variable_manager'].
            _hostvars[duthost.hostname]['snappi_ixl_server']['rest_port'])

@pytest.fixture(autouse=True, scope="module")
def config_snappi_ixl(request, duthosts, tbinfo):
    """
    Fixture configures UHD connect

    Args:
        request (object): pytest request object, duthost, tbinfo

    Yields:
    """

    snappi_ixl_params = {}

    chassis_ip = tbinfo['chassis_ip']
    gw_ip = tbinfo['gw_ip']

    test_filename = "dash_cps"
    initial_cps_obj = 1000000

    test_type_dict = {
        'cps': 'cps', 'tcpbg': 'tcpbg', 'all': 'all',
        'test_filename': test_filename, 'initial_cps_obj': initial_cps_obj
    }

    connection_dict = {
        'chassis_ip': chassis_ip,
        'gw_ip': gw_ip,
        'port': '8080',
    }

    snappi_ixl_params['test_type_dict'] = test_type_dict
    snappi_ixl_params['connection_dict'] = connection_dict

    return snappi_ixl_params
