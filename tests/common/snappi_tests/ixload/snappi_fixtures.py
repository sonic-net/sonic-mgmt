"""
This module contains the snappi fixture in the snappi_tests directory.
"""
from tests.common.snappi_tests.ixload.snappi_helper import main  # noqa F401
from tests.common.snappi_tests.uhd.uhd_helpers import NetworkConfigSettings  # noqa: F403, F401
import pytest
import logging

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
    logger.info(duthost.host.options['variable_manager']._hostvars)
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
    logger.info(100*'1')
    logger.info(duthost.host.options['variable_manager']._hostvars)
    logger.info(100*'2')
    return (duthost.host.options['variable_manager'].
            _hostvars[duthost.hostname]['snappi_ixl_server']['rest_port'])


@pytest.fixture(autouse=True, scope="module")
def config_snappi_l47(request, duthosts, tbinfo):
    """
    Fixture configures UHD connect

    Args:
        request (object): pytest request object, duthost, tbinfo

    Yields:
    """
    snappi_l47_params = {}

    service_type = tbinfo['service_type']
    l47_version = tbinfo['l47_version']
    chassis_ip = tbinfo['chassis_ip']
    gw_ip = tbinfo['l47_gateway']
    test_filename = "dash_cps"
    initial_cps_obj = 1000000

    test_type_dict = {
        'cps': 'cps', 'tcpbg': 'tcpbg', 'all': 'all',
        'test_filename': test_filename, 'initial_cps_obj': initial_cps_obj
    }

    ports_list = {
        'Traffic1@Network1': [(1, 1, 1)],
        'Traffic2@Network2': [(1, 1, 2)]
    }

    connection_dict = {
        'chassis_ip': chassis_ip,
        'gw_ip': gw_ip,
        'port': '8080',
        'version': l47_version,
    }

    nw_config = NetworkConfigSettings()

    api, config, initial_cps_value = main(ports_list, connection_dict, nw_config, service_type,
                                          test_type_dict['cps'], test_type_dict['initial_cps_obj'])

    snappi_l47_params['test_type_dict'] = test_type_dict
    snappi_l47_params['connection_dict'] = connection_dict
    snappi_l47_params['ports_list'] = ports_list
    snappi_l47_params['api'] = api
    snappi_l47_params['config'] = config
    snappi_l47_params['initial_cps_value'] = initial_cps_value
    snappi_l47_params['nw_config'] = nw_config
    snappi_l47_params['service_type'] = service_type

    return snappi_l47_params
