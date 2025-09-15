"""
This module contains the snappi fixture in the snappi_tests directory.
"""
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
    logger.info("Configuring L47 parameters")
    snappi_l47_params = {}

    l47_version = tbinfo['l47_version']

    chassis_ip = tbinfo['chassis_ip']
    gw_ip = tbinfo['l47_gateway']

    ports_list = tbinfo['ports_list']
    ports_list = {k: [tuple(x) for x in v] for k, v in ports_list.items()}

    test_filename = "dash_cps"
    initial_cps_obj = (len(ports_list['Traffic1@Network1']) * 4000000) // 2


    test_type_dict = {
        'cps': 'cps', 'tcpbg': 'tcpbg', 'all': 'all',
        'test_filename': test_filename, 'initial_cps_obj': initial_cps_obj
    }

    connection_dict = {
        'chassis_ip': chassis_ip,
        'gw_ip': gw_ip,
        'port': '8080',
        'version': l47_version,
    }

    snappi_l47_params['test_type_dict'] = test_type_dict
    snappi_l47_params['connection_dict'] = connection_dict
    snappi_l47_params['ports_list'] = ports_list

    return snappi_l47_params
