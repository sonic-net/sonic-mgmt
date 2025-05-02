"""
This module contains the snappi fixture in the snappi_tests directory.
"""
from tests.common.snappi_tests.ixload.snappi_helper import main
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
    import pdb; pdb.set_trace()
    snappi_ixl_params = {}

    chassis_ip = tbinfo['chassis_ip']
    gw_ip = tbinfo['ixl_gateway']

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

    api, config, initial_cps_value = main(connection_dict, test_type_dict['cps'],
                                          test_type_dict['test_filename'], test_type_dict['initial_cps_obj'],)

    ixl_cfg = {}
    ixl_cfg['test_type_dict'] = test_type_dict
    ixl_cfg['connection_dict'] = connection_dict

    ixl_cfg['api'] = api
    ixl_cfg['config'] = config
    ixl_cfg['initial_cps_value'] = initial_cps_value

    return ixl_cfg
