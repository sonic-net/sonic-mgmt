"""
This module contains the snappi fixture in the snappi_tests directory.
"""
from tests.common.snappi_tests.ixload.snappi_helper import (l47_trafficgen_main, duthost_ha_config,
                                                            npu_startup, dpu_startup, set_static_routes)
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


@pytest.fixture(scope="module")
def config_snappi_l47(request, duthosts, tbinfo):
    """
    Fixture configures UHD connect

    Args:
        request (object): pytest request object, duthost, tbinfo

    Yields:
    """
    l47_trafficgen_enabled = request.config.getoption("--l47_trafficgen")
    l47_trafficgen_save = request.config.getoption("--save_l47_trafficgen")
    snappi_l47_params = {}

    if l47_trafficgen_enabled:
        logger.info("Configuring L47 parameters")

        l47_version = tbinfo['l47_version']
        service_type = tbinfo['service_type']
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

        nw_config = NetworkConfigSettings()
        api, config, initial_cps_value = l47_trafficgen_main(ports_list, connection_dict, nw_config, service_type,
                                                             test_type_dict['all'], test_type_dict['initial_cps_obj'])

        if l47_trafficgen_save:
            snappi_l47_params['save'] = True

        snappi_l47_params['config_build'] = True
        snappi_l47_params['test_type_dict'] = test_type_dict
        snappi_l47_params['connection_dict'] = connection_dict
        snappi_l47_params['ports_list'] = ports_list
        snappi_l47_params['api'] = api
        snappi_l47_params['config'] = config
        snappi_l47_params['initial_cps_value'] = initial_cps_value
        snappi_l47_params['nw_config'] = nw_config
        snappi_l47_params['service_type'] = service_type
    else:
        snappi_l47_params['config_build'] = False
        logger.info("Skipping L47 parameters configuration")

    return snappi_l47_params


@pytest.fixture(scope="module")
def config_npu_dpu(request, duthost, localhost, tbinfo):
    """
    Fixture configures UHD connect

    Args:
        request (object): pytest request object, duthost, tbinfo

    Yields:
    """
    npu_dpu_startup_enabled = request.config.getoption("--npu_dpu_startup")
    passing_dpus = []

    if npu_dpu_startup_enabled:
        logger.info("Running NPU DPU configuration setup")
        nw_config = NetworkConfigSettings()  # noqa: F405
        nw_config.set_mac_addresses(tbinfo['l47_tg_clientmac'], tbinfo['l47_tg_servermac'], tbinfo['dut_mac'])

        # Configure SmartSwitch
        # duthost_port_config(duthost)

        static_ipsmacs_dict = duthost_ha_config(duthost, nw_config)

        npu_startup_result = npu_startup(duthost, localhost)  # noqa: F841
        # if npu_startup_result is False:
        #    return

        dpu_startup_result, passing_dpus = dpu_startup(duthost, static_ipsmacs_dict)
        # if dpu_startup_result is False:
        #    return

        set_static_routes(duthost, static_ipsmacs_dict)
    else:
        logger.info("Skipping NPU DPU configuration setup")

    return passing_dpus
