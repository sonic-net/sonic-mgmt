"""
This module contains the snappi fixture in the snappi_tests directory.
"""
from tests.common.snappi_tests.ixload.snappi_helper import (l47_trafficgen_main, duthost_ha_config,
                                                            npu_startup, dpu_startup, set_static_routes, set_ha_roles,
                                                            set_ha_admin_up, set_ha_activate_role, duthost_port_config)
from tests.common.snappi_tests.uhd.uhd_helpers import NetworkConfigSettings  # noqa: F403, F401
import pytest
import threading
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


def setup_config_snappi_l47(request, duthosts, tbinfo, ha_test_case=None):
    """
    Standalone function for L47 configuration that can be called in threads

    Args:
        request (object): pytest request object
        duthosts: duthosts fixture
        tbinfo: testbed info
        ha_test_case: HA test case name

    Returns:
        dict: snappi L47 parameters
    """
    l47_trafficgen_enabled = request.config.getoption("--l47_trafficgen")
    l47_trafficgen_save = request.config.getoption("--save_l47_trafficgen")
    snappi_l47_params = {}

    if l47_trafficgen_enabled:
        logger.info(f"Configuring L47 parameters for test case: {ha_test_case}")

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
        if ha_test_case != "cps":
            nw_config.ENI_COUNT = 32  # Set to 32 ENIs for HA test cases to test 1 Active/Standby DPU
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


def setup_config_npu_dpu(request, duthosts, localhost, tbinfo, ha_test_case=None):
    """
    Standalone function for NPU/DPU configuration that can be called in threads

    Args:
        request (object): pytest request object
        duthost: DUT host fixture
        localhost: localhost fixture
        tbinfo: testbed info
        ha_test_case: HA test case name

    Returns:
        tuple: (passing_dpus, static_ipsmacs_dict)
    """

    def run_npu_startup(duthosts, duthost, localhost, key):
        npu_dpu_startup_results[key] = npu_startup(duthosts, duthost, localhost)

    def run_dpu_startup(duthosts, duthost, tbinfo, static_ipsmacs_dict, ha_test_case, key):
        dpu_startup_results[key] = dpu_startup(duthosts, duthost, tbinfo, static_ipsmacs_dict, ha_test_case)

    npu_dpu_startup_enabled = request.config.getoption("--npu_dpu_startup")

    passing_dpus = {'dpu1': [], 'dpu2': []}
    static_ipsmacs_dict = {'dpu1': {}, 'dpu2': {}}
    # passing_dpus = []
    # static_ipsmacs_dict = {}

    if npu_dpu_startup_enabled:
        logger.info(f"Running NPU DPU configuration setup for test case: {ha_test_case}")
        nw_config = NetworkConfigSettings()
        nw_config.set_mac_addresses(tbinfo['l47_tg_clientmac'], tbinfo['l47_tg_servermac'], tbinfo['dut_mac'])

        if len(duthosts) > 1:
            # Two DUTs in the testbed
            duthost1 = duthosts[0]
            duthost2 = duthosts[1]

            # Configure SmartSwitch load proper config_db.json
            duthost_portconfig_thread1 = threading.Thread(target=duthost_port_config, args=(duthost1,))
            duthost_portconfig_thread2 = threading.Thread(target=duthost_port_config, args=(duthost2,))

            duthost_portconfig_thread1.start()
            duthost_portconfig_thread2.start()

            duthost_portconfig_thread1.join()
            duthost_portconfig_thread2.join()

            static_ipsmacs_dict1 = duthost_ha_config(duthost1, nw_config)
            static_ipsmacs_dict2 = duthost_ha_config(duthost2, nw_config)

            # Reboot NPUs and check for DPU startup status
            npu_dpu_startup_results = {}
            run_npu_startup_thread1 = threading.Thread(target=run_npu_startup,
                                                       args=(duthosts, duthost1, localhost, 'result1'))
            run_npu_startup_thread2 = threading.Thread(target=run_npu_startup,
                                                       args=(duthosts, duthost2, localhost, 'result2'))

            run_npu_startup_thread1.start()
            run_npu_startup_thread2.start()

            run_npu_startup_thread1.join()
            run_npu_startup_thread2.join()

            # Access results after NPU bootup
            npu_startup_result1 = npu_dpu_startup_results.get('result1')  # noqa: F841
            npu_startup_result2 = npu_dpu_startup_results.get('result2')  # noqa: F841
            # if npu_startup_result is False:
            #    return

            # Create threads with wrapper function for DPU startup
            dpu_startup_results = {}
            dpu_thread1 = threading.Thread(target=run_dpu_startup,
                                           args=(duthosts, duthost1, tbinfo, static_ipsmacs_dict1, ha_test_case, 'dpu1'))  # noqa: E501
            dpu_thread2 = threading.Thread(target=run_dpu_startup,
                                           args=(duthosts, duthost2, tbinfo, static_ipsmacs_dict2, ha_test_case, 'dpu2'))  # noqa: E501

            # Start both DPU threads
            dpu_thread1.start()
            dpu_thread2.start()

            # Wait for both to complete
            dpu_thread1.join()
            dpu_thread2.join()

            # Access DPU startup results
            dpu_result1 = dpu_startup_results.get('dpu1')
            dpu_result2 = dpu_startup_results.get('dpu2')

            # Extract results
            dpu_startup_result1, passing_dpus1 = dpu_result1 if dpu_result1 else (None, [])
            dpu_startup_result2, passing_dpus2 = dpu_result2 if dpu_result2 else (None, [])

            # Store results in nested dictionaries
            passing_dpus['dpu1'] = passing_dpus1
            passing_dpus['dpu2'] = passing_dpus2
            static_ipsmacs_dict['dpu1'] = static_ipsmacs_dict1
            static_ipsmacs_dict['dpu2'] = static_ipsmacs_dict2

            # if dpu_startup_result is False:
            #    return

            logger.info(f"Setting static routes on DUT: {duthost1.hostname}")
            set_static_routes(duthost1, static_ipsmacs_dict1)
            logger.info(f"Setting static routes on DUT: {duthost2.hostname}")
            set_static_routes(duthost2, static_ipsmacs_dict2)

            # HA setup between NPUs
            set_ha_roles(duthosts, duthost1)
            set_ha_roles(duthosts, duthost2)

            set_ha_admin_up(duthosts, duthost1, tbinfo)
            set_ha_admin_up(duthosts, duthost2, tbinfo)

            set_ha_activate_role(duthosts, duthost1)
            set_ha_activate_role(duthosts, duthost2)
        else:
            # Only one DUT in the testbed
            duthost1 = duthosts[0]

            # Configure SmartSwitch
            # duthost_port_config(duthost)

            static_ipsmacs_dict1 = duthost_ha_config(duthost1, nw_config)

            # Run NPU startup directly (no threading needed)
            npu_startup_result1 = npu_startup(duthost1, localhost)  # noqa: F841
            # if npu_startup_result is False:
            #    return

            # Run DPU startup directly (no threading needed)
            dpu_startup_result1, passing_dpus1 = dpu_startup(duthosts, duthost1, static_ipsmacs_dict1, ha_test_case)

            # Store results in nested dictionaries
            passing_dpus['dpu1'] = passing_dpus1
            static_ipsmacs_dict['dpu1'] = static_ipsmacs_dict1

            # if dpu_startup_result is False:
            #    return

            logger.info(f"Setting static routes on DUT: {duthost1.hostname}")
            set_static_routes(duthost1, static_ipsmacs_dict1)
    else:
        logger.info("Skipping NPU DPU configuration setup")

    logger.info("Exiting NPU DPU configuration setup")

    return passing_dpus, static_ipsmacs_dict


@pytest.fixture(scope="module")
def config_snappi_l47(request, duthosts, tbinfo):
    """
    Fixture configures L47 parameters
    """
    return setup_config_snappi_l47(request, duthosts, tbinfo)


@pytest.fixture(scope="module")
def config_npu_dpu(request, duthosts, localhost, tbinfo):
    """
    Fixture configures NPU/DPU
    """
    return setup_config_npu_dpu(request, duthosts, localhost, tbinfo)
