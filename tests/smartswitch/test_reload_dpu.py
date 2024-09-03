"""
Tests for the `reboot and reload ...` commands in DPU 
"""

import logging
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts     
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot,wait_for_startup,REBOOT_TYPE_COLD
from tests.common.config_reload import config_force_option_supported, config_system_checks_passed
from tests.common.platform.device_utils_dpu import *
from tests.common.helpers.platform_api import chassis, module
from tests.platform_tests.api.conftest import platform_api_conn

pytestmark = [
    pytest.mark.topology('t1')
]


def test_dpu_ping_after_reboot(duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
    """
    @summary: Verify output of `config chassis modules startup <DPU_Number>`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ip_address_list = []
    dpu_powered_on_list = []
    num_modules = int(chassis.get_num_modules(platform_api_conn))
    output_dpu_status = duthost.show_and_parse('show chassis module status')

    for index in range(len(output_dpu_status)):
        parse_output = output_dpu_status[index]
        if parse_output['oper-status'] != 'Offline':
            dpu_powered_on_list.append(parse_output['name'])

    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD, wait_for_ssh=False)
    wait_for_startup(duthost, localhost, 10, 300)
    pytest_assert(wait_until(300, 5, 0, check_interface_status_of_up_ports, duthost),
                          "Not all ports that are admin up on are operationally up")
    logging.info("Interfaces are up")

    for DPU in dpu_powered_on_list:
        dpu = module.get_name(platform_api_conn, DPU[3:])
        ip_address_list.append(module.get_midplane_ip(platform_api_conn, DPU[3:]))
        duthosts.shell("config chassis modules startup %s"%DPU)
        time.sleep(2)

    pytest_assert(wait_until(120, 30, 0, check_dpu_ping_status, duthost, ip_address_list),
                          "Not all DPUs operationally up")


def test_show_ping_int_after_reload(duthosts, enum_rand_one_per_hwsku_hostname, localhost, platform_api_conn):
    """
    @summary: Verify the ping output of `interface status after reload`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    num_modules = int(chassis.get_num_modules(platform_api_conn))
    ip_address_list = []

    for index in range(num_modules):
        dpu = module.get_name(platform_api_conn, index)
        ip_address_list.append(module.get_midplane_ip(platform_api_conn, index))
        duthosts.shell("config chassis modules startup %s"%dpu)
        time.sleep(2)

    pytest_assert(wait_until(120, 30, 0, check_dpu_ping_status, duthost, ip_address_list),
                          "Not all DPUs operationally up")

    logging.info("Reload configuration")
    duthost.shell("sudo config reload -y &>/dev/null", executable="/bin/bash")

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(duthost)

    pytest_assert(wait_until(30, 10, 0, check_dpu_ping_status, duthost, ip_address_list),
                          "Not all DPUs operationally up")
