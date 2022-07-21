"""
Check platform status after config is reloaded

This script is to cover the test case 'Reload configuration' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging

import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.transceiver_utils import check_transceiver_basic
from tests.common.platform.interface_utils import check_all_interface_information, get_port_map
from tests.common.reboot import reboot
from tests.common.config_reload import config_force_option_supported, config_system_checks_passed

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

def test_reload_configuration(duthosts, rand_one_dut_hostname, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to reload the configuration and check platform status
    """
    duthost = duthosts[rand_one_dut_hostname]
    interfaces = conn_graph_facts["device_conn"][duthost.hostname]
    asic_type = duthost.facts["asic_type"]

    if config_force_option_supported(duthost):
        assert wait_until(300, 20, 0, config_system_checks_passed, duthost)

    logging.info("Reload configuration")
    duthost.shell("sudo config reload -y &>/dev/null", executable="/bin/bash")

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(duthost)

    logging.info("Wait some time for all the transceivers to be detected")
    assert wait_until(300, 20, 0, check_all_interface_information, duthost, interfaces, xcvr_skip_list), \
        "Not all transceivers are detected in 300 seconds"

    logging.info("Check transceiver status")
    for asic_index in duthost.get_frontend_asic_ids():
        # Get the interfaces pertaining to that asic
        interface_list = get_port_map(duthost, asic_index)
        interfaces_per_asic = {k:v for k, v in interface_list.items() if k in interfaces}
        check_transceiver_basic(duthost, asic_index, interfaces_per_asic, xcvr_skip_list)

    if asic_type in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(duthost)

        logging.info("Check sysfs")
        check_sysfs(duthost)


def check_database_status(duthost):
    # check global database docker is running
    if not duthost.is_service_fully_started('database'):
        return False

    # For multi-asic check each asics database
    if duthost.is_multi_asic:
        for asic in duthost.asics:
            if not duthost.is_service_fully_started('database{}'.format(asic.asic_index)):
                return False

    return True

def test_reload_configuration_checks(duthosts, rand_one_dut_hostname, localhost, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to test various system checks in config reload
    """
    duthost = duthosts[rand_one_dut_hostname]

    if not config_force_option_supported(duthost):
        return

    reboot(duthost, localhost, reboot_type="cold", wait=5)

    # Check if all database containers have started
    wait_until(60, 1, 0, check_database_status, duthost)

    logging.info("Reload configuration check")
    out = duthost.shell("sudo config reload -y", executable="/bin/bash", module_ignore_errors=True)
    # config reload command shouldn't work immediately after system reboot
    assert "Retry later" in out['stdout']

    assert wait_until(300, 20, 0, config_system_checks_passed, duthost)

    # After the system checks succeed the config reload command should not throw error
    out = duthost.shell("sudo config reload -y", executable="/bin/bash", module_ignore_errors=True)
    assert "Retry later" not in out['stdout']

    # Immediately after one config reload command, another shouldn't execute and wait for system checks
    logging.info("Checking config reload after system is up")
    out = duthost.shell("sudo config reload -y", executable="/bin/bash", module_ignore_errors=True)
    assert "Retry later" in out['stdout']
    assert wait_until(300, 20, 0, config_system_checks_passed, duthost)

    logging.info("Stopping swss docker and checking config reload")
    if duthost.is_multi_asic:
        for asic in duthost.asics:
            duthost.shell("sudo service swss@{} stop".format(asic.asic_index))
    else:
        duthost.shell("sudo service swss stop")

    # Without swss running config reload option should not proceed
    out = duthost.shell("sudo config reload -y", executable="/bin/bash", module_ignore_errors=True)
    assert "Retry later" in out['stdout']

    # However with force option config reload should proceed
    logging.info("Performing force config reload")
    out = duthost.shell("sudo config reload -y -f", executable="/bin/bash")
    assert "Retry later" not in out['stdout']

    assert wait_until(300, 20, 0, config_system_checks_passed, duthost)
