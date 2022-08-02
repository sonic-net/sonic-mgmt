import time
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.utils import ignore_loganalyzer
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.configlet.util.common import chk_for_pfc_wd
from tests.common.platform.interface_utils import check_interface_status_of_up_ports

logger = logging.getLogger(__name__)

config_sources = ['config_db', 'minigraph']

def config_system_checks_passed(duthost):
    logging.info("Checking if system is running")
    out= duthost.shell("systemctl is-system-running", module_ignore_errors=True)
    if "running" not in out['stdout_lines']:
        logging.info("Checking failure reason")
        fail_reason = duthost.shell("systemctl list-units --state=failed", module_ignore_errors=True)
        logging.info(fail_reason['stdout_lines'])
        return False

    logging.info("Checking if Orchagent up for at least 2 min")
    if duthost.is_multi_asic:
        for asic in duthost.asics:
            out = duthost.shell("systemctl show swss@{}.service --property ActiveState --value".format(asic.asic_index))
            if out["stdout"] != "active":
                return False

            out = duthost.shell(
                "ps -o etimes -p $(systemctl show swss@{}.service --property ExecMainPID --value) | sed '1d'".format(asic.asic_index))
            if int(out['stdout'].strip()) < 120:
                return False
    else:
        out = duthost.shell("systemctl show swss.service --property ActiveState --value")
        if out["stdout"] != "active":
            return False

        out = duthost.shell("ps -o etimes -p $(systemctl show swss.service --property ExecMainPID --value) | sed '1d'")
        if int(out['stdout'].strip()) < 120:
            return False

    logging.info("Checking if delayed services are up")
    out = duthost.shell("systemctl list-dependencies sonic-delayed.target --plain |sed '1d'")
    status = duthost.shell("systemctl is-enabled {}".format(out['stdout'].replace("\n", " ")))
    services = [line.strip() for line in out['stdout'].splitlines()]
    state = [line.strip() for line in status['stdout'].splitlines()]
    for service in services:
        if state[services.index(service)] == "enabled":
            out1 = duthost.shell("systemctl show {} --property=LastTriggerUSecMonotonic --value".format(service))
            if out1['stdout'].strip() == "0":
                return False
    logging.info("All checks passed")
    return True


def config_force_option_supported(duthost):
    out = duthost.shell("config reload -h", executable="/bin/bash")
    if "force" in out['stdout'].strip():
        return True
    return False


@ignore_loganalyzer
def config_reload(duthost, config_source='config_db', wait=120, start_bgp=True, start_dynamic_buffer=True, safe_reload=False,
                  check_intf_up_ports=False, traffic_shift_away=False):
    """
    reload SONiC configuration
    :param duthost: DUT host object
    :param config_source: configuration source either 'config_db' or 'minigraph'
    :param wait: wait timeout for DUT to initialize after configuration reload
    :return:
    """

    if config_source not in config_sources:
        raise ValueError('invalid config source passed in "{}", must be {}'.format(
            config_source,
            ' or '.join(['"{}"'.format(src) for src in config_sources])
        ))

    cmd = 'config reload -y &>/dev/null'
    if config_force_option_supported(duthost):
        cmd = 'config reload -y -f &>/dev/null'

    logger.info('reloading {}'.format(config_source))

    if config_source == 'minigraph':
        if start_dynamic_buffer and duthost.facts['asic_type'] == 'mellanox':
            output = duthost.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model', module_ignore_errors=True)
            is_buffer_model_dynamic = (output and output.get('stdout') == 'dynamic')
        else:
            is_buffer_model_dynamic = False
        if traffic_shift_away:
            duthost.shell('config load_minigraph -y -t &>/dev/null', executable="/bin/bash")
        else:
            duthost.shell('config load_minigraph -y &>/dev/null', executable="/bin/bash")
        time.sleep(60)
        if start_bgp:
            duthost.shell('config bgp startup all')
        if is_buffer_model_dynamic:
            duthost.shell('enable-dynamic-buffer.py')
        duthost.shell('config save -y')

    if config_source == 'config_db':
        duthost.shell(cmd, executable="/bin/bash")

    modular_chassis = duthost.get_facts().get("modular_chassis")
    wait = max(wait, 240) if modular_chassis else wait

    if safe_reload:
        # The wait time passed in might not be guaranteed to cover the actual
        # time it takes for containers to come back up. Therefore, add 5
        # minutes to the maximum wait time. If it's ready sooner, then the
        # function will return sooner.
        pytest_assert(wait_until(wait + 300, 20, 0, duthost.critical_services_fully_started),
                "All critical services should be fully started!")
        wait_critical_processes(duthost)
        if config_source == 'minigraph':
            pytest_assert(wait_until(300, 20, 0, chk_for_pfc_wd, duthost),
                    "PFC_WD is missing in CONFIG-DB")

        if check_intf_up_ports:
            pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
                          "Not all ports that are admin up on are operationally up")
    else:
        time.sleep(wait)
