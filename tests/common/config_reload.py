import time
import logging
import os

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.utils import ignore_loganalyzer
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.configlet.util.common import chk_for_pfc_wd
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.helpers.dut_utils import ignore_t2_syslog_msgs

logger = logging.getLogger(__name__)

config_sources = ['config_db', 'minigraph', 'running_golden_config']

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
GOLDEN_CONFIG_TEMPLATE = os.path.join(TEMPLATE_DIR, 'golden_config_db.j2')
DEFAULT_GOLDEN_CONFIG_PATH = '/etc/sonic/golden_config_db.json'


def config_system_checks_passed(duthost, delayed_services=[]):
    logging.info("Checking if system is running")
    out = duthost.shell("systemctl is-system-running", module_ignore_errors=True)
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
                "ps -o etimes -p $(systemctl show swss@{}.service --property ExecMainPID --value) | sed '1d'".format(
                    asic.asic_index))
            if int(out['stdout'].strip()) < 120:
                return False
    else:
        out = duthost.shell("systemctl show swss.service --property ActiveState --value")
        if out["stdout"] != "active":
            return False

        out = duthost.shell("ps -o etimes -p $(systemctl show swss.service --property ExecMainPID --value) | sed '1d'")
        if int(out['stdout'].strip()) < 120:
            return False

    logging.info("Checking delayed services: %s", delayed_services)
    for service in delayed_services:
        out = duthost.shell("systemctl is-active %s" % service, module_ignore_errors=True)
        if out["stdout"].strip().lower() != "active":
            return False

    logging.info("All checks passed")
    return True


def config_force_option_supported(duthost):
    out = duthost.shell("config reload -h", executable="/bin/bash")
    if "force" in out['stdout'].strip():
        return True
    return False


def config_reload_minigraph_with_rendered_golden_config_override(
        sonic_host, wait=120, start_bgp=True, start_dynamic_buffer=True,
        safe_reload=False, wait_before_force_reload=0, wait_for_bgp=False,
        check_intf_up_ports=False, traffic_shift_away=False,
        golden_config_path=DEFAULT_GOLDEN_CONFIG_PATH,
        local_golden_config_template=GOLDEN_CONFIG_TEMPLATE,
        dut_golden_config_template=None, remote_src=False, is_dut=True):
    """
    This function facilitates new feature table testing without minigraph parser modification. It
    reloads the minigraph using a j2 file to render Golden Config, which overrides the ConfigDB.
    This function includes all parameters from config_reload() with the restraint parameters
    listed below:
    :param config_source: Always set to 'minigraph' cuz Golden Config override are embeded in
                          load_minigraph
    :param override_config: Always True as it needs Golden Config to override
    :param golden_config_path: Path of Golden Config on DUT
    :param local_golden_config_template: template in sonic-mgmt repo and will be copy to DUT to parse
    :param dut_golden_config_template: template that located in remote DUT if there is any.
    :param remote_src: Whether `src` is on the remote host or on the calling device.
    """
    # If dut_template_path is being set, we can directly generate Golden Config from there.
    # Otherwise, we can copy and parse the template in sonic-mgmt repo
    if dut_golden_config_template:
        sonic_host.shell("sonic-cfggen -d -t {} > {}".format(dut_golden_config_template, golden_config_path))
    else:
        dut_golden_config_template = '/tmp/golden_config_db.j2'
        # default src: tests/common/templates/golden_config_db.j2
        # The src could be specified in the template dir under your test.
        # Check test_config_reload_with_rendered_golden_config.py
        sonic_host.copy(src=local_golden_config_template, dest=dut_golden_config_template, remote_src=remote_src)
        # run sonic-cfggen to generate golden_config_db.json with existing config.
        sonic_host.shell("sonic-cfggen -d -t {} > {}".format(dut_golden_config_template, golden_config_path))

    config_reload(sonic_host, 'minigraph', wait, start_bgp, start_dynamic_buffer, safe_reload,
                  wait_before_force_reload, wait_for_bgp, check_intf_up_ports, traffic_shift_away,
                  override_config=True, golden_config_path=golden_config_path, is_dut=is_dut)


@ignore_loganalyzer
def config_reload(sonic_host, config_source='config_db', wait=120, start_bgp=True, start_dynamic_buffer=True,
                  safe_reload=False, wait_before_force_reload=0, wait_for_bgp=False,
                  check_intf_up_ports=False, traffic_shift_away=False, override_config=False,
                  golden_config_path=DEFAULT_GOLDEN_CONFIG_PATH, is_dut=True):
    """
    reload SONiC configuration
    :param sonic_host: SONiC host object
    :param config_source: configuration source is 'config_db', 'minigraph' or 'running_golden_config'
    :param wait: wait timeout for sonic_host to initialize after configuration reload
    :param wait_for_bgp: True to wait for all BGP connections to come up after configuration reload
    :param override_config: override current config with '/etc/sonic/golden_config_db.json'
    :param is_dut: True if the host is DUT, False if the host may be neighbor device.
                    To the non-DUT host, it may lack of some runtime variables like `topo_type`
                    so that this config_reload may fail.
    :return:
    """
    def _config_reload_cmd_wrapper(cmd, executable):
        out = sonic_host.shell(cmd, executable=executable)
        if out['rc'] == 0:
            return True
        else:
            return False

    if config_source not in config_sources:
        raise ValueError('invalid config source passed in "{}", must be {}'.format(
            config_source,
            ' or '.join(['"{}"'.format(src) for src in config_sources])
        ))

    logger.info('reloading {}'.format(config_source))

    if is_dut:
        # Extend ignore fabric port msgs for T2 chassis with DNX chipset on Linecards
        ignore_t2_syslog_msgs(sonic_host)

    if config_source == 'minigraph':
        if start_dynamic_buffer and sonic_host.facts['asic_type'] == 'mellanox':
            output = sonic_host.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model',
                                      module_ignore_errors=True)
            is_buffer_model_dynamic = (output and output.get('stdout') == 'dynamic')
        else:
            is_buffer_model_dynamic = False
        cmd = 'config load_minigraph -y &>/dev/null'
        if traffic_shift_away:
            cmd += ' -t'
        if override_config:
            cmd += ' -o'
        if golden_config_path:
            cmd += ' -p {} '.format(golden_config_path)
        sonic_host.shell(cmd, executable="/bin/bash")
        time.sleep(60)
        if start_bgp:
            sonic_host.shell('config bgp startup all')
        if is_buffer_model_dynamic:
            sonic_host.shell('enable-dynamic-buffer.py')
        sonic_host.shell('config save -y')

    elif config_source == 'config_db':
        cmd = 'config reload -y &>/dev/null'
        reloading = False
        if config_force_option_supported(sonic_host):
            if wait_before_force_reload:
                reloading = wait_until(wait_before_force_reload, 10, 0, _config_reload_cmd_wrapper, cmd, "/bin/bash")
            cmd = 'config reload -y -f &>/dev/null'
        if not reloading:
            time.sleep(30)
            sonic_host.shell(cmd, executable="/bin/bash")

    elif config_source == 'running_golden_config':
        golden_path = '/etc/sonic/running_golden_config.json'
        if sonic_host.is_multi_asic:
            for asic in sonic_host.asics:
                golden_path = f'{golden_path},/etc/sonic/running_golden_config{asic.asic_index}.json'
        cmd = f'config reload -y -l {golden_path} &>/dev/null'
        if config_force_option_supported(sonic_host):
            cmd = f'config reload -y -f -l {golden_path} &>/dev/null'
        sonic_host.shell(cmd, executable="/bin/bash")

    modular_chassis = sonic_host.get_facts().get("modular_chassis")
    wait = max(wait, 240) if modular_chassis.lower() == 'true' else wait

    if safe_reload:
        # The wait time passed in might not be guaranteed to cover the actual
        # time it takes for containers to come back up. Therefore, add 5
        # minutes to the maximum wait time. If it's ready sooner, then the
        # function will return sooner.
        pytest_assert(wait_until(wait + 300, 20, 0, sonic_host.critical_services_fully_started),
                      "All critical services should be fully started!")
        wait_critical_processes(sonic_host)
        if config_source == 'minigraph':
            pytest_assert(wait_until(300, 20, 0, chk_for_pfc_wd, sonic_host),
                          "PFC_WD is missing in CONFIG-DB")

        if check_intf_up_ports:
            pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, sonic_host),
                          "Not all ports that are admin up on are operationally up")
    else:
        time.sleep(wait)

    if wait_for_bgp:
        bgp_neighbors = sonic_host.get_bgp_neighbors_per_asic()
        pytest_assert(
            wait_until(120, 10, 0, sonic_host.check_bgp_session_state_all_asics, bgp_neighbors),
            "Not all bgp sessions are established after config reload",
        )
