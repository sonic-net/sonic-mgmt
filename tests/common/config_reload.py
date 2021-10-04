import time
import logging

logger = logging.getLogger(__name__)

config_sources = ['config_db', 'minigraph']

def config_system_checks_passed(duthost):
    logging.info("Checking if system is running")
    out=duthost.shell("systemctl is-system-running")
    if "running" not in out['stdout']:
        return False

    logging.info("Checking if Orchagent up for at least 2 min")
    out = duthost.shell("systemctl show swss.service --property ActiveState --value")
    if out["stdout"] != "active":
        return False

    out = duthost.shell("ps -o etimes -p $(systemctl show swss.service --property ExecMainPID --value) | sed '1d'")
    if int(out['stdout'].strip()) < 120:
        return False

    logging.info("Checking if delayed services are up")
    out = duthost.shell("systemctl list-dependencies sonic-delayed.target --plain |sed '1d'")
    for service in out['stdout'].splitlines():
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

def config_reload(duthost, config_source='config_db', wait=120, start_bgp=True, start_dynamic_buffer=True):
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

    time.sleep(wait)
