import pytest
import logging
import random

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def get_pid(duthost, process_name):
    return duthost.shell("pgrep {}".format(process_name), module_ignore_errors=True)["stdout"]


def save_reload_config(duthost):

    def _check_process_ready(duthost, process_name, old_pid):
        new_pid = get_pid(duthost, process_name)
        logger.debug("_check_orchagent_ready: {} PID {}".format(process_name, new_pid))
        return new_pid != "" and new_pid != old_pid

    orchagent_pid = get_pid(duthost, "orchagent")
    telemetry_pid = get_pid(duthost, "telemetry")

    result = duthost.shell("sudo config save -y", module_ignore_errors=True)
    logger.debug("Save config: {}".format(result))
    result = duthost.shell("sudo config reload -y -f", module_ignore_errors=True)
    logger.debug("Reload config: {}".format(result))

    pytest_assert(wait_until(360, 2, 0, _check_process_ready, duthost, "orchagent", orchagent_pid),
                  "The orchagent not start after change subtype")

    pytest_assert(wait_until(360, 2, 0, _check_process_ready, duthost, "telemetry", telemetry_pid),
                  "The telemetry not start after change subtype")


@pytest.fixture
def enable_zmq(duthost):
    command = 'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" subtype'
    subtype = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.debug("subtype: {}".format(subtype))

    # the device already enable SmartSwitch
    if subtype == "SmartSwitch":
        yield
        return

    # enable ZMQ
    command = 'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" subtype SmartSwitch'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.debug("set subtype subtype: {}".format(result))
    save_reload_config(duthost)

    pytest_assert(wait_until(360, 10, 120, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    pytest_assert(
        wait_until(360, 10, 0, duthost.check_bgp_session_state, bgp_neighbors),
        "bgp sessions {} are not up".format(bgp_neighbors)
    )

    yield

    # revert change
    command = 'sonic-db-cli CONFIG_DB hdel "DEVICE_METADATA|localhost" subtype'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.debug("revert subtype subtype: {}".format(result))
    save_reload_config(duthost)


def gnmi_set(duthost, ptfhost, delete_list, update_list, replace_list):
    ip = duthost.mgmt_ip
    port = 8080
    cmd = 'python /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 --notls '
    cmd += '--notls '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-m set-update '
    xpath = ''
    xvalue = ''
    for path in delete_list:
        path = path.replace('sonic-db:', '')
        xpath += ' ' + path
        xvalue += ' ""'
    for update in update_list:
        update = update.replace('sonic-db:', '')
        result = update.rsplit(':', 1)
        xpath += ' ' + result[0]
        xvalue += ' ' + result[1]
    for replace in replace_list:
        replace = replace.replace('sonic-db:', '')
        result = replace.rsplit(':', 1)
        xpath += ' ' + result[0]
        if '#' in result[1]:
            xvalue += ' ""'
        else:
            xvalue += ' ' + result[1]
    cmd += '--xpath ' + xpath
    cmd += ' '
    cmd += '--value ' + xvalue
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    error = "GRPC error\n"
    if error in output['stdout']:
        result = output['stdout'].split(error, 1)
        raise Exception("GRPC error:" + result[1])
    return


def test_gnmi_zmq(duthosts,
                  rand_one_dut_hostname,
                  ptfhost,
                  enable_zmq):
    duthost = duthosts[rand_one_dut_hostname]

    command = 'ps -auxww | grep "/usr/sbin/telemetry -logtostderr --noTLS --port 8080"'
    gnmi_process = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.debug("gnmi_process: {}".format(gnmi_process))

    file_name = "vnet.txt"
    vnet_key = "Vnet{}".format(random.randint(0, 1000))
    text = "{\"" + vnet_key + "\": {\"vni\": \"1000\", \"guid\": \"559c6ce8-26ab-4193-b946-ccc6e8f930b2\"}}"
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    # Add DASH_VNET_TABLE
    update_list = ["/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE:@/root/%s" % (file_name)]
    gnmi_set(duthost, ptfhost, [], update_list, [])

    command = 'sonic-db-cli APPL_DB keys "*" | grep "DASH_VNET_TABLE:{}"'.format(vnet_key)
    appl_db_key = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.debug("appl_db_key: {}".format(appl_db_key))
    assert appl_db_key == "DASH_VNET_TABLE:{}".format(vnet_key)
