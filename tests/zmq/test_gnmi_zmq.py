import pytest
import logging
import random
import time

from gnmi.helper import gnmi_set
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('any')
]


def save_reload_config(duthost):

    def _check_process_ready(process_name):
        pid = duthost.shell("pgrep {}".format(process_name), module_ignore_errors=True)["stdout"]
        logger.warning("_check_orchagent_ready: {} PID {}".format(process_name, pid))
        return pid != ""

    result = duthost.shell("sudo config save -y", module_ignore_errors=True)
    logger.warning("Save config: {}".format(result))
    result = duthost.shell("sudo config reload -y -f", module_ignore_errors=True)
    logger.warning("Reload config: {}".format(result))

    # swss and gnmi container may take some time to stop after reload config command
    time.sleep(5)

    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "orchagent"),
                  "The orchagent not start after change subtype")

    pytest_assert(wait_until(30, 2, 0, _check_process_ready, "telemetry"),
                  "The telemetry not start after change subtype")


@pytest.fixture
def enable_zmq(duthost):
    command = 'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" subtype'
    subtype = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.warning("subtype: {}".format(subtype))

    # the device already enable SmartSwitch
    if subtype == "SmartSwitch":
        yield
        return

    # enable ZMQ
    command = 'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" subtype SmartSwitch'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.warning("set subtype subtype: {}".format(result))
    save_reload_config(duthost)

    yield

    # revert change
    command = 'sonic-db-cli CONFIG_DB hdel "DEVICE_METADATA|localhost" subtype'
    result = duthost.shell(command, module_ignore_errors=True)
    logger.warning("revert subtype subtype: {}".format(result))
    save_reload_config(duthost)



def gnmi_set(duthost, ptfhost, delete_list, update_list, replace_list):
    ip = duthost.mgmt_ip
    port = 8080
    cmd = 'python2 /root/gnxi/gnmi_cli_py/py_gnmicli.py '
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
    logger.warning("gnmi_set command:{}".format(cmd))
    error = "GRPC error\n"
    if error in output['stdout']:
        result = output['stdout'].split(error, 1)
        raise Exception("GRPC error:" + result[1])
    if output['stderr']:
        raise Exception("error:" + output['stderr'])
    else:
        return


def test_gnmi_zmq(duthosts,
                    rand_one_dut_hostname,
                    ptfhost,
                    enable_zmq):
    duthost = duthosts[rand_one_dut_hostname]

    command = 'ps -auxww | grep "/usr/sbin/telemetry -logtostderr --noTLS --port 8080"'
    gnmi_process = duthost.shell(command, module_ignore_errors=True)["stdout"]
    logger.warning("gnmi_process:{}".format(gnmi_process))

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
    logger.warning("appl_db_key:{}".format(appl_db_key))
    assert appl_db_key == "DASH_VNET_TABLE:{}".format(vnet_key)
