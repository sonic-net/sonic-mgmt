import time
import re
from tests.common.utilities import get_image_type

GNMI_CONTAINER_NAME = ''
GNMI_PROGRAM_NAME = ''
GNMI_PORT = 0
# Wait 15 seconds after starting GNMI server
GNMI_SERVER_START_WAIT_TIME = 15


def gnmi_container(duthost):
    global GNMI_CONTAINER_NAME
    if len(GNMI_CONTAINER_NAME) == 0:
        if get_image_type(duthost) == "public":
            GNMI_CONTAINER_NAME = "telemetry"
        else:
            GNMI_CONTAINER_NAME = "gnmi"
    return GNMI_CONTAINER_NAME


def gnmi_program(duthost):
    global GNMI_PROGRAM_NAME
    if len(GNMI_PROGRAM_NAME) == 0:
        if get_image_type(duthost) == "public":
            GNMI_PROGRAM_NAME = "telemetry"
        else:
            GNMI_PROGRAM_NAME = "gnmi-native"
    return GNMI_PROGRAM_NAME


def gnmi_port(duthost):
    global GNMI_PORT
    if GNMI_PORT == 0:
        if get_image_type(duthost) == "public":
            GNMI_CONFIG_KEY = 'TELEMETRY|gnmi'
        else:
            GNMI_CONFIG_KEY = 'GNMI|gnmi'
        port = duthost.shell("sonic-db-cli CONFIG_DB hget '%s' 'port'" % GNMI_CONFIG_KEY)['stdout']
        GNMI_PORT = int(port)
    return GNMI_PORT


def create_ext_conf(ip, filename):
    text = '''
[ req_ext ]
subjectAltName = @alt_names
[alt_names]
DNS.1   = hostname.com
IP      = %s
''' % ip
    with open(filename, 'w') as file:
        file.write(text)
    return


def apply_cert_config(duthost):
    port = gnmi_port(duthost)
    assert int(port) > 0, "Invalid GNMI port"
    dut_command = "docker exec %s supervisorctl stop %s" % (gnmi_container(duthost), gnmi_program(duthost))
    duthost.shell(dut_command)
    dut_command = "docker exec %s pkill telemetry" % (gnmi_container(duthost))
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s bash -c " % gnmi_container(duthost)
    dut_command += "\"/usr/bin/nohup /usr/sbin/telemetry -logtostderr --port %s " % port
    dut_command += "--server_crt /etc/sonic/telemetry/gnmiserver.crt --server_key /etc/sonic/telemetry/gnmiserver.key "
    dut_command += "--ca_crt /etc/sonic/telemetry/gnmiCA.pem -gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\""
    duthost.shell(dut_command)
    time.sleep(GNMI_SERVER_START_WAIT_TIME)


def recover_cert_config(duthost):
    dut_command = "docker exec %s supervisorctl status %s" % (gnmi_container(duthost), gnmi_program(duthost))
    output = duthost.command(dut_command, module_ignore_errors=True)['stdout'].strip()
    if 'RUNNING' in output:
        return
    dut_command = "docker exec %s pkill telemetry" % (gnmi_container(duthost))
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start %s" % (gnmi_container(duthost), gnmi_program(duthost))
    duthost.shell(dut_command)
    time.sleep(GNMI_SERVER_START_WAIT_TIME)


def gnmi_capabilities(duthost, localhost):
    ip = duthost.mgmt_ip
    port = gnmi_port(duthost)
    cmd = "gnmi/gnmi_cli -client_types=gnmi -a %s:%s " % (ip, port)
    cmd += "-logtostderr -client_crt ./gnmiclient.crt -client_key ./gnmiclient.key -ca_crt ./gnmiCA.pem -capabilities"
    output = localhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def gnmi_set(duthost, localhost, delete_list, update_list, replace_list):
    ip = duthost.mgmt_ip
    port = gnmi_port(duthost)
    cmd = "gnmi/gnmi_set -target_addr %s:%s " % (ip, port)
    cmd += "-alsologtostderr -cert ./gnmiclient.crt -key ./gnmiclient.key -ca ./gnmiCA.pem -time_out 60s"
    for delete in delete_list:
        cmd += " -delete " + delete
    for update in update_list:
        cmd += " -update " + update
    for replace in replace_list:
        cmd += " -replace " + replace
    output = localhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def gnmi_get(duthost, localhost, path_list):
    ip = duthost.mgmt_ip
    port = gnmi_port(duthost)
    cmd = "gnmi/gnmi_get -target_addr %s:%s " % (ip, port)
    cmd += "-alsologtostderr -cert ./gnmiclient.crt -key ./gnmiclient.key -ca ./gnmiCA.pem"
    for path in path_list:
        cmd += " -xpath " + path
    output = localhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        return -1, [output['stderr']]
    else:
        msg = output['stdout'].replace('\\', '')
        find_list = re.findall(r'json_ietf_val:\s*"(.*?)"\s*>', msg)
        if find_list:
            return 0, find_list
        else:
            return -1, [msg]


def gnoi_reboot(duthost, localhost, method, delay, message):
    ip = duthost.mgmt_ip
    port = gnmi_port(duthost)
    cmd = "gnmi/gnoi_client -target %s:%s " % (ip, port)
    cmd += "-logtostderr -cert ./gnmiclient.crt -key ./gnmiclient.key -ca ./gnmiCA.pem -rpc Reboot "
    cmd += '-jsonin "{\\\"method\\\":%d, \\\"delay\\\":%d, \\\"message\\\":\\\"%s\\\"}"' % (method, delay, message)
    output = localhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        return -1, output['stderr']
    else:
        return 0, output['stdout']
