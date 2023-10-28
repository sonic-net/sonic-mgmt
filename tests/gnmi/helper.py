import time
import re
from functools import lru_cache
import pytest

GNMI_CONTAINER_NAME = ''
GNMI_PROGRAM_NAME = ''
GNMI_PORT = 0
# Wait 15 seconds after starting GNMI server
GNMI_SERVER_START_WAIT_TIME = 15


@lru_cache(maxsize=None)
class GNMIEnvironment(object):
    def __init__(self, duthost):
        cmd = "docker images | grep -w sonic-gnmi"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            cmd = "docker ps | grep -w gnmi"
            if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
                self.gnmi_config_table = "GNMI"
                self.gnmi_container = "gnmi"
                self.gnmi_program = "gnmi-native"
                self.gnmi_port = 50052
                return
            else:
                pytest.fail("GNMI is not running")
        cmd = "docker images | grep -w sonic-telemetry"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            cmd = "docker ps | grep -w telemetry"
            if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
                self.gnmi_config_table = "TELEMETRY"
                self.gnmi_container = "telemetry"
                self.gnmi_program = "telemetry"
                self.gnmi_port = 50051
                return
            else:
                pytest.fail("Telemetry is not running")
        pytest.fail("Can't find telemetry and gnmi image")


def gnmi_container(duthost):
    env = GNMIEnvironment(duthost)
    return env.gnmi_container


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
    env = GNMIEnvironment(duthost)
    dut_command = "docker exec %s supervisorctl stop %s" % (env.gnmi_container, env.gnmi_program)
    duthost.shell(dut_command)
    dut_command = "docker exec %s pkill telemetry" % (env.gnmi_container)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s bash -c " % env.gnmi_container
    dut_command += "\"/usr/bin/nohup /usr/sbin/telemetry -logtostderr --port %s " % env.gnmi_port
    dut_command += "--server_crt /etc/sonic/telemetry/gnmiserver.crt --server_key /etc/sonic/telemetry/gnmiserver.key "
    dut_command += "--ca_crt /etc/sonic/telemetry/gnmiCA.pem -gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\""
    duthost.shell(dut_command)
    time.sleep(GNMI_SERVER_START_WAIT_TIME)


def recover_cert_config(duthost):
    env = GNMIEnvironment(duthost)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.command(dut_command, module_ignore_errors=True)['stdout'].strip()
    if 'RUNNING' in output:
        return
    dut_command = "docker exec %s pkill telemetry" % (env.gnmi_container)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start %s" % (env.gnmi_container, env.gnmi_program)
    duthost.shell(dut_command)
    time.sleep(GNMI_SERVER_START_WAIT_TIME)


def gnmi_capabilities(duthost, localhost):
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = "gnmi/gnmi_cli -client_types=gnmi -a %s:%s " % (ip, port)
    cmd += "-logtostderr -client_crt ./gnmiclient.crt -client_key ./gnmiclient.key -ca_crt ./gnmiCA.pem -capabilities"
    output = localhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def gnmi_set(duthost, localhost, delete_list, update_list, replace_list):
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
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
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
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
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = "gnmi/gnoi_client -target %s:%s " % (ip, port)
    cmd += "-logtostderr -cert ./gnmiclient.crt -key ./gnmiclient.key -ca ./gnmiCA.pem -rpc Reboot "
    cmd += '-jsonin "{\\\"method\\\":%d, \\\"delay\\\":%d, \\\"message\\\":\\\"%s\\\"}"' % (method, delay, message)
    output = localhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        return -1, output['stderr']
    else:
        return 0, output['stdout']
