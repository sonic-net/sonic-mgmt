import logging
import json
import time
import uuid
from functools import lru_cache

import proto_utils

logger = logging.getLogger(__name__)


@lru_cache(maxsize=None)
class GNMIEnvironment(object):
    def __init__(self, duthost):
        self.duthost = duthost
        self.work_dir = "/tmp/" + str(uuid.uuid4()) + "/"
        self.use_gnmi_container = duthost.shell("docker ps | grep -w gnmi", module_ignore_errors=True)['rc'] == 0
        if self.use_gnmi_container:
            self.gnmi_config_table = "GNMI"
            self.gnmi_container = "gnmi"
            self.gnmi_program = "gnmi-native"
        else:
            self.gnmi_config_table = "TELEMETRY"
            self.gnmi_container = "telemetry"
            self.gnmi_program = "telemetry"
        self.gnmi_port = int(duthost.shell(
            "sonic-db-cli CONFIG_DB hget '%s' 'port'" % (self.gnmi_config_table + '|gnmi'))['stdout'])
        self.gnmi_cert_path = "/etc/sonic/telemetry/"
        self.gnmi_ca_cert = "gnmiCA.pem"
        self.gnmi_ca_key = "gnmiCA.key"
        self.gnmi_server_cert = "gnmiserver.crt"
        self.gnmi_server_key = "gnmiserver.key"
        self.gnmi_client_cert = "gnmiclient.crt"
        self.gnmi_client_key = "gnmiclient.key"
        self.gnmi_server_start_wait_time = 30
        self.enable_zmq = duthost.shell("netstat -na | grep -w 8100", module_ignore_errors=True)['rc'] == 0


def create_ext_conf(ip, filename):
    """
    Generate configuration for openssl

    Args:
        ip: server ip address
        filename: configuration file name

    Returns:
    """
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


def generate_gnmi_cert(localhost, duthost):
    """
    Generate CA certificate, server certificate and client certificate

    Args:
        localhost: fixture for localhost
        duthost: fixture for duthost

    Returns:
    """
    env = GNMIEnvironment(duthost)
    localhost.shell("mkdir "+env.work_dir, module_ignore_errors=True)
    # Create Root key
    local_command = "openssl genrsa -out %s 2048" % (env.work_dir+env.gnmi_ca_key)
    localhost.shell(local_command)

    # Create Root cert
    local_command = "openssl req \
                        -x509 \
                        -new \
                        -nodes \
                        -key %s \
                        -sha256 \
                        -days 1825 \
                        -subj '/CN=test.gnmi.sonic' \
                        -out %s" % (env.work_dir+env.gnmi_ca_key, env.work_dir+env.gnmi_ca_cert)
    localhost.shell(local_command)

    # Create server key
    local_command = "openssl genrsa -out %s 2048" % (env.work_dir+env.gnmi_server_key)
    localhost.shell(local_command)

    # Create server CSR
    local_command = "openssl req \
                        -new \
                        -key %s \
                        -subj '/CN=test.server.gnmi.sonic' \
                        -out %s" % (
                            env.work_dir+env.gnmi_server_key,
                            env.work_dir+"gnmiserver.csr")
    localhost.shell(local_command)

    # Sign server certificate
    create_ext_conf(duthost.mgmt_ip, env.work_dir+"extfile.cnf")
    local_command = "openssl x509 \
                        -req \
                        -in %s \
                        -CA %s \
                        -CAkey %s \
                        -CAcreateserial \
                        -out %s \
                        -days 825 \
                        -sha256 \
                        -extensions req_ext -extfile %s" % (
                            env.work_dir+"gnmiserver.csr",
                            env.work_dir+env.gnmi_ca_cert,
                            env.work_dir+env.gnmi_ca_key,
                            env.work_dir+env.gnmi_server_cert,
                            env.work_dir+"extfile.cnf")
    localhost.shell(local_command)

    # Create client key
    local_command = "openssl genrsa -out %s 2048" % (env.work_dir+env.gnmi_client_key)
    localhost.shell(local_command)

    # Create client CSR
    local_command = "openssl req \
                        -new \
                        -key %s \
                        -subj '/CN=test.client.gnmi.sonic' \
                        -out %s" % (
                            env.work_dir+env.gnmi_client_key,
                            env.work_dir+"gnmiclient.csr")
    localhost.shell(local_command)

    # Sign client certificate
    local_command = "openssl x509 \
                        -req \
                        -in %s \
                        -CA %s \
                        -CAkey %s \
                        -CAcreateserial \
                        -out %s \
                        -days 825 \
                        -sha256" % (
                            env.work_dir+"gnmiclient.csr",
                            env.work_dir+env.gnmi_ca_cert,
                            env.work_dir+env.gnmi_ca_key,
                            env.work_dir+env.gnmi_client_cert)
    localhost.shell(local_command)


def apply_gnmi_cert(duthost, ptfhost):
    """
    Upload new certificate to DUT, and restart gnmi server with new certificate

    Args:
        duthost: fixture for duthost
        ptfhost: fixture to ptfhost

    Returns:
    """
    env = GNMIEnvironment(duthost)
    # Copy CA certificate and server certificate over to the DUT
    duthost.copy(src=env.work_dir+env.gnmi_ca_cert, dest=env.gnmi_cert_path)
    duthost.copy(src=env.work_dir+env.gnmi_server_cert, dest=env.gnmi_cert_path)
    duthost.copy(src=env.work_dir+env.gnmi_server_key, dest=env.gnmi_cert_path)
    # Copy CA certificate and client certificate over to the PTF
    ptfhost.copy(src=env.work_dir+env.gnmi_ca_cert, dest='/root/')
    ptfhost.copy(src=env.work_dir+env.gnmi_client_cert, dest='/root/')
    ptfhost.copy(src=env.work_dir+env.gnmi_client_key, dest='/root/')
    port = env.gnmi_port
    assert int(port) > 0, "Invalid GNMI port"
    dut_command = "docker exec %s supervisorctl stop %s" % (env.gnmi_container, env.gnmi_program)
    duthost.shell(dut_command)
    dut_command = "docker exec %s pkill telemetry" % (env.gnmi_container)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s bash -c " % env.gnmi_container
    dut_command += "\"/usr/bin/nohup /usr/sbin/telemetry -logtostderr --port %s " % port
    dut_command += "--server_crt %s%s " % (env.gnmi_cert_path, env.gnmi_server_cert)
    dut_command += "--server_key %s%s " % (env.gnmi_cert_path, env.gnmi_server_key)
    dut_command += "--ca_crt %s%s " % (env.gnmi_cert_path, env.gnmi_ca_cert)
    if env.enable_zmq:
        dut_command += " -zmq_address=tcp://127.0.0.1:8100 "
    dut_command += "-gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\""
    duthost.shell(dut_command)
    time.sleep(env.gnmi_server_start_wait_time)


def recover_gnmi_cert(localhost, duthost):
    """
    Restart gnmi server to use default certificate

    Args:
        localhost: fixture for localhost
        duthost: fixture for duthost

    Returns:
    """
    env = GNMIEnvironment(duthost)
    localhost.shell("rm -rf "+env.work_dir, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.command(dut_command, module_ignore_errors=True)['stdout'].strip()
    if 'RUNNING' in output:
        return
    dut_command = "docker exec %s pkill telemetry" % (env.gnmi_container)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start %s" % (env.gnmi_container, env.gnmi_program)
    duthost.shell(dut_command)
    time.sleep(env.gnmi_server_start_wait_time)


def gnmi_set(duthost, ptfhost, delete_list, update_list, replace_list):
    """
    Send GNMI set request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        delete_list: list for delete operations
        update_list: list for update operations
        replace_list: list for replace operations

    Returns:
    """
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = 'python2 /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-rcert /root/%s ' % (env.gnmi_ca_cert)
    cmd += '-pkey /root/%s ' % (env.gnmi_client_key)
    cmd += '-cchain /root/%s ' % (env.gnmi_client_cert)
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
    if output['stderr']:
        raise Exception("error:" + output['stderr'])
    else:
        return


def gnmi_get(duthost, ptfhost, path_list):
    """
    Send GNMI get request with GNMI client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        path_list: list for get path

    Returns:
        msg_list: list for get result
    """
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = 'python2 /root/gnxi/gnmi_cli_py/py_gnmicli.py '
    cmd += '--timeout 30 '
    cmd += '-t %s -p %u ' % (ip, port)
    cmd += '-xo sonic-db '
    cmd += '-rcert /root/%s ' % (env.gnmi_ca_cert)
    cmd += '-pkey /root/%s ' % (env.gnmi_client_key)
    cmd += '-cchain /root/%s ' % (env.gnmi_client_cert)
    cmd += '--encoding 4 '
    cmd += '-m get '
    cmd += '--xpath '
    for path in path_list:
        path = path.replace('sonic-db:', '')
        cmd += " " + path
    output = ptfhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        raise Exception("error:" + output['stderr'])
    else:
        msg = output['stdout'].replace('\\', '')
        error = "GRPC error\n"
        if error in msg:
            result = msg.split(error, 1)
            raise Exception("GRPC error:" + result[1])
        mark = 'The GetResponse is below\n' + '-'*25 + '\n'
        if mark in msg:
            result = msg.split(mark, 1)
            msg_list = result[1].split('-'*25)[0:-1]
            return [msg.strip("\n") for msg in msg_list]
        else:
            raise Exception("error:" + msg)


def apply_gnmi_file(duthost, ptfhost, dest_path):
    """
    Apply dash configuration with gnmi client

    Args:
        duthost: fixture for duthost
        ptfhost: fixture for ptfhost
        dest_path: configuration file path

    Returns:
    """
    env = GNMIEnvironment(duthost)
    logger.info("Applying config files on DUT")
    dut_command = "cat %s" % dest_path
    ret = duthost.shell(dut_command)
    assert ret["rc"] == 0, "Failed to read config file"
    text = ret["stdout"]
    res = json.loads(text)
    delete_list = []
    update_list = []
    update_cnt = 0
    for operation in res:
        if operation["OP"] == "SET":
            for k, v in operation.items():
                if k == "OP":
                    continue
                logger.info("Config Json %s" % k)
                update_cnt += 1
                filename = "update%u" % update_cnt
                if proto_utils.ENABLE_PROTO:
                    message = proto_utils.json_to_proto(k, v)
                    with open(env.work_dir+filename, "wb") as file:
                        file.write(message)
                else:
                    text = json.dumps(v)
                    with open(env.work_dir+filename, "w") as file:
                        file.write(text)
                ptfhost.copy(src=env.work_dir+filename, dest='/root/')
                keys = k.split(":", 1)
                k = keys[0] + "[key=" + keys[1] + "]"
                if proto_utils.ENABLE_PROTO:
                    path = "/APPL_DB/%s:$/root/%s" % (k, filename)
                else:
                    path = "/APPL_DB/%s:@/root/%s" % (k, filename)
                update_list.append(path)
        elif operation["OP"] == "DEL":
            for k, v in operation.items():
                if k == "OP":
                    continue
                keys = k.split(":", 1)
                k = keys[0] + "[key=" + keys[1] + "]"
                path = "/APPL_DB/%s" % (k)
                delete_list.append(path)
        else:
            logger.info("Invalid operation %s" % operation["OP"])
    gnmi_set(duthost, ptfhost, delete_list, update_list, [])
    time.sleep(5)
