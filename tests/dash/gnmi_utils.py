import logging
import json
from time import sleep


logger = logging.getLogger(__name__)

GNMI_PORT = 0
# Wait 15 seconds after starting GNMI server
GNMI_SERVER_START_WAIT_TIME = 15
GNMI_CONTAINER = "gnmi"
GNMI_PROGRAM = "gnmi-native"
GNMI_CA_CERT = "gnmiCA.pem"
GNMI_CA_KEY = "gnmiCA.key"
GNMI_SERVER_CERT = "gnmiserver.crt"
GNMI_SERVER_KEY = "gnmiserver.key"
GNMI_CLIENT_CERT = "gnmiclient.crt"
GNMI_CLIENT_KEY = "gnmiclient.key"


def gnmi_port(duthost):
    global GNMI_PORT
    if GNMI_PORT == 0:
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


def generate_gnmi_cert(localhost, duthost):
    # Create Root key
    local_command = "openssl genrsa -out %s 2048" % (GNMI_CA_KEY)
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
                        -out %s" % (GNMI_CA_KEY, GNMI_CA_CERT)
    localhost.shell(local_command)

    # Create server key
    local_command = "openssl genrsa -out %s 2048" % (GNMI_SERVER_KEY)
    localhost.shell(local_command)

    # Create server CSR
    local_command = "openssl req \
                        -new \
                        -key %s \
                        -subj '/CN=test.server.gnmi.sonic' \
                        -out gnmiserver.csr" % (GNMI_SERVER_KEY)
    localhost.shell(local_command)

    # Sign server certificate
    create_ext_conf(duthost.mgmt_ip, "extfile.cnf")
    local_command = "openssl x509 \
                        -req \
                        -in gnmiserver.csr \
                        -CA %s \
                        -CAkey %s \
                        -CAcreateserial \
                        -out %s \
                        -days 825 \
                        -sha256 \
                        -extensions req_ext -extfile extfile.cnf" % (GNMI_CA_CERT, GNMI_CA_KEY, GNMI_SERVER_CERT)
    localhost.shell(local_command)

    # Create client key
    local_command = "openssl genrsa -out %s 2048" % (GNMI_CLIENT_KEY)
    localhost.shell(local_command)

    # Create client CSR
    local_command = "openssl req \
                        -new \
                        -key %s \
                        -subj '/CN=test.client.gnmi.sonic' \
                        -out gnmiclient.csr" % (GNMI_CLIENT_KEY)
    localhost.shell(local_command)

    # Sign client certificate
    local_command = "openssl x509 \
                        -req \
                        -in gnmiclient.csr \
                        -CA %s \
                        -CAkey %s \
                        -CAcreateserial \
                        -out %s \
                        -days 825 \
                        -sha256" % (GNMI_CA_CERT, GNMI_CA_KEY, GNMI_CLIENT_CERT)
    localhost.shell(local_command)


def apply_gnmi_cert(duthost):
    # Copy CA certificate and server certificate over to the DUT
    duthost.copy(src=GNMI_CA_CERT, dest='/etc/sonic/telemetry/')
    duthost.copy(src=GNMI_SERVER_CERT, dest='/etc/sonic/telemetry/')
    duthost.copy(src=GNMI_SERVER_KEY, dest='/etc/sonic/telemetry/')
    port = gnmi_port(duthost)
    assert int(port) > 0, "Invalid GNMI port"
    dut_command = "docker exec %s supervisorctl stop %s" % (GNMI_CONTAINER, GNMI_PROGRAM)
    duthost.shell(dut_command)
    dut_command = "docker exec %s pkill telemetry" % (GNMI_CONTAINER)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s bash -c " % GNMI_CONTAINER
    dut_command += "\"/usr/bin/nohup /usr/sbin/telemetry -logtostderr --port %s " % port
    dut_command += "--server_crt /etc/sonic/telemetry/%s --server_key /etc/sonic/telemetry/%s " % (GNMI_SERVER_CERT, GNMI_SERVER_KEY)
    dut_command += "--ca_crt /etc/sonic/telemetry/%s -gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\"" % (GNMI_CA_CERT)
    duthost.shell(dut_command)
    time.sleep(GNMI_SERVER_START_WAIT_TIME)


def recover_gnmi_cert(duthost):
    dut_command = "docker exec %s supervisorctl status %s" % (GNMI_CONTAINER, GNMI_PROGRAM)
    output = duthost.command(dut_command, module_ignore_errors=True)['stdout'].strip()
    if 'RUNNING' in output:
        return
    dut_command = "docker exec %s pkill telemetry" % (GNMI_CONTAINER)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start %s" % (GNMI_CONTAINER, GNMI_PROGRAM)
    duthost.shell(dut_command)
    time.sleep(GNMI_SERVER_START_WAIT_TIME)


def gnmi_capabilities(duthost, localhost, client_cert):
    ip = duthost.mgmt_ip
    port = gnmi_port(duthost)
    cmd = "dash/gnmi_cli -client_types=gnmi -a %s:%s " % (ip, port)
    cmd += "-logtostderr -client_crt ./%s -client_key ./%s " % (GNMI_CLIENT_CERT, GNMI_CLIENT_KEY)
    cmd += "-ca_crt ./%s -capabilities" % (GNMI_CA_CERT)
    output = localhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def gnmi_set(duthost, localhost, delete_list, update_list, replace_list):
    ip = duthost.mgmt_ip
    port = gnmi_port(duthost)
    cmd = "dash/gnmi_set -target_addr %s:%s " % (ip, port)
    cmd += "-alsologtostderr -cert ./%s -key ./%s " % (GNMI_CLIENT_CERT, GNMI_CLIENT_KEY)
    cmd += "-ca ./%s -time_out 60s " % (GNMI_CA_CERT)
    cmd += "-xpath_target MIXED "
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
    cmd = "dash/gnmi_get -target_addr %s:%s " % (ip, port)
    cmd += "-alsologtostderr -cert ./%s -key ./%s " % (GNMI_CLIENT_CERT, GNMI_CLIENT_KEY)
    cmd += "-ca ./%s " % (GNMI_CA_CERT)
    cmd += "-xpath_target MIXED "
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


def apply_gnmi_file(duthost, localhost, dest_path):
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
                update_cnt += 1
                text = json.dumps(v)
                filename = "update%u" % update_cnt
                with open(filename, "w") as file:
                    file.write(text)
                k = k.replace("/", "\\\\/", 1)
                k = k.replace(":", "/", 1)
                path = "/sonic-db:APPL_DB/%s:@%s" % (k, filename)
                update_list.append(path)
        elif operation["OP"] == "DEL":
            for k, v in operation.items():
                if k == "OP":
                    continue
                k = k.replace("/", "\\\\/", 1)
                k = k.replace(":", "/", 1)
                path = "/sonic-db:APPL_DB/%s" % (k)
                delete_list.append(path)
        else:
            logger.info("Invalid operation %s" % operation["OP"])
    ret, msg = gnmi_set(duthost, localhost, delete_list, update_list, [])
    assert ret == 0, msg
    sleep(5)
