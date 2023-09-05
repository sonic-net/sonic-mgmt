import logging
import json
import time
import re
import ipaddress
import pytest
import socket
import uuid
from functools import lru_cache

from dash_api.appliance_pb2 import Appliance
from dash_api.vnet_pb2 import Vnet
from dash_api.eni_pb2 import Eni, State
from dash_api.qos_pb2 import Qos
from dash_api.route_pb2 import Route
from dash_api.route_rule_pb2 import RouteRule
from dash_api.vnet_mapping_pb2 import VnetMapping
from dash_api.route_type_pb2 import RoutingType, ActionType, RouteType, RouteTypeItem

logger = logging.getLogger(__name__)


ENABLE_PROTO = True


@lru_cache(maxsize=None)
class GNMIEnvironment(object):
    def __init__(self, duthost):
        self.duthost = duthost
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
        self.gnmi_ca_cert = "gnmiCA.pem"
        self.gnmi_ca_key = "gnmiCA.key"
        self.gnmi_server_cert = "gnmiserver.crt"
        self.gnmi_server_key = "gnmiserver.key"
        self.gnmi_client_cert = "gnmiclient.crt"
        self.gnmi_client_key = "gnmiclient.key"
        self.gnmi_server_start_wait_time = 30
        self.enable_zmq = duthost.shell("netstat -na | grep -w 8100", module_ignore_errors=True)['rc'] == 0


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
    env = GNMIEnvironment(duthost)
    # Create Root key
    local_command = "openssl genrsa -out %s 2048" % (env.gnmi_ca_key)
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
                        -out %s" % (env.gnmi_ca_key, env.gnmi_ca_cert)
    localhost.shell(local_command)

    # Create server key
    local_command = "openssl genrsa -out %s 2048" % (env.gnmi_server_key)
    localhost.shell(local_command)

    # Create server CSR
    local_command = "openssl req \
                        -new \
                        -key %s \
                        -subj '/CN=test.server.gnmi.sonic' \
                        -out gnmiserver.csr" % (env.gnmi_server_key)
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
                        -extensions req_ext -extfile extfile.cnf" % (
                            env.gnmi_ca_cert, env.gnmi_ca_key, env.gnmi_server_cert)
    localhost.shell(local_command)

    # Create client key
    local_command = "openssl genrsa -out %s 2048" % (env.gnmi_client_key)
    localhost.shell(local_command)

    # Create client CSR
    local_command = "openssl req \
                        -new \
                        -key %s \
                        -subj '/CN=test.client.gnmi.sonic' \
                        -out gnmiclient.csr" % (env.gnmi_client_key)
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
                        -sha256" % (env.gnmi_ca_cert, env.gnmi_ca_key, env.gnmi_client_cert)
    localhost.shell(local_command)


def apply_gnmi_cert(duthost):
    env = GNMIEnvironment(duthost)
    # Copy CA certificate and server certificate over to the DUT
    duthost.copy(src=env.gnmi_ca_cert, dest='/etc/sonic/telemetry/')
    duthost.copy(src=env.gnmi_server_cert, dest='/etc/sonic/telemetry/')
    duthost.copy(src=env.gnmi_server_key, dest='/etc/sonic/telemetry/')
    port = env.gnmi_port
    assert int(port) > 0, "Invalid GNMI port"
    dut_command = "docker exec %s supervisorctl stop %s" % (env.gnmi_container, env.gnmi_program)
    duthost.shell(dut_command)
    dut_command = "docker exec %s pkill telemetry" % (env.gnmi_container)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s bash -c " % env.gnmi_container
    dut_command += "\"/usr/bin/nohup /usr/sbin/telemetry -logtostderr --port %s " % port
    dut_command += "--server_crt /etc/sonic/telemetry/%s " % (env.gnmi_server_cert)
    dut_command += "--server_key /etc/sonic/telemetry/%s " % (env.gnmi_server_key)
    dut_command += "--ca_crt /etc/sonic/telemetry/%s " % (env.gnmi_ca_cert)
    if env.enable_zmq:
        dut_command += " -zmq_address=tcp://127.0.0.1:8100 "
    dut_command += "-gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\""
    duthost.shell(dut_command)
    time.sleep(env.gnmi_server_start_wait_time)


def recover_gnmi_cert(duthost):
    env = GNMIEnvironment(duthost)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.command(dut_command, module_ignore_errors=True)['stdout'].strip()
    if 'RUNNING' in output:
        return
    dut_command = "docker exec %s pkill telemetry" % (env.gnmi_container)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s supervisorctl start %s" % (env.gnmi_container, env.gnmi_program)
    duthost.shell(dut_command)
    time.sleep(env.gnmi_server_start_wait_time)


def gnmi_capabilities(duthost, localhost, client_cert):
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = "dash/gnmi_cli -client_types=gnmi -a %s:%s " % (ip, port)
    cmd += "-logtostderr -client_crt ./%s -client_key ./%s " % (env.gnmi_client_cert, env.gnmi_client_key)
    cmd += "-ca_crt ./%s -capabilities" % (env.gnmi_ca_cert)
    output = localhost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        return -1, output['stderr']
    else:
        return 0, output['stdout']


def gnmi_set(duthost, localhost, delete_list, update_list, replace_list):
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = "dash/gnmi_set -target_addr %s:%s " % (ip, port)
    cmd += "-alsologtostderr -cert ./%s -key ./%s " % (env.gnmi_client_cert, env.gnmi_client_key)
    cmd += "-ca ./%s -time_out 60s " % (env.gnmi_ca_cert)
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
    env = GNMIEnvironment(duthost)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    cmd = "dash/gnmi_get -target_addr %s:%s " % (ip, port)
    cmd += "-alsologtostderr -cert ./%s -key ./%s " % (env.gnmi_client_cert, env.gnmi_client_key)
    cmd += "-ca ./%s " % (env.gnmi_ca_cert)
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


def json_to_proto(key, json_obj):
    table_name = re.search(r"DASH_(\w+)_TABLE", key).group(1)
    if table_name == "APPLIANCE":
        pb = Appliance()
        pb.sip.ipv4 = socket.htonl(int(ipaddress.IPv4Address(json_obj["sip"])))
        pb.vm_vni = int(json_obj["vm_vni"])
    elif table_name == "VNET":
        pb = Vnet()
        pb.vni = int(json_obj["vni"])
        pb.guid.value = bytes.fromhex(uuid.UUID(json_obj["guid"]).hex)
    elif table_name == "VNET_MAPPING":
        pb = VnetMapping()
        pb.action_type = RoutingType.ROUTING_TYPE_VNET_ENCAP
        pb.underlay_ip.ipv4 = socket.htonl(int(ipaddress.IPv4Address(json_obj["underlay_ip"])))
        pb.mac_address = bytes.fromhex(json_obj["mac_address"].replace(":", ""))
        pb.use_dst_vni = json_obj["use_dst_vni"] == "true"
    elif table_name == "QOS":
        pb = Qos()
        pb.qos_id = json_obj["qos_id"]
        pb.bw = int(json_obj["bw"])
        pb.cps = int(json_obj["cps"])
        pb.flows = int(json_obj["flows"])
    elif table_name == "ENI":
        pb = Eni()
        pb.eni_id = json_obj["eni_id"]
        pb.mac_address = bytes.fromhex(json_obj["mac_address"].replace(":", ""))
        pb.underlay_ip.ipv4 = socket.htonl(int(ipaddress.IPv4Address(json_obj["underlay_ip"])))
        pb.admin_state = State.STATE_ENABLED if json_obj["admin_state"] == "enabled" else State.STATE_DISABLED
        pb.vnet = json_obj["vnet"]
        pb.qos = json_obj["qos"]
    elif table_name == "ROUTE":
        pb = Route()
        if json_obj["action_type"] == "vnet":
            pb.action_type = RoutingType.ROUTING_TYPE_VNET
            pb.vnet = json_obj["vnet"]
        elif json_obj["action_type"] == "vnet_direct":
            pb.action_type = RoutingType.ROUTING_TYPE_VNET_DIRECT
            pb.vnet_direct.vnet = json_obj["vnet"]
            pb.vnet_direct.overlay_ip.ipv4 = socket.htonl(int(ipaddress.IPv4Address(json_obj["overlay_ip"])))
        elif json_obj["action_type"] == "direct":
            pb.action_type = RoutingType.ROUTING_TYPE_DIRECT
        else:
            pytest.fail("Unknown action type %s" % json_obj["action_type"])
    elif table_name == "ROUTE_RULE":
        pb = RouteRule()
        pb.action_type = RoutingType.ROUTING_TYPE_VNET_ENCAP
        pb.priority = int(json_obj["priority"])
        pb.pa_validation = json_obj["pa_validation"] == "true"
        pb.vnet = json_obj["vnet"]
    elif table_name == "ROUTING_TYPE":
        pb = RouteType()
        pbi = RouteTypeItem()
        pbi.action_name = json_obj["name"]
        pbi.action_type = ActionType.ACTION_TYPE_MAPROUTING
        pb.items.append(pbi)
    else:
        pytest.fail("Unknown table %s" % table_name)
    return pb.SerializeToString()


def apply_gnmi_file(duthost, localhost, dest_path):
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
                if ENABLE_PROTO:
                    message = json_to_proto(k, v)
                    with open(filename, "wb") as file:
                        file.write(message)
                else:
                    text = json.dumps(v)
                    with open(filename, "w") as file:
                        file.write(text)
                k = k.replace("/", "\\\\/", 1)
                k = k.replace(":", "/", 1)
                if ENABLE_PROTO:
                    path = "/sonic-db:APPL_DB/%s:$./%s" % (k, filename)
                else:
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
    time.sleep(5)
