from functools import lru_cache
import pytest
import logging

logger = logging.getLogger(__name__)


GNMI_CERT_NAME = "test.client.gnmi.sonic"
TELEMETRY_CONTAINER = "telemetry"


@lru_cache(maxsize=None)
class GNMIEnvironment(object):
    TELEMETRY_MODE = 0
    GNMI_MODE = 1

    def __init__(self, duthost, mode):
        if mode == self.TELEMETRY_MODE:
            ret = self.generate_telemetry_config(duthost)
            if ret:
                return
            ret = self.generate_gnmi_config(duthost)
            if ret:
                return
        elif mode == self.GNMI_MODE:
            ret = self.generate_gnmi_config(duthost)
            if ret:
                return
            ret = self.generate_telemetry_config(duthost)
            if ret:
                return
        pytest.fail("Can't generate GNMI/TELEMETRY configuration, mode %d" % mode)

    def generate_gnmi_config(self, duthost):
        cmd = "docker images | grep -w sonic-gnmi"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            cmd = "docker ps | grep -w gnmi"
            if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
                self.gnmi_config_table = "GNMI"
                self.gnmi_container = "gnmi"
                self.gnmi_program = "gnmi-native"
                # GNMI process is gnmi or telemetry
                res = duthost.shell("docker exec gnmi ps -ef", module_ignore_errors=True)
                if '/usr/sbin/gnmi' in res['stdout']:
                    self.gnmi_process = "gnmi"
                else:
                    self.gnmi_process = "telemetry"
                self.gnmi_port = 50052
                return True
            else:
                pytest.fail("GNMI is not running")
        return False

    def generate_telemetry_config(self, duthost):
        cmd = "docker images | grep -w sonic-telemetry"
        if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
            cmd = "docker ps | grep -w {}".format(TELEMETRY_CONTAINER)
            if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
                self.gnmi_config_table = "TELEMETRY"
                self.gnmi_container = TELEMETRY_CONTAINER
                # GNMI program is telemetry or gnmi-native
                res = duthost.shell("docker exec %s supervisorctl status" % self.gnmi_container,
                                    module_ignore_errors=True)
                if 'telemetry' in res['stdout']:
                    self.gnmi_program = "telemetry"
                else:
                    self.gnmi_program = "gnmi-native"
                self.gnmi_process = "telemetry"
                self.gnmi_port = 50051
                return True
            else:
                pytest.fail("Telemetry is not running")
        return False


def gnmi_container(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    return env.gnmi_container


def add_gnmi_client_common_name(duthost, cname, role="gnmi_readwrite"):
    command = 'sudo sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|{}" "role@" "{}"'.format(cname, role)
    duthost.shell(command, module_ignore_errors=True)


def del_gnmi_client_common_name(duthost, cname):
    duthost.shell('sudo sonic-db-cli CONFIG_DB del "GNMI_CLIENT_CERT|{}"'.format(cname), module_ignore_errors=True)


def create_ca_conf(crl, filename):
    text = '''
[ req_ext ]
crlDistributionPoints=URI:%s
''' % crl
    with open(filename, 'w') as file:
        file.write(text)
    return


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


def get_ptf_crl_server_ip(duthost, ptfhost):
    """
    Get the appropriate PTF IP address for CRL server based on DUT management IP type.
    If DUT is IPv6-only, use PTF IPv6 address; otherwise use IPv4.
    """
    # Check if DUT management is IPv6-only
    dut_facts = duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts']
    is_mgmt_ipv6_only = dut_facts.get('is_mgmt_ipv6_only', False)
    if is_mgmt_ipv6_only and ptfhost.mgmt_ipv6:
        # Use IPv6 address with brackets for URL
        return "[{}]".format(ptfhost.mgmt_ipv6)
    else:
        # Use IPv4 address
        return ptfhost.mgmt_ip


def create_revoked_cert_and_crl(localhost, ptfhost, duthost=None):
    # Create client key
    local_command = "openssl genrsa -out gnmiclient.revoked.key 2048"
    localhost.shell(local_command)

    # Create client CSR
    local_command = "openssl req \
                        -new \
                        -key gnmiclient.revoked.key \
                        -subj '/CN=test.client.revoked.gnmi.sonic' \
                        -out gnmiclient.revoked.csr"
    localhost.shell(local_command)

    # Sign client certificate
    # Get appropriate PTF IP address based on DUT management IP type
    ptf_ip = get_ptf_crl_server_ip(duthost, ptfhost) if duthost else ptfhost.mgmt_ip
    crl_url = "http://{}:1234/crl".format(ptf_ip)
    create_ca_conf(crl_url, "crlext.cnf")
    local_command = "openssl x509 \
                        -req \
                        -in gnmiclient.revoked.csr \
                        -CA gnmiCA.pem \
                        -CAkey gnmiCA.key \
                        -CAcreateserial \
                        -out gnmiclient.revoked.crt \
                        -days 825 \
                        -sha256 \
                        -extensions req_ext -extfile crlext.cnf"
    localhost.shell(local_command)

    # create crl config file
    local_command = "rm -f gnmi/crl/index.txt"
    localhost.shell(local_command)
    local_command = "touch gnmi/crl/index.txt"
    localhost.shell(local_command)

    local_command = "rm -f gnmi/crl/sonic_crl_number"
    localhost.shell(local_command)
    local_command = "echo 00 > gnmi/crl/sonic_crl_number"
    localhost.shell(local_command)

    # revoke cert CRL
    local_command = "openssl ca \
                        -revoke gnmiclient.revoked.crt \
                        -keyfile gnmiCA.key \
                        -cert gnmiCA.pem \
                        -config gnmi/crl/crl.cnf"

    localhost.shell(local_command)

    # re-create CRL
    local_command = "openssl ca \
                        -gencrl \
                        -keyfile gnmiCA.key \
                        -cert gnmiCA.pem \
                        -out sonic.crl.pem \
                        -config gnmi/crl/crl.cnf"

    localhost.shell(local_command)

    # copy to PTF for test
    ptfhost.copy(src='gnmiclient.revoked.crt', dest='/root/')
    ptfhost.copy(src='gnmiclient.revoked.key', dest='/root/')
    ptfhost.copy(src='sonic.crl.pem', dest='/root/')
    ptfhost.copy(src='gnmi/crl/crl_server.py', dest='/root/')

    local_command = "rm \
                        crlext.cnf \
                        gnmi/crl/index.* \
                        gnmi/crl/sonic_crl_number.*"
    localhost.shell(local_command)


def create_gnmi_certs(duthost, localhost, ptfhost):
    '''
    Create GNMI client certificates
    '''
    # Create Root key
    local_command = "openssl genrsa -out gnmiCA.key 2048"
    localhost.shell(local_command)

    # Create Root cert
    local_command = "openssl req \
                        -x509 \
                        -new \
                        -nodes \
                        -key gnmiCA.key \
                        -sha256 \
                        -days 1825 \
                        -subj '/CN=test.gnmi.sonic' \
                        -out gnmiCA.pem"
    localhost.shell(local_command)

    # Create server key
    local_command = "openssl genrsa -out gnmiserver.key 2048"
    localhost.shell(local_command)

    # Create server CSR
    local_command = "openssl req \
                        -new \
                        -key gnmiserver.key \
                        -subj '/CN=test.server.gnmi.sonic' \
                        -out gnmiserver.csr"
    localhost.shell(local_command)

    # Sign server certificate
    create_ext_conf(duthost.mgmt_ip, "extfile.cnf")
    local_command = "openssl x509 \
                        -req \
                        -in gnmiserver.csr \
                        -CA gnmiCA.pem \
                        -CAkey gnmiCA.key \
                        -CAcreateserial \
                        -out gnmiserver.crt \
                        -days 825 \
                        -sha256 \
                        -extensions req_ext -extfile extfile.cnf"
    localhost.shell(local_command)

    # Create client key
    local_command = "openssl genrsa -out gnmiclient.key 2048"
    localhost.shell(local_command)

    # Create client CSR
    local_command = "openssl req \
                        -new \
                        -key gnmiclient.key \
                        -subj '/CN={}' \
                        -out gnmiclient.csr".format(GNMI_CERT_NAME)
    localhost.shell(local_command)

    # Sign client certificate
    local_command = "openssl x509 \
                        -req \
                        -in gnmiclient.csr \
                        -CA gnmiCA.pem \
                        -CAkey gnmiCA.key \
                        -CAcreateserial \
                        -out gnmiclient.crt \
                        -days 825 \
                        -sha256"
    localhost.shell(local_command)

    create_revoked_cert_and_crl(localhost, ptfhost)

    # Copy CA certificate, server certificate and client certificate over to the DUT
    duthost.copy(src='gnmiCA.pem', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiserver.crt', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiserver.key', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiclient.crt', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiclient.key', dest='/etc/sonic/telemetry/')
    # Copy CA certificate and client certificate over to the PTF
    ptfhost.copy(src='gnmiCA.pem', dest='/root/')
    ptfhost.copy(src='gnmiclient.crt', dest='/root/')
    ptfhost.copy(src='gnmiclient.key', dest='/root/')


def delete_gnmi_certs(localhost):
    '''
    Delete GNMI client certificates
    '''
    local_command = "rm \
                        extfile.cnf \
                        gnmiCA.* \
                        gnmiserver.* \
                        gnmiclient.*"
    localhost.shell(local_command)


def dump_gnmi_log(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s cat /root/gnmi.log" % (env.gnmi_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("GNMI log: " + res['stdout'])
    return res['stdout']


def dump_system_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s ps -efwww" % (env.gnmi_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("GNMI process: " + res['stdout'])
    dut_command = "docker exec %s date" % (env.gnmi_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("System time: " + res['stdout'] + res['stderr'])


def verify_tcp_port(localhost, ip, port):
    command = "ssh  -o ConnectTimeout=3 -v -p %s %s" % (port, ip)
    res = localhost.shell(command, module_ignore_errors=True)
    logger.info("TCP: " + res['stdout'] + res['stderr'])


def gnmi_capabilities(duthost, localhost, duthost_mgmt_ip):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    ip = duthost.mgmt_ip
    port = env.gnmi_port
    # Run gnmi_cli in gnmi container as workaround
    addr = f"[{ip}]" if duthost_mgmt_ip['version'] == 'v6' else f"{ip}"
    cmd = "docker exec %s gnmi_cli -client_types=gnmi -a %s:%s " % (env.gnmi_container, addr, port)
    cmd += "-client_crt /etc/sonic/telemetry/gnmiclient.crt "
    cmd += "-client_key /etc/sonic/telemetry/gnmiclient.key "
    cmd += "-ca_crt /etc/sonic/telemetry/gnmiCA.pem "
    cmd += "-logtostderr -capabilities"
    output = duthost.shell(cmd, module_ignore_errors=True)
    if output['stderr']:
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        verify_tcp_port(localhost, ip, port)
        return -1, output['stderr']
    else:
        return 0, output['stdout']
