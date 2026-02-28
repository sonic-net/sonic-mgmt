import logging

logger = logging.getLogger(__name__)


GNMI_CERT_NAME = "test.client.gnmi.sonic"
REVOKED_GNMICERT_NAME = "test.client.revoked.gnmi.sonic"
TELEMETRY_CONTAINER = "telemetry"


class GNMIEnvironment(object):
    TELEMETRY_MODE = 0
    GNMI_MODE = 1

    def __init__(self, duthost, mode):
        logger.info(f"Initializing GNMIEnvironment with mode {mode}")
        if mode == self.TELEMETRY_MODE:
            ret = self.generate_telemetry_config(duthost)
            if ret:
                logger.info("Successfully generated telemetry config")
                return
            ret = self.generate_gnmi_config(duthost)
            if ret:
                logger.info("Successfully generated gnmi config")
                return
        elif mode == self.GNMI_MODE:
            ret = self.generate_gnmi_config(duthost)
            if ret:
                logger.info("Successfully generated gnmi config")
                return
            ret = self.generate_telemetry_config(duthost)
            if ret:
                logger.info("Successfully generated telemetry config")
                return
        # If no container found, use default configuration
        logger.warning("No GNMI/Telemetry container found, using default configuration")
        self._set_default_config()
        self._configure_connection_params(duthost)

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

                # Read configuration from CONFIG_DB or use defaults
                self._configure_connection_params(duthost)
                return True
            else:
                logger.warning("GNMI container is not running")
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

                # Read configuration from CONFIG_DB or use defaults
                self._configure_connection_params(duthost)
                return True
            else:
                logger.warning("Telemetry container is not running")
        return False

    def _set_default_config(self):
        """Set default configuration when no container is found"""
        self.gnmi_config_table = "GNMI"
        self.gnmi_container = "gnmi"
        self.gnmi_program = "telemetry"
        self.gnmi_process = "telemetry"

    def _configure_connection_params(self, duthost):
        """Configure connection parameters from CONFIG_DB with fallbacks"""
        # Try to read from CONFIG_DB first based on the container type
        try:
            cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

            # Only check the config table that matches our container type
            if self.gnmi_config_table == "GNMI":
                config = cfg_facts.get('GNMI', {}).get('gnmi', {})
            else:  # TELEMETRY
                config = cfg_facts.get('TELEMETRY', {}).get('gnmi', {})

            if config:
                self.gnmi_port = int(config.get('port', 8080))
                client_auth = config.get('client_auth', 'false').lower()
                self.use_tls = client_auth != 'false'
                logger.info(f"Found CONFIG_DB {self.gnmi_config_table} config: "
                            f"port={self.gnmi_port}, tls={self.use_tls}")
                return
        except Exception as e:
            logger.warning(f"Failed to read CONFIG_DB: {e}")

        # Fallback: detect from running telemetry process
        try:
            if hasattr(self, 'gnmi_container'):
                res = duthost.shell(f"docker exec {self.gnmi_container} ps aux | grep telemetry",
                                    module_ignore_errors=True)
                if res['rc'] == 0 and '--port' in res['stdout']:
                    # Extract port from telemetry command line
                    import re
                    match = re.search(r'--port\s+(\d+)', res['stdout'])
                    if match:
                        self.gnmi_port = int(match.group(1))
                        # Check for --noTLS flag
                        self.use_tls = '--noTLS' not in res['stdout']
                        logger.info(f"Detected from process: port={self.gnmi_port}, tls={self.use_tls}")
                        return
        except Exception as e:
            logger.warning(f"Failed to detect from running process: {e}")

        # Final fallback: use standard defaults
        self.gnmi_port = 8080
        self.use_tls = False
        logger.info(f"Using default config: port={self.gnmi_port}, tls={self.use_tls}")


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
    create_client_key(localhost, revoke=True)

    create_client_csr(localhost, revoke=True)

    # Sign client certificate
    # Get appropriate PTF IP address based on DUT management IP type
    ptf_ip = get_ptf_crl_server_ip(duthost, ptfhost) if duthost else ptfhost.mgmt_ip
    crl_url = "http://{}:1234/crl".format(ptf_ip)
    create_ca_conf(crl_url, "crlext.cnf")
    sign_client_certificate(localhost, revoke=True, extension_file="crlext.cnf")

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
    prepare_root_cert(localhost)
    prepare_server_cert(duthost, localhost)
    prepare_client_cert(localhost)
    create_revoked_cert_and_crl(localhost, ptfhost)
    copy_certificate_to_dut(duthost)
    copy_certificate_to_ptf(ptfhost)


def prepare_root_cert(localhost, days="1825"):
    create_root_key(localhost)
    create_root_cert(localhost, days)


def create_root_key(localhost):
    local_command = "openssl genrsa -out gnmiCA.key 2048"
    localhost.shell(local_command)


def create_root_cert(localhost, days):
    local_command = "openssl req \
                            -x509 \
                            -new \
                            -nodes \
                            -key gnmiCA.key \
                            -sha256 \
                            -days {} \
                            -subj '/CN=test.gnmi.sonic' \
                            -out gnmiCA.pem".format(days)
    localhost.shell(local_command)


def prepare_server_cert(duthost, localhost, days="825"):
    create_server_key(localhost)
    create_server_csr(localhost)
    sign_server_certificate(duthost, localhost, days)


def create_server_key(localhost):
    local_command = "openssl genrsa -out gnmiserver.key 2048"
    localhost.shell(local_command)


def create_server_csr(localhost):
    local_command = "openssl req \
                            -new \
                            -key gnmiserver.key \
                            -subj '/CN=test.server.gnmi.sonic' \
                            -out gnmiserver.csr"
    localhost.shell(local_command)


def sign_server_certificate(duthost, localhost, days):
    create_ext_conf(duthost.mgmt_ip, "extfile.cnf")
    local_command = "openssl x509 \
                            -req \
                            -in gnmiserver.csr \
                            -CA gnmiCA.pem \
                            -CAkey gnmiCA.key \
                            -CAcreateserial \
                            -out gnmiserver.crt \
                            -days {} \
                            -sha256 \
                            -extensions req_ext \
                            -extfile extfile.cnf".format(days)
    localhost.shell(local_command)


def prepare_client_cert(localhost, days="825"):
    create_client_key(localhost)
    create_client_csr(localhost)
    sign_client_certificate(localhost, days)


def create_client_key(localhost, revoke=False):
    revoke_suffix = "revoked." if revoke else ""
    local_command = "openssl genrsa -out gnmiclient.{}key 2048".format(revoke_suffix)
    localhost.shell(local_command)


def create_client_csr(localhost, revoke=False):
    revoke_suffix = "revoked." if revoke else ""
    cn = REVOKED_GNMICERT_NAME if revoke else GNMI_CERT_NAME
    local_command = "openssl req \
                            -new \
                            -key gnmiclient.{}key \
                            -subj '/CN={}' \
                            -out gnmiclient.{}csr".format(revoke_suffix, cn, revoke_suffix)
    localhost.shell(local_command)


def sign_client_certificate(localhost, days="825", revoke=False, extension_file=None):
    revoke_suffix = "revoked." if revoke else ""
    extensions = "-extensions req_ext -extfile {}".format(extension_file) if extension_file else ""
    local_command = "openssl x509 \
                            -req \
                            -in gnmiclient.{}csr \
                            -CA gnmiCA.pem \
                            -CAkey gnmiCA.key \
                            -CAcreateserial \
                            -out gnmiclient.{}crt \
                            -days {} \
                            -sha256 {}".format(revoke_suffix, revoke_suffix, days, extensions)
    localhost.shell(local_command)


def copy_certificate_to_dut(duthost):
    # Copy CA certificate, server certificate and client certificate over to the DUT
    duthost.copy(src='gnmiCA.pem', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiserver.crt', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiserver.key', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiclient.crt', dest='/etc/sonic/telemetry/')
    duthost.copy(src='gnmiclient.key', dest='/etc/sonic/telemetry/')


def copy_certificate_to_ptf(ptfhost):
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


def gnmi_capabilities(duthost, localhost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    duthost_mgmt_info = duthost.get_mgmt_ip()
    ip = duthost_mgmt_info['mgmt_ip']
    addr = f"[{ip}]" if duthost_mgmt_info['version'] == 'v6' else f"{ip}"

    port = env.gnmi_port
    # Run gnmi_cli in gnmi container as workaround
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
