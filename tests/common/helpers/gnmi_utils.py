import ipaddress
import logging
import re
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from tests.common.utilities import wait_until
from tests.common.helpers.ntp_helper import NtpDaemon, get_ntp_daemon_in_use
from tests.common.helpers.dut_utils import check_container_state

logger = logging.getLogger(__name__)


GNMI_CERT_NAME = "test.client.gnmi.sonic"
REVOKED_GNMICERT_NAME = "test.client.revoked.gnmi.sonic"
TELEMETRY_CONTAINER = "telemetry"
# Wait 15 seconds after starting GNMI server
GNMI_SERVER_START_WAIT_TIME = 15

# Backdate notBefore on test certs to absorb clock skew between the
# sonic-mgmt runner, the DUT, and the PTF docker. Without this, even a
# few minutes of drift produces TLS handshake failures with
# "certificate is not yet valid". We do the signing in-process via
# cryptography because the openssl 3.0.x CLI on the runner has no flag
# to set notBefore on `req -x509` / `x509 -req` (added only in 3.5).
_CERT_BACKDATE_DAYS = 7


def _cert_validity_period(days):
    """notBefore is backdated by _CERT_BACKDATE_DAYS; notAfter is `days` from now."""
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=_CERT_BACKDATE_DAYS)
    not_after = now + timedelta(days=int(days))
    return not_before, not_after


def _load_pem_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_pem_certificate(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _load_pem_csr(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_csr(f.read())


def _write_pem_certificate(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _parse_crl_dp_uri(extension_file):
    """Extract the CRL distribution point URI written by create_ca_conf."""
    with open(extension_file, "r") as f:
        text = f.read()
    match = re.search(r"crlDistributionPoints\s*=\s*URI:(\S+)", text)
    return match.group(1) if match else None


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
                        # --noTLS means no TLS; --insecure means TLS with self-signed cert (use_tls=True)
                        self.use_tls = '--noTLS' not in res['stdout']
                        logger.info(f"Detected from process: port={self.gnmi_port}, tls={self.use_tls}")
                        return
        except Exception as e:
            logger.warning(f"Failed to detect from running process: {e}")

        # Final fallback: use standard defaults
        self.gnmi_port = 8080
        self.use_tls = True  # default to insecure TLS (GNMI|certs configured in tests)
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


def create_gnmi_certs(duthost, localhost, ptfhost, dut_ip=None):
    '''
    Create GNMI client certificates
    '''
    prepare_root_cert(localhost)
    prepare_server_cert(duthost, localhost, dut_ip=dut_ip)
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
    """Self-signed CA cert, backdated by _CERT_BACKDATE_DAYS.

    Includes SubjectKeyIdentifier to match what `openssl req -x509`
    used to add for free via the system openssl.cnf [v3_ca] section.
    The CRL flow in create_revoked_cert_and_crl needs SKI here so its
    `authorityKeyIdentifier=keyid:always` extension can resolve.
    """
    ca_key = _load_pem_private_key("gnmiCA.key")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.gnmi.sonic"),
    ])
    not_before, not_after = _cert_validity_period(days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_pem_certificate("gnmiCA.pem", cert)


def prepare_server_cert(duthost, localhost, days="825", dut_ip=None):
    create_server_key(localhost)
    create_server_csr(localhost)
    sign_server_certificate(duthost, localhost, days, dut_ip=dut_ip)


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


def sign_server_certificate(duthost, localhost, days, dut_ip=None):
    """Sign gnmiserver.csr with the CA, backdated, with SAN (hostname.com + DUT mgmt IP).

    When dut_ip is provided, it is used as the SAN IP address instead of
    duthost.mgmt_ip. This lets callers bind the cert to the address the
    gnmi server is actually reachable at (e.g. when bound to a non-default VRF).
    """
    ca_cert = _load_pem_certificate("gnmiCA.pem")
    ca_key = _load_pem_private_key("gnmiCA.key")
    csr = _load_pem_csr("gnmiserver.csr")
    not_before, not_after = _cert_validity_period(days)
    san_entries = [
        x509.DNSName("hostname.com"),
        x509.IPAddress(ipaddress.ip_address(dut_ip or duthost.mgmt_ip)),
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_pem_certificate("gnmiserver.crt", cert)


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
    """Sign a (regular or revoked) client CSR with the CA, backdated.

    `extension_file` is the cnf written by create_ca_conf when caller wants
    a CRL Distribution Points extension on the cert; we parse the URI out
    of it and add the extension via cryptography (we no longer hand the
    file to openssl).
    """
    revoke_suffix = "revoked." if revoke else ""
    csr_path = "gnmiclient.{}csr".format(revoke_suffix)
    out_path = "gnmiclient.{}crt".format(revoke_suffix)
    ca_cert = _load_pem_certificate("gnmiCA.pem")
    ca_key = _load_pem_private_key("gnmiCA.key")
    csr = _load_pem_csr(csr_path)
    not_before, not_after = _cert_validity_period(days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if extension_file:
        crl_uri = _parse_crl_dp_uri(extension_file)
        if crl_uri:
            dp = x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_uri)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
            builder = builder.add_extension(
                x509.CRLDistributionPoints([dp]),
                critical=False,
            )
    cert = builder.sign(ca_key, hashes.SHA256())
    _write_pem_certificate(out_path, cert)


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
    # -f because extfile.cnf is no longer always created on disk
    # (sign_server_certificate now sets SAN in-process).
    local_command = "rm -f \
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


def ensure_gnmi_insecure_mode(duthost, mode=GNMIEnvironment.GNMI_MODE):
    """
    Configure GNMI/TELEMETRY certs table in CONFIG_DB with empty cert fields.
    This causes the startup script to use --insecure (TLS with self-signed cert)
    instead of --noTLS (cleartext), improving security while maintaining test compatibility.

    Args:
        duthost: DUT host object
        mode: GNMI_MODE uses GNMI|certs table; TELEMETRY_MODE uses TELEMETRY|certs
    """
    if mode == GNMIEnvironment.GNMI_MODE:
        table = "GNMI|certs"
    else:
        table = "TELEMETRY|certs"

    logger.info(f"Configuring {table} with empty cert fields to enable --insecure mode")
    # Include ca_crt "" to avoid jq returning string "null" for missing key,
    # which would cause telemetry startup script to pass --ca_crt null and block port binding.
    duthost.shell(f'sonic-db-cli CONFIG_DB hset "{table}" server_crt "" server_key "" ca_crt ""',
                  module_ignore_errors=True)


def cleanup_gnmi_insecure_mode(duthost, mode=GNMIEnvironment.GNMI_MODE):
    """Remove the empty cert config added by ensure_gnmi_insecure_mode."""
    if mode == GNMIEnvironment.GNMI_MODE:
        table = "GNMI|certs"
    else:
        table = "TELEMETRY|certs"

    # Only remove if no real certs are configured
    result = duthost.shell(f'sonic-db-cli CONFIG_DB hget "{table}" server_crt',
                           module_ignore_errors=True)
    if result['stdout'].strip() == "":
        logger.info(f"Removing empty cert config from {table}")
        duthost.shell(f'sonic-db-cli CONFIG_DB del "{table}"', module_ignore_errors=True)


def check_ntp_sync_status(duthost):
    """
    Checks if the DUT's time is synchronized with the NTP server.
    """

    ntp_daemon = get_ntp_daemon_in_use(duthost)

    if ntp_daemon == NtpDaemon.CHRONY:
        ntp_status_cmd = "chronyc -c tracking"
    else:
        ntp_status_cmd = "ntpstat"

    ntp_status = duthost.command(ntp_status_cmd, module_ignore_errors=True)
    if (ntp_daemon == NtpDaemon.CHRONY and "Not synchronised" not in ntp_status["stdout"]) or \
            (ntp_daemon != NtpDaemon.CHRONY and "unsynchronised" not in ntp_status["stdout"]):
        logger.info("DUT %s is synchronized with NTP server.", duthost)
        return True
    else:
        logger.info("DUT %s is NOT synchronized.", duthost)
        return False


def check_system_time_sync(duthost):
    """
    Checks if the DUT's time is synchronized with the NTP server.
    If not synchronized, it attempts to restart the NTP service.
    """

    if check_ntp_sync_status(duthost) is True:
        return True

    ntp_daemon = get_ntp_daemon_in_use(duthost)

    if ntp_daemon == NtpDaemon.CHRONY:
        restart_ntp_cmd = "sudo systemctl restart chrony"
    else:
        restart_ntp_cmd = "sudo systemctl restart ntp"

    logger.info("DUT %s is NOT synchronized. Restarting NTP service...", duthost)
    duthost.command(restart_ntp_cmd)
    time.sleep(5)
    # Rechecking status after restarting NTP
    ntp_status = check_ntp_sync_status(duthost)
    if ntp_status is True:
        logger.info("DUT %s is now synchronized with NTP server.", duthost)
        return True
    else:
        logger.error("DUT %s: NTP synchronization failed. Please check manually.", duthost)
        return False


def check_gnmi_process(duthost):
    """
    Make sure there's no GNMI process running.
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s pgrep -f %s" % (env.gnmi_container, env.gnmi_process)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return output['stdout'].strip() == ""


def check_gnmi_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def _check_monit_container_checker(duthost):
    """Check if monit container_checker service is healthy.

    After gNMI cert config recovery, monit needs time to re-evaluate
    container status. This function checks if container_checker has
    returned to a healthy state (OK or Status ok).
    """
    monit_services = duthost.get_monit_services_status()
    if not monit_services:
        return False
    container_checker = monit_services.get("container_checker", {})
    status = container_checker.get("service_status", "")
    return status in ("OK", "Status ok")


def apply_cert_config(duthost, vrf_name=None):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    # Get subtype
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    metadata = cfg_facts["DEVICE_METADATA"]["localhost"]
    subtype = metadata.get('subtype', None)
    # Stop all running program
    stopped_programs = []
    dut_command = "docker exec %s supervisorctl status" % (env.gnmi_container)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    for line in output['stdout_lines']:
        res = line.split()
        if len(res) < 3:
            continue
        program = res[0]
        status = res[1]
        if status == "RUNNING":
            dut_command = "docker exec %s supervisorctl stop %s" % (env.gnmi_container, program)
            duthost.shell(dut_command, module_ignore_errors=True)
            logger.info("Stopped supervisord program: %s", program)
            stopped_programs.append(program)
    dut_command = "docker exec %s pkill %s" % (env.gnmi_container, env.gnmi_process)
    duthost.shell(dut_command, module_ignore_errors=True)
    dut_command = "docker exec %s bash -c " % env.gnmi_container
    dut_command += "\"/usr/bin/nohup /usr/sbin/%s -logtostderr --port %s " % (env.gnmi_process, env.gnmi_port)
    dut_command += "--server_crt /etc/sonic/telemetry/gnmiserver.crt --server_key /etc/sonic/telemetry/gnmiserver.key "
    dut_command += "--config_table_name GNMI_CLIENT_CERT "
    dut_command += "--client_auth cert "
    dut_command += "--enable_crl=true "
    if subtype == 'SmartSwitch':
        dut_command += "--zmq_address=tcp://127.0.0.1:8100 "
    if vrf_name:
        dut_command += "--gnmi_vrf %s " % vrf_name
    dut_command += "--ca_crt /etc/sonic/telemetry/gnmiCA.pem -gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\""
    duthost.shell(dut_command)

    # Setup gnmi client cert common name
    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
    add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic", role)

    time.sleep(GNMI_SERVER_START_WAIT_TIME)
    dut_command = "sudo netstat -nap | grep %d" % env.gnmi_port
    output = duthost.shell(dut_command, module_ignore_errors=True)
    if duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
        is_time_synced = wait_until(80, 3, 0, check_system_time_sync, duthost)
        assert is_time_synced, "Failed to synchronize DUT system time with NTP Server"
    if env.gnmi_process not in output['stdout']:
        # Dump tcp port status and gnmi log
        logger.info("TCP port status: " + output['stdout'])
        dump_gnmi_log(duthost)
        dump_system_status(duthost)
        pytest.fail("Failed to start gnmi server")
    return stopped_programs


def recover_cert_config(duthost, stopped_programs=None):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    # Kill the GNMI process
    dut_command = "docker exec %s pkill %s" % (env.gnmi_container, env.gnmi_process)
    duthost.shell(dut_command, module_ignore_errors=True)
    wait_until(60, 1, 0, check_gnmi_process, duthost)
    # Restore only the programs that apply_cert_config explicitly stopped
    if stopped_programs:
        for program in stopped_programs:
            logger.info("Restarting supervisord program: %s", program)
            dut_command = "docker exec %s supervisorctl start %s" % (env.gnmi_container, program)
            duthost.shell(dut_command, module_ignore_errors=True)

    # Remove gnmi client cert common name
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    del_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic")
    ret = wait_until(300, 3, 0, check_gnmi_status, duthost)
    if not ret:
        dut_command = "tail /var/log/gnmi.log"
        output = duthost.shell(dut_command, module_ignore_errors=True)
        logger.error("GNMI service failed to start. GNMI log: {}".format(output['stdout']))
        pytest.fail("Failed to recover GNMI client cert configuration.")

    # Restart telemetry container if it was stopped during cert config change
    # apply_cert_config may trigger ctrmgrd to stop the telemetry container
    if not check_container_state(duthost, "telemetry", should_be_running=True):
        logger.info("Telemetry container is not running after cert config recovery, restarting it")
        duthost.shell("sudo systemctl restart telemetry", module_ignore_errors=True)

    # Wait for monit container_checker to report healthy status.
    # After restarting processes/containers, monit needs time to re-evaluate
    # service status. Without this wait, post-test sanity check may see stale
    # "Status failed" from container_checker and fail the test on teardown.
    if not wait_until(120, 10, 30, _check_monit_container_checker, duthost):
        logger.warning("Monit container_checker did not recover to healthy status after cert config recovery")
