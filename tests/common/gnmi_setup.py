"""
Module for setting up gNMI target used by tests
that require SAI validation.
"""
# TODO refactor this module
# Move tests/gnmi/helper.py to tests/common/gnmi_helper.py
# copy of code from tests/gnmi/helper.py

from pathlib import Path

import logging
import shutil
import pytest
import time

import tests.common.gu_utils as gu_utils

from tests.common.cert_utils import TlsCertificateGenerator
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.utilities import wait_until
from tests.common.helpers.ntp_helper import NtpDaemon, get_ntp_daemon_in_use   # noqa: F401

logger = logging.getLogger(__name__)

# Wait time in seconds after starting GNMI server
GNMI_SERVER_START_WAIT_TIME = 5


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


def add_gnmi_client_common_name(duthost, cname, role="readwrite"):
    command = 'sudo sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|{}" "role@" "{}"'.format(cname, role)
    duthost.shell(command, module_ignore_errors=True)


def del_gnmi_client_common_name(duthost, cname):
    duthost.shell('sudo sonic-db-cli CONFIG_DB del "GNMI_CLIENT_CERT|{}"'.format(cname), module_ignore_errors=True)


def check_system_time_sync(duthost):
    """
    Checks if the DUT's time is synchronized with the NTP server.
    If not synchronized, it attempts to restart the NTP service.
    """

    ntp_daemon = get_ntp_daemon_in_use(duthost)

    if ntp_daemon == NtpDaemon.CHRONY:
        ntp_status_cmd = "chronyc -c tracking"
        restart_ntp_cmd = "sudo systemctl restart chrony"
    else:
        ntp_status_cmd = "ntpstat"
        restart_ntp_cmd = "sudo systemctl restart ntp"

    ntp_status = duthost.command(ntp_status_cmd, module_ignore_errors=True)
    if (ntp_daemon == NtpDaemon.CHRONY and "Not synchronised" not in ntp_status["stdout"]) or \
            (ntp_daemon != NtpDaemon.CHRONY and "unsynchronised" not in ntp_status["stdout"]):
        logger.info("DUT %s is synchronized with NTP server.", duthost)
        return True
    else:
        logger.info("DUT %s is NOT synchronized. Restarting NTP service...", duthost)
        duthost.command(restart_ntp_cmd)
        time.sleep(5)
        # Rechecking status after restarting NTP
        ntp_status = duthost.command(ntp_status_cmd, module_ignore_errors=True)
        if (ntp_daemon == NtpDaemon.CHRONY and "Not synchronised" not in ntp_status["stdout"]) or \
                (ntp_daemon != NtpDaemon.CHRONY and "synchronized" in ntp_status["stdout"]):
            logger.info("DUT %s is now synchronized with NTP server.", duthost)
            return True
        else:
            logger.error("DUT %s: NTP synchronization failed. Please check manually.", duthost)
            return False


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


def check_gnmi_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def apply_cert_config(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    # Get subtype
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    metadata = cfg_facts["DEVICE_METADATA"]["localhost"]
    subtype = metadata.get('subtype', None)
    # Stop all running program
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
    dut_command += "--ca_crt /etc/sonic/telemetry/gnmiCA.pem -gnmi_native_write=true -v=10 >/root/gnmi.log 2>&1 &\""
    duthost.shell(dut_command)

    # Setup gnmi client cert common name
    role = "gnmi_readwrite,gnmi_config_db_readwrite,gnmi_appl_db_readwrite,gnmi_dpu_appl_db_readwrite,gnoi_readwrite"
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
    add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic", role)

    is_time_synced = False
    for i in range(3):
        time.sleep(GNMI_SERVER_START_WAIT_TIME)
        dut_command = "sudo netstat -nap | grep %d" % env.gnmi_port
        output = duthost.shell(dut_command, module_ignore_errors=True)
        if is_time_synced is False and duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
            is_time_synced = wait_until(60, 3, 0, check_system_time_sync, duthost)
            assert is_time_synced, "Failed to synchronize DUT system time with NTP Server"
        if env.gnmi_process not in output['stdout']:
            # Dump tcp port status and gnmi log
            logger.info("TCP port status: " + output['stdout'])
            dump_gnmi_log(duthost)
            dump_system_status(duthost)
            pytest.fail("Failed to start gnmi server")


def recover_cert_config(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    cmds = [
        'systemctl reset-failed %s' % (env.gnmi_container),
        'systemctl restart %s' % (env.gnmi_container)
    ]
    duthost.shell_cmds(cmds=cmds)

    # Remove gnmi client cert common name
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    del_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic")
    assert wait_until(60, 3, 0, check_gnmi_status, duthost), "GNMI service failed to start"


def create_certificates(localhost, duthost_mgmt_ip, cert_path: Path):
    """
    Create GNMI CA, server and client certificates.

    Builds the test PKI in-process via cryptography (not openssl shell) so
    that notBefore can be backdated by 7 days. This absorbs clock skew
    between the sonic-mgmt runner, the DUT, and the PTF docker; otherwise
    the TLS handshake fails with "certificate is not yet valid". The
    openssl 3.0.x runtime on Ubuntu 24.04 has no CLI flag to set
    notBefore on `req -x509` or `x509 -req` (added only in 3.5).

    :param localhost: localhost fixture (unused; kept for backward compat)
    :param duthost_mgmt_ip: DUT management IP (included in server cert SAN)
    :param cert_path: Path to store the certificates
    :return: True if successful, False otherwise
    """
    logger.info("Starting certificate creation process.")
    logger.debug(f"Parameters - duthost_mgmt_ip: {duthost_mgmt_ip}, cert_path: {cert_path}")

    dest_dir = cert_path
    old_dest_dir = dest_dir.with_name(dest_dir.name + ".old")
    try:
        if dest_dir.exists():
            logger.debug(f"Destination directory {dest_dir} exists.")
            if old_dest_dir.exists():
                logger.debug(f"Old destination directory {old_dest_dir} exists. Removing it.")
                shutil.rmtree(old_dest_dir)
            dest_dir.rename(old_dest_dir)
            logger.info(f"Renamed existing directory {dest_dir} to {old_dest_dir}.")
        dest_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created new directory {dest_dir}.")
    except Exception as e:
        logger.error(f"Failed to create directory {dest_dir}: {e}")
        raise Exception(f"Failed to create directory {dest_dir}: {e}")

    try:
        generator = TlsCertificateGenerator(
            server_ip=duthost_mgmt_ip,
            backdate_days=7,
            dns_names=["hostname.com"],
            ca_cn="test.gnmi.sonic",
            server_cn="test.server.gnmi.sonic",
            client_cn="test.client.gnmi.sonic",
            ca_cert_name="gnmiCA.pem",
            ca_key_name="gnmiCA.key",
            server_cert_name="gnmiserver.crt",
            server_key_name="gnmiserver.key",
            client_cert_name="gnmiclient.crt",
            client_key_name="gnmiclient.key",
        )
        generator.write_all(str(dest_dir))
    except Exception as e:
        logger.error(f"Failed to generate GNMI certificates: {e}")
        return False

    logger.info("Certificate creation process completed successfully.")
    return True


def copy_certificates_to_dut(local_path, duthost):
    """
    Copy the certificates to the DUT
    :param local_path: Path to the certificates on localhost
    :param duthost: DUT host object
    """
    logger.info("Starting to copy certificates to the DUT.")
    certs = ['gnmiCA.pem', 'gnmiserver.crt', 'gnmiserver.key', 'gnmiclient.crt', 'gnmiclient.key']
    for cert in certs:
        local_file = str(local_path / cert)
        remote_file = str(Path('/etc/sonic/telemetry') / cert)
        logger.debug(f"Copying {local_file} to {remote_file}.")
        out = duthost.copy(src=local_file, dest=remote_file)
        if out.get('failed') is True:
            logger.error(f"Failed to copy {cert} to DUT: {out}")
            return False
    logger.info("All certificates copied to the DUT successfully.")
    return True


def apply_certs(duthost, checkpoint_name):
    """
    Apply the certificates to the DUT
    :param duthost: DUT host object
    """
    logger.info(f"Creating checkpoint '{checkpoint_name}' on the DUT.")
    gu_utils.create_checkpoint(duthost, checkpoint_name)
    logger.info("Applying certificate configuration on the DUT.")
    apply_cert_config(duthost)
    logger.info("Certificate configuration applied successfully.")


def remove_certs(duthost, checkpoint_name):
    """
    Remove the certificates from the DUT
    :param duthost: DUT host object
    :param checkpoint_name: Name of the checkpoint to rollback to
    """
    logger.info(f"Rolling back to checkpoint '{checkpoint_name}' on the DUT.")
    gu_utils.rollback(duthost, checkpoint_name)
    logger.info("Recovering certificate configuration on the DUT.")
    recover_cert_config(duthost)
    logger.info("Certificate configuration removed successfully.")
