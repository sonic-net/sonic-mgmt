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
    duthost.shell('sudo sonic-db-cli CONFIG_DB hset "GNMI_CLIENT_CERT|{}" "role" "{}"'.format(cname, role),
                  module_ignore_errors=True)


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
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    add_gnmi_client_common_name(duthost, "test.client.revoked.gnmi.sonic")

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
    Create GNMI CA, server and client certificates
    :param localhost: localhost fixture
    :param duthost_mgmt_ip: DUT management IP
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

    # Create CA key and certificate
    logger.info("Creating CA key and certificate.")
    key_file = str(dest_dir / 'gnmiCA.key')
    out_file = str(dest_dir / 'gnmiCA.pem')
    logger.debug(f"CA key file: {key_file}, CA certificate file: {out_file}")
    local_command = f"openssl genrsa -out {key_file} 2048"
    localhost.shell(local_command)
    local_command = (
        f"openssl req -x509 -new -nodes -key {key_file} "
        f"-sha256 -days 1825 -subj '/CN=test.gnmi.sonic' "
        f"-out {out_file}"
    )
    out = localhost.shell(local_command)
    if out['rc'] != 0:
        logger.error(f"Failed to create CA certificate {out['stderr']}")
        return False

    # Create server key
    logger.info("Creating server key.")
    key_file = str(dest_dir / 'gnmiserver.key')
    logger.debug(f"Server key file: {key_file}")
    local_command = f"openssl genrsa -out {key_file} 2048"
    out = localhost.shell(local_command)
    if out['rc'] != 0:
        logger.error(f"Failed to create server key {out['stderr']}")
        return False

    # Create server CSR
    logger.info("Creating server CSR.")
    out_file = str(dest_dir / 'gnmiserver.csr')
    logger.debug(f"Server CSR file: {out_file}")
    local_command = (
        f"openssl req -new -key {key_file} "
        f"-subj '/CN=test.server.gnmi.sonic' -out {out_file}"
    )
    localhost.shell(local_command)
    if out['rc'] != 0:
        logger.error(f"Failed to create server CSR {out['stderr']}")
        return False

    # Sign server certificate
    logger.info("Signing server certificate.")
    extfile_path = str(dest_dir / 'extfile.cnf')
    logger.debug(f"Extension file path: {extfile_path}")
    create_ext_conf(duthost_mgmt_ip, extfile_path)
    ca_key = str(dest_dir / 'gnmiCA.key')
    ca_pem = str(dest_dir / 'gnmiCA.pem')
    in_file = str(dest_dir / 'gnmiserver.csr')
    out_file = str(dest_dir / 'gnmiserver.crt')
    logger.debug(f"CA key: {ca_key}, CA PEM: {ca_pem}, Input CSR: {in_file}, Output CRT: {out_file}")
    local_command = (
        f"openssl x509 -req -in {in_file} "
        f"-CA {ca_pem} -CAkey {ca_key} -CAcreateserial "
        f"-out {out_file} -days 825 -sha256 "
        f"-extensions req_ext -extfile {extfile_path}"
    )
    out = localhost.shell(local_command)
    if out['rc'] != 0:
        logger.error(f"Failed to sign server certificate {out['stderr']}")
        return False

    # Create client key
    logger.info("Creating client key.")
    key_file = str(dest_dir / 'gnmiclient.key')
    logger.debug(f"Client key file: {key_file}")
    local_command = f"openssl genrsa -out {key_file} 2048"
    out = localhost.shell(local_command)
    if out['rc'] != 0:
        logger.error(f"Failed to create client key {out['stderr']}")
        return False

    # Create client CSR
    logger.info("Creating client CSR.")
    out_file = str(dest_dir / 'gnmiclient.csr')
    logger.debug(f"Client CSR file: {out_file}")
    local_command = (
        f"openssl req -new -key {key_file} "
        f"-subj '/CN=test.client.gnmi.sonic' -out {out_file}"
    )
    out = localhost.shell(local_command)
    if out['rc'] != 0:
        logger.error(f"Failed to create client CSR {out['stderr']}")
        return False

    # Sign client certificate
    logger.info("Signing client certificate.")
    in_file = str(dest_dir / 'gnmiclient.csr')
    ca_pem = str(dest_dir / 'gnmiCA.pem')
    ca_key = str(dest_dir / 'gnmiCA.key')
    out_file = str(dest_dir / 'gnmiclient.crt')
    logger.debug(f"CA key: {ca_key}, CA PEM: {ca_pem}, Input CSR: {in_file}, Output CRT: {out_file}")
    local_command = (
        f"openssl x509 -req -in {in_file} "
        f"-CA {ca_pem} -CAkey {ca_key} "
        f"-CAcreateserial -out {out_file} -days 825 -sha256"
    )
    out = localhost.shell(local_command)
    if out['rc'] != 0:
        logger.error(f"Failed to sign client certificate {out['stderr']}")
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
