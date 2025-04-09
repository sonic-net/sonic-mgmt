"""
Module for setting up gNMI target used by tests
that require SAI validation.
"""
from pathlib import Path

import logging
import shutil

import tests.common.gu_utils as gu_utils
import tests.gnmi.helper as gnmi_helper

logger = logging.getLogger(__name__)


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
    gnmi_helper.create_ext_conf(duthost_mgmt_ip, extfile_path)
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
    gnmi_helper.apply_cert_config(duthost)
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
    gnmi_helper.recover_cert_config(duthost)
    logger.info("Certificate configuration removed successfully.")
