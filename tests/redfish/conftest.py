import json
import logging
import os
import subprocess
import textwrap
import time

import pytest
import yaml

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.redfish.redfish_utils import RedfishClient

logger = logging.getLogger(__name__)

REDFISH_ROOT = "/redfish/v1"


@pytest.fixture(scope="module", autouse=True)
def is_bmc_present(request, tbinfo):
    """Skip the module if the target is not a BMC device.

    Checks the topology name from tbinfo. If the topology contains 'bmc'
    (e.g. bmc-dual-mgmt, bmc-shared-mgmt) the check passes immediately.
    Otherwise duthost.is_bmc() is consulted via DUT SSH.
    """
    if 'bmc' in tbinfo['topo']['name']:
        return
    duthosts = request.getfixturevalue("duthosts")
    hostname = request.getfixturevalue("enum_rand_one_per_hwsku_hostname")
    duthost = duthosts[hostname]
    pyrequire(duthost.is_bmc(),
              "DUT is not a BMC device (dut_type != NetworkBmc), skipping Redfish tests")


@pytest.fixture(scope="module")
def bmc_ip(tbinfo):
    """Return the BMC Redfish IP from testbed.yaml (bmc_ip field)."""
    ip = tbinfo.get("bmc_ip")
    pyrequire(ip, "bmc_ip field missing from testbed.yaml entry for this testbed")
    return ip


@pytest.fixture(scope="module")
def bmc_creds():
    """Return BMC credentials from ansible/group_vars/all/creds.yml.

    Uses sonic_login as the username and sonic_default_passwords[0] as
    the password — the same credentials used for SONiC device SSH access.
    """
    creds_file = os.path.join(
        os.path.dirname(__file__), "../../ansible/group_vars/all/creds.yml"
    )
    with open(creds_file) as f:
        creds_data = yaml.safe_load(f)
    default_passwords = creds_data.get("sonic_default_passwords", [])
    return {
        "user": creds_data.get("sonic_login"),
        "password": default_passwords[0] if default_passwords else None,
    }


@pytest.fixture(scope="module")
def redfish_base_url(bmc_ip):
    return "https://{}{}".format(bmc_ip, REDFISH_ROOT)


@pytest.fixture(scope="module")
def redfish_client(bmc_ip, bmc_creds):
    """Return a RedfishClient instance configured with BMC credentials."""
    return RedfishClient(bmc_ip, bmc_creds["user"], bmc_creds["password"])


@pytest.fixture(scope="module")
def bmc_exec(bmc_ip, bmc_creds):
    """Return a callable that runs a command directly on bmc_ip via SSH.

    Usage in tests:
        stdout, stderr, rc = bmc_exec("docker exec redfish ls /etc/ssl/certs/https/")

    Use this (not bmc_duthost) for any command that must run on the BMC itself,
    since bmc_duthost connects to the SONiC management IP, not bmc_ip.
    """
    def _exec(cmd):
        return _bmc_ssh(bmc_ip, bmc_creds["password"], "'{}'".format(cmd))
    return _exec


@pytest.fixture(scope="module")
def bmc_duthost(duthosts, tbinfo):
    """Return the DUT host object for the BMC device (for SSH-based checks)."""
    dut_name = tbinfo["duts"][0]
    return duthosts[dut_name]


BMCWEB_CONTAINER = "redfish"


def _run(cmd, cwd=None):
    """Run a shell command locally inside the sonic-mgmt container."""
    subprocess.run(cmd, shell=True, check=True, cwd=cwd,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _bmc_ssh(bmc_ip, bmc_pass, cmd, bmc_user="admin"):
    """Run a command on the BMC itself via sshpass+ssh.

    Used for docker cp / docker exec operations that must run on bmc_ip,
    not on the SONiC management host that bmc_duthost connects to.
    Returns (stdout, stderr, returncode).
    """
    ssh_cmd = (
        "sshpass -p {pass_} ssh -o StrictHostKeyChecking=no {user}@{ip} {cmd}".format(
            pass_=bmc_pass, user=bmc_user, ip=bmc_ip, cmd=cmd)
    )
    result = subprocess.run(ssh_cmd, shell=True, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.decode().strip(), result.stderr.decode().strip(), result.returncode


def _bmc_scp(bmc_ip, bmc_pass, local_path, remote_path, bmc_user="admin"):
    """Copy a local file to the BMC via sshpass+scp."""
    scp_cmd = (
        "sshpass -p {pass_} scp -o StrictHostKeyChecking=no {src} {user}@{ip}:{dst}".format(
            pass_=bmc_pass, user=bmc_user, ip=bmc_ip,
            src=local_path, dst=remote_path)
    )
    subprocess.run(scp_cmd, shell=True, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _generate_ca_cert(cert_dir):
    """Generate CA certificate and key."""
    d = str(cert_dir)
    _run("openssl genrsa -out CA-key.pem 2048", cwd=d)
    _run("openssl req -new -x509 -days 3650 -key CA-key.pem -out CA-cert.pem "
         "-subj '/C=IN/ST=Karnataka/L=Bengaluru/O=Nexthop AI/OU=BMC/CN=Nexthop AI BMC CA'",
         cwd=d)


def _generate_server_cert(cert_dir, bmc_ip):
    """Generate server certificate signed by CA."""
    d = str(cert_dir)
    _run("openssl genrsa -out server-key.pem 2048", cwd=d)
    _run("openssl req -new -config openssl-server.cnf -key server-key.pem -out server.csr",
         cwd=d)
    _run("openssl x509 -req -extensions my_ext_section -extfile myext-server.cnf -days 730 "
         "-in server.csr -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial "
         "-out server-cert.pem", cwd=d)
    # Create combined PEM (cert + key for bmcweb)
    _run("cat server-cert.pem server-key.pem > server-combined.pem", cwd=d)


def _generate_client_cert(cert_dir, client_cn):
    """Generate client certificate signed by CA."""
    d = str(cert_dir)
    _run("openssl genrsa -out client-key.pem 2048", cwd=d)
    _run("openssl req -new -config openssl-client.cnf -key client-key.pem -out client.csr",
         cwd=d)
    _run("openssl x509 -req -extensions my_ext_section -extfile myext-client.cnf -days 730 "
         "-in client.csr -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial "
         "-out client-cert.pem", cwd=d)


def _write_openssl_configs(cert_dir, bmc_ip, client_cn):
    """Write OpenSSL config and extension files for server and client certs."""
    d = str(cert_dir)
    configs = {
        "openssl-server.cnf": textwrap.dedent("""\
            [ req ]
            default_bits = 2048
            prompt = no
            default_md = sha256
            distinguished_name = dn
            req_extensions = v3_req

            [ dn ]
            C = IN
            ST = Karnataka
            L = Bengaluru
            O = Nexthop AI
            OU = BMC
            CN = {ip}

            [ v3_req ]
            keyUsage = digitalSignature, keyAgreement
            extendedKeyUsage = serverAuth
            subjectAltName = @alt_names

            [ alt_names ]
            DNS.1 = {ip}
            IP.1 = {ip}
        """.format(ip=bmc_ip)),
        "myext-server.cnf": textwrap.dedent("""\
            [ my_ext_section ]
            keyUsage = digitalSignature, keyAgreement
            extendedKeyUsage = serverAuth
            authorityKeyIdentifier = keyid
            subjectKeyIdentifier = hash
            subjectAltName = @alt_names

            [ alt_names ]
            DNS.1 = {ip}
            IP.1 = {ip}
        """.format(ip=bmc_ip)),
        "openssl-client.cnf": textwrap.dedent("""\
            [ req ]
            default_bits = 2048
            prompt = no
            default_md = sha256
            distinguished_name = dn
            req_extensions = v3_req

            [ dn ]
            C = IN
            ST = Karnataka
            L = Bengaluru
            O = Nexthop AI
            OU = BMC
            CN = {cn}

            [ v3_req ]
            keyUsage = digitalSignature
            extendedKeyUsage = clientAuth
        """.format(cn=client_cn)),
        "myext-client.cnf": textwrap.dedent("""\
            [ my_ext_section ]
            keyUsage = digitalSignature
            extendedKeyUsage = clientAuth
            authorityKeyIdentifier = keyid
            subjectKeyIdentifier = hash
        """),
    }
    for fname, content in configs.items():
        with open(os.path.join(d, fname), "w") as f:
            f.write(content)


def _write_bmcweb_tls_config(cert_dir, tls_strict=True):
    """Write bmcweb_tls_config.json with the given TLSStrict setting."""
    config = {
        "auth_config": {
            "BasicAuth": True, "Cookie": True, "SessionToken": True,
            "XToken": True, "TLS": True, "TLSStrict": tls_strict,
            "MTLSCommonNameParseMode": 2,
        },
        "sessions": [],
        "revision": 1,
    }
    with open(os.path.join(str(cert_dir), "bmcweb_tls_config.json"), "w") as f:
        json.dump(config, f)


def _generate_certs(cert_dir, bmc_ip, client_cn):
    """Generate CA, server, and client certificates using openssl CLI."""
    _write_openssl_configs(cert_dir, bmc_ip, client_cn)
    _generate_ca_cert(cert_dir)
    _generate_server_cert(cert_dir, bmc_ip)
    _generate_client_cert(cert_dir, client_cn)
    _write_bmcweb_tls_config(cert_dir, tls_strict=True)


@pytest.fixture(scope="module")
def bmc_tls_certs(bmc_ip, bmc_creds, tmp_path_factory):
    """Generate TLS certificates, install them on the BMC, and clean up after the module.

    What this fixture does:
    1. Generates CA, server, and client certs inside the sonic-mgmt container using openssl.
    2. Copies the server cert, CA cert, and TLS config to the BMC via SSH.
    3. Installs the certs into the redfish container and enables TLSStrict in bmcweb.
    4. Yields a dict with paths to client-cert.pem, client-key.pem, and CA-cert.pem
       for use in requests(cert=..., verify=...) calls.
    5. On teardown: removes the CA cert from the BMC truststore, restores TLSStrict=false,
       and restarts bmcweb — leaving the BMC in Basic Auth mode as it was before.
    """
    cert_dir = tmp_path_factory.mktemp("bmc_certs")
    logger.info("Generating TLS certificates in {}".format(cert_dir))

    # --- Step 1: Generate certificates using openssl inside the container ---
    _generate_certs(cert_dir, bmc_ip, client_cn=bmc_creds["user"])

    server_combined = str(cert_dir / "server-combined.pem")
    ca_cert = str(cert_dir / "CA-cert.pem")
    client_cert = str(cert_dir / "client-cert.pem")
    client_key = str(cert_dir / "client-key.pem")
    tls_config = str(cert_dir / "bmcweb_tls_config.json")

    logger.info("Certificates generated. Installing on BMC {}".format(bmc_ip))

    bmc_pass = bmc_creds["password"]

    # --- Step 2: Copy files to BMC ---
    _bmc_scp(bmc_ip, bmc_pass, server_combined, "/tmp/server-combined.pem")
    _bmc_scp(bmc_ip, bmc_pass, ca_cert, "/tmp/CA-cert.pem")
    _bmc_scp(bmc_ip, bmc_pass, tls_config, "/tmp/bmcweb_tls_config.json")

    # --- Step 3: Install server certificate ---
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker cp /tmp/server-combined.pem {}:/etc/ssl/certs/https/server.pem'".format(
                 BMCWEB_CONTAINER))

    # --- Step 4: Install CA certificate into truststore ---
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker exec {} mkdir -p /etc/ssl/certs/authority'".format(BMCWEB_CONTAINER))
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker cp /tmp/CA-cert.pem {}:/etc/ssl/certs/authority/CA-cert.pem'".format(
                 BMCWEB_CONTAINER))

    # Compute the hash on the BMC host (where /tmp/CA-cert.pem is accessible),
    # then create the symlink inside the container using the explicit hash value.
    # This avoids $() being evaluated in the wrong shell context.
    ca_hash, _, _ = _bmc_ssh(bmc_ip, bmc_pass,
                              "'openssl x509 -hash -noout -in /tmp/CA-cert.pem'")
    logger.info("CA cert hash: {}".format(ca_hash))
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker exec {c} bash -c \"cd /etc/ssl/certs/authority && "
             "ln -sf CA-cert.pem {h}.0\"'".format(c=BMCWEB_CONTAINER, h=ca_hash))

    # --- Step 5: Enable TLSStrict and restart bmcweb ---
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker exec {} supervisorctl stop bmcweb'".format(BMCWEB_CONTAINER))
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker cp /tmp/bmcweb_tls_config.json {}:/bmcweb_persistent_data.json'".format(
                 BMCWEB_CONTAINER))
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker exec {} supervisorctl start bmcweb'".format(BMCWEB_CONTAINER))

    # Wait for bmcweb to be ready
    time.sleep(5)
    logger.info("TLSStrict enabled. BMC is now in mTLS mode.")

    yield {
        "cert": client_cert,
        "key": client_key,
        "ca": ca_cert,
        "dir": str(cert_dir),
    }

    # --- Teardown: restore BMC to Basic Auth mode ---
    logger.info("Cleaning up: removing certs from BMC and disabling TLSStrict")

    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker exec {} supervisorctl stop bmcweb'".format(BMCWEB_CONTAINER))

    # Remove CA cert and its hash symlink from truststore.
    # Compute hash on the host first (same reason as setup — avoid $() context issues).
    ca_hash_td, _, _ = _bmc_ssh(bmc_ip, bmc_pass,
                                 "'openssl x509 -hash -noout -in /tmp/CA-cert.pem 2>/dev/null'")
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker exec {c} bash -c \"rm -f /etc/ssl/certs/authority/CA-cert.pem "
             "/etc/ssl/certs/authority/{h}.0\"'".format(c=BMCWEB_CONTAINER, h=ca_hash_td))

    # Write TLSStrict=false config, copy to BMC, install into container
    _write_bmcweb_tls_config(cert_dir, tls_strict=False)
    restore_config = str(cert_dir / "bmcweb_tls_config.json")
    _bmc_scp(bmc_ip, bmc_pass, restore_config, "/tmp/bmcweb_tls_restore.json")
    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker cp /tmp/bmcweb_tls_restore.json {}:/bmcweb_persistent_data.json'".format(
                 BMCWEB_CONTAINER))

    _bmc_ssh(bmc_ip, bmc_pass,
             "'docker exec {} supervisorctl start bmcweb'".format(BMCWEB_CONTAINER))
    time.sleep(5)
    logger.info("BMC restored to Basic Auth mode.")
