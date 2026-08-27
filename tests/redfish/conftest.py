import json
import logging
import os
import subprocess
import textwrap
import time

import pytest

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import BMC_TEST_CA_NAME, RedfishClient

logger = logging.getLogger(__name__)

REDFISH_ROOT = "/redfish/v1"
BMCWEB_CONTAINER = "redfish"

BMCWEB_READY_TIMEOUT = 60
BMCWEB_READY_POLL = 2


@pytest.fixture(scope="session")
def bmc_duthost(duthosts, tbinfo):
    """Return the SonicHost for the BMC under test.

    In the bmc-* topologies the testbed's DUT is the BMC itself -- the
    ``<switch>-bmc`` inventory host, which runs SONiC -- so it is ``duts[0]``;
    the host-side switch is a separate device referenced via the ``bmc_host``
    field. Skips the test if the resolved DUT is not a BMC.
    """
    duthost = duthosts[tbinfo["duts"][0]]
    pyrequire(duthost.is_bmc(), "Redfish BMC tests require a BMC DUT (NetworkBmc)")
    return duthost


@pytest.fixture(scope="session")
def bmc_ip(bmc_duthost):
    """Return the BMC management IP, used to build Redfish https URLs."""
    return bmc_duthost.mgmt_ip


@pytest.fixture(scope="session")
def redfish_base_url(bmc_ip):
    return "https://{}{}".format(bmc_ip, REDFISH_ROOT)


@pytest.fixture(scope="session")
def redfish_client(bmc_ip, bmc_tls_certs):
    """Return a RedfishClient configured for mTLS client-certificate auth.

    Depends on bmc_tls_certs so the BMC is in TLSStrict mode and the client
    cert/key/CA paths are available before any Redfish request is issued.
    """
    return RedfishClient(
        bmc_ip,
        bmc_tls_certs["cert"],
        bmc_tls_certs["key"],
        bmc_tls_certs["ca"],
    )


@pytest.fixture(scope="session")
def bmc_exec(bmc_duthost):
    """Return a callable that runs a command on the BMC, returning (stdout, stderr, rc).

    Usage in tests:
        stdout, stderr, rc = bmc_exec("docker exec redfish ls /etc/ssl/certs/https/")

    A non-zero exit is reported in rc rather than raised, so callers can assert on it.
    """
    def _exec(cmd):
        res = bmc_duthost.shell(cmd, module_ignore_errors=True)
        return res["stdout"], res["stderr"], res["rc"]
    return _exec


def _safe(fn, *args, **kwargs):
    """Run a teardown step, log and swallow any exception so later steps still run."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.warning("Teardown step %s(%s) failed: %s",
                       getattr(fn, "__name__", fn), args, e)
        return None


def _run(cmd, cwd=None):
    """Run a shell command locally inside the sonic-mgmt container."""
    subprocess.run(cmd, shell=True, check=True, cwd=cwd,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _bmcweb_running(bmc_duthost):
    """True iff `supervisorctl status bmcweb` reports RUNNING in the redfish container.

    Used as the wait_until condition.
    """
    res = bmc_duthost.shell(
        "docker exec {} supervisorctl status bmcweb".format(BMCWEB_CONTAINER),
        module_ignore_errors=True,
    )
    return res["rc"] == 0 and "RUNNING" in res["stdout"]


def _generate_ca_cert(cert_dir):
    """Generate CA certificate and key."""
    d = str(cert_dir)
    _run("openssl genrsa -out CA-key.pem 2048", cwd=d)
    _run("openssl req -new -x509 -days 3650 -key CA-key.pem -out CA-cert.pem "
         "-subj '/O=SONiC/OU=BMC/CN={}'".format(BMC_TEST_CA_NAME),
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
            O = SONiC
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
            O = SONiC
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


@pytest.fixture(scope="session")
def bmc_clock_in_sync(bmc_duthost):
    """Skip cert tests early if BMC clock is skewed beyond the cert NotBefore window.

    Generated certs use the sonic-mgmt container's current time as NotBefore.
    If the BMC is behind that time, bmcweb sees the cert as not-yet-valid and
    fails the TLS handshake with SSLV3_ALERT_BAD_CERTIFICATE — surfacing as an
    opaque "bad certificate" error far from the actual cause.
    """
    container_now = int(time.time())
    bmc_now = int(bmc_duthost.shell("date -u +%s")["stdout"].strip())
    skew = container_now - bmc_now
    pyrequire(
        abs(skew) <= 60,
        "BMC clock is {}s {} sonic-mgmt container ({} vs {}). "
        "Sync clocks before running cert tests.".format(
            abs(skew),
            "behind" if skew > 0 else "ahead of",
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(container_now)),
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(bmc_now)),
        ),
    )


@pytest.fixture(scope="session")
def bmc_tls_certs(bmc_duthost, bmc_ip, bmc_clock_in_sync, tmp_path_factory):
    """Generate TLS certificates, install them on the BMC, and clean up at session end.

    What this fixture does:
    1. Generates CA, server, and client certs inside the sonic-mgmt container using openssl.
    2. Copies the server cert, CA cert, and TLS config to the BMC.
    3. Installs the certs into the redfish container and enables TLSStrict in bmcweb.
    4. Yields a dict with paths to client-cert.pem, client-key.pem, and CA-cert.pem
       for use in requests(cert=..., verify=...) calls.
    5. On teardown: removes the CA cert from the BMC truststore, restores TLSStrict=false,
       and restarts bmcweb — leaving the BMC in Basic Auth mode as it was before.
    """
    cert_dir = tmp_path_factory.mktemp("bmc_certs")
    logger.info("Generating TLS certificates in {}".format(cert_dir))

    # --- Step 1: Generate certificates using openssl inside the container ---
    # Client cert CN must match a bmcweb user; use the "bmcweb" user.
    _generate_certs(cert_dir, bmc_ip, client_cn="bmcweb")

    server_combined = str(cert_dir / "server-combined.pem")
    ca_cert = str(cert_dir / "CA-cert.pem")
    client_cert = str(cert_dir / "client-cert.pem")
    client_key = str(cert_dir / "client-key.pem")
    tls_config = str(cert_dir / "bmcweb_tls_config.json")

    logger.info("Certificates generated. Installing on BMC {}".format(bmc_ip))

    # --- Step 2: Copy files to BMC ---
    bmc_duthost.copy(src=server_combined, dest="/tmp/server-combined.pem")
    bmc_duthost.copy(src=ca_cert, dest="/tmp/CA-cert.pem")
    bmc_duthost.copy(src=tls_config, dest="/tmp/bmcweb_tls_config.json")

    # --- Step 3: Install server certificate (backup the original first) ---
    bmc_duthost.shell(
        "docker exec {} cp /etc/ssl/certs/https/server.pem "
        "/etc/ssl/certs/https/server.pem.bak".format(BMCWEB_CONTAINER))
    bmc_duthost.shell(
        "docker cp /tmp/server-combined.pem {}:/etc/ssl/certs/https/server.pem".format(
            BMCWEB_CONTAINER))

    # --- Step 4: Install CA certificate into truststore ---
    bmc_duthost.shell(
        "docker exec {} mkdir -p /etc/ssl/certs/authority".format(BMCWEB_CONTAINER))
    bmc_duthost.shell(
        "docker cp /tmp/CA-cert.pem {}:/etc/ssl/certs/authority/CA-cert.pem".format(
            BMCWEB_CONTAINER))

    # Compute the hash on the BMC host (where /tmp/CA-cert.pem is accessible),
    # then create the symlink inside the container using the explicit hash value.
    # This avoids $() being evaluated in the wrong shell context.
    ca_hash = bmc_duthost.shell(
        "openssl x509 -hash -noout -in /tmp/CA-cert.pem")["stdout"].strip()
    logger.info("CA cert hash: {}".format(ca_hash))
    bmc_duthost.shell(
        'docker exec {c} bash -c "cd /etc/ssl/certs/authority && '
        'ln -sf CA-cert.pem {h}.0"'.format(c=BMCWEB_CONTAINER, h=ca_hash))

    # --- Step 5: Enable TLSStrict and restart bmcweb ---
    bmc_duthost.shell(
        "docker exec {} supervisorctl stop bmcweb".format(BMCWEB_CONTAINER))
    bmc_duthost.shell(
        "docker cp /tmp/bmcweb_tls_config.json {}:/bmcweb_persistent_data.json".format(
            BMCWEB_CONTAINER))
    bmc_duthost.shell(
        "docker exec {} supervisorctl start bmcweb".format(BMCWEB_CONTAINER))

    # Wait for bmcweb to reach RUNNING again after the supervisorctl restart.
    pyrequire(
        wait_until(BMCWEB_READY_TIMEOUT, BMCWEB_READY_POLL, 0,
                   _bmcweb_running, bmc_duthost),
        "bmcweb did not reach RUNNING within {}s after enabling TLSStrict".format(
            BMCWEB_READY_TIMEOUT),
    )
    logger.info("TLSStrict enabled. BMC is now in mTLS mode.")

    yield {
        "cert": client_cert,
        "key": client_key,
        "ca": ca_cert,
        "dir": str(cert_dir),
    }

    # --- Teardown: restore BMC to Basic Auth mode ---
    # Each step is wrapped in _safe() so a failure in one step doesn't leave
    # the BMC half-configured (e.g. CA removed but server cert/TLSStrict not restored).
    logger.info("Cleaning up: removing certs from BMC and disabling TLSStrict")

    _safe(bmc_duthost.shell,
          "docker exec {} supervisorctl stop bmcweb".format(BMCWEB_CONTAINER),
          module_ignore_errors=True)

    # Remove CA cert and its hash symlink from truststore.
    # Compute hash on the host first (same reason as setup — avoid $() context issues).
    ca_hash_res = _safe(bmc_duthost.shell,
                        "openssl x509 -hash -noout -in /tmp/CA-cert.pem 2>/dev/null",
                        module_ignore_errors=True)
    if ca_hash_res and ca_hash_res["stdout"].strip():
        ca_hash_td = ca_hash_res["stdout"].strip()
        _safe(bmc_duthost.shell,
              'docker exec {c} bash -c "rm -f /etc/ssl/certs/authority/CA-cert.pem '
              '/etc/ssl/certs/authority/{h}.0"'.format(c=BMCWEB_CONTAINER, h=ca_hash_td),
              module_ignore_errors=True)

    # Restore the original server.pem from the backup taken at setup
    _safe(bmc_duthost.shell,
          'docker exec {c} bash -c "mv -f /etc/ssl/certs/https/server.pem.bak '
          '/etc/ssl/certs/https/server.pem"'.format(c=BMCWEB_CONTAINER),
          module_ignore_errors=True)

    # Write TLSStrict=false config, copy to BMC, install into container
    _safe(_write_bmcweb_tls_config, cert_dir, tls_strict=False)
    restore_config = str(cert_dir / "bmcweb_tls_config.json")
    _safe(bmc_duthost.copy, src=restore_config, dest="/tmp/bmcweb_tls_restore.json")
    _safe(bmc_duthost.shell,
          "docker cp /tmp/bmcweb_tls_restore.json {}:/bmcweb_persistent_data.json".format(
              BMCWEB_CONTAINER),
          module_ignore_errors=True)

    _safe(bmc_duthost.shell,
          "docker exec {} supervisorctl start bmcweb".format(BMCWEB_CONTAINER),
          module_ignore_errors=True)

    # Wait for RUNNING again.
    if not wait_until(BMCWEB_READY_TIMEOUT, BMCWEB_READY_POLL, 0,
                      _bmcweb_running, bmc_duthost):
        logger.warning("bmcweb did not reach RUNNING within %ds during teardown",
                       BMCWEB_READY_TIMEOUT)
    logger.info("BMC restored to Basic Auth mode.")
