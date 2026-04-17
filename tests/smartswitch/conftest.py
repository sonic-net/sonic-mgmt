"""
Pytest fixtures for SmartSwitch tests.

Provides gNOI client with dsmsroot-signed TLS certificates for NPU gRPC
(port 50052). SmartSwitch devices use dsmsroot CA for client auth, not gnmiCA.

Runs grpcurl on the DUT (NPU) via localhost - PTF->NPU gRPC often times out
in lab topologies, but DUT->127.0.0.1 works.
"""
import logging
import pytest

logger = logging.getLogger(__name__)

# SmartSwitch gNOI uses port 50052 (TLS) on NPU
SS_GNOI_PORT = 50052
SS_DUT_CERT_DIR = "/tmp/ss_gnoi_certs"


def _create_dsmsroot_signed_client_certs(duthost):
    """
    Create dsmsroot-signed client cert on DUT (kept on DUT for local grpcurl).

    SmartSwitch NPU gNOI server (port 50052) uses dsmsroot.cer as CA to verify
    client certs. gnmiCA-signed certs are rejected.
    """
    duthost.shell(f"mkdir -p {SS_DUT_CERT_DIR}")

    # 1. Create client key
    duthost.shell(f"openssl genrsa -out {SS_DUT_CERT_DIR}/client.key 2048")
    # 2. Create CSR
    duthost.shell(
        f"openssl req -new -key {SS_DUT_CERT_DIR}/client.key "
        f"-out {SS_DUT_CERT_DIR}/client.csr -subj '/CN=grpc.client.sonic'"
    )
    # 3. Sign with dsmsroot (-set_serial avoids serial file permission issues)
    duthost.shell(
        f"sudo openssl x509 -req -in {SS_DUT_CERT_DIR}/client.csr "
        f"-CA /etc/sonic/telemetry/dsmsroot.cer "
        f"-CAkey /etc/sonic/telemetry/dsmsroot.key "
        f"-set_serial 1 -out {SS_DUT_CERT_DIR}/client.crt -days 365"
    )

    return (
        f"{SS_DUT_CERT_DIR}/client.crt",
        f"{SS_DUT_CERT_DIR}/client.key",
    )


@pytest.fixture
def ptf_gnoi(ptfhost, duthost):
    """
    gNOI client for SmartSwitch with dsmsroot-signed TLS certs.

    Runs grpcurl on the DUT (NPU) connecting to 127.0.0.1:50052 - avoids
    PTF->NPU network timeouts. Uses dsmsroot-signed client certs.
    """
    from tests.common.ptf_grpc import PtfGrpc
    from tests.common.ptf_gnoi import PtfGnoi

    dut_cert, dut_key = _create_dsmsroot_signed_client_certs(duthost)

    # Run grpcurl on DUT via localhost (avoids PTF->NPU connectivity issues)
    target = f"127.0.0.1:{SS_GNOI_PORT}"
    client = PtfGrpc(
        duthost,  # Run commands on DUT, not PTF
        target,
        plaintext=False,
        insecure=True,
    )
    client.configure_tls_certificates(
        ca_cert="",
        client_cert=dut_cert,
        client_key=dut_key,
    )
    client.configure_timeout(30.0)

    gnoi_client = PtfGnoi(client)
    logger.info(
        "Created SmartSwitch gNOI client: target=%s (on DUT), cert=%s",
        target,
        dut_cert,
    )
    yield gnoi_client

    # Remove the client CN registered in CONFIG_DB during setup
    duthost.shell('sonic-db-cli CONFIG_DB del "GNMI_CLIENT_CERT|grpc.client.sonic"',
                  module_ignore_errors=True)

    # Remove client certs from DUT — private key was world-readable (644) during the test
    duthost.shell(f"rm -rf {SS_DUT_CERT_DIR}", module_ignore_errors=True)
    logger.info("Removed client cert directory %s", SS_DUT_CERT_DIR)
