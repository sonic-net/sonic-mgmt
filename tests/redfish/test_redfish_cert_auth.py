"""
Tests for Redfish certificate-based (mTLS) authentication.

The bmc_tls_certs fixture (in conftest.py) runs before any test in this module:
  - Generates CA, server, and client certificates locally
  - Installs them on the BMC and enables TLSStrict in bmcweb
  - Yields the client cert/key/CA paths for use in requests
  - On teardown: removes the certs from BMC and restores Basic Auth mode

Test Cases:
  A — Valid client cert is accepted
  B — Cert auth works for an authenticated endpoint
  C — No client cert is rejected (TLSStrict=true)
  D — Wrong CA (untrusted cert) is rejected
"""
import logging
import ssl
import pytest
import requests
import urllib3

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('bmc-dual-mgmt', 'bmc-shared-mgmt'),
]


class TestRedfishCertAuth:

    def test_cert_installed_on_bmc(self, bmc_tls_certs, bmc_exec):
        """
        Test Case — Verify certs are installed on the BMC before running auth tests.

        Checks that:
        - The server cert exists at the expected container path
        - The CA cert is present in the truststore
        - bmcweb is running (supervisorctl shows RUNNING)
        """
        # Server cert
        stdout, _, _ = bmc_exec(
            "docker exec redfish test -f /etc/ssl/certs/https/server.pem && echo exists"
        )
        pytest_assert(
            "exists" in stdout,
            "Server cert not found at redfish:/etc/ssl/certs/https/server.pem"
        )

        # CA cert in truststore
        stdout, _, _ = bmc_exec(
            "docker exec redfish test -f /etc/ssl/certs/authority/CA-cert.pem && echo exists"
        )
        pytest_assert(
            "exists" in stdout,
            "CA cert not found at redfish:/etc/ssl/certs/authority/CA-cert.pem"
        )

        # bmcweb is running
        stdout, _, _ = bmc_exec("docker exec redfish supervisorctl status bmcweb")
        pytest_assert(
            "RUNNING" in stdout,
            "bmcweb is not running after cert install: {}".format(stdout)
        )
        logger.info("All certs installed and bmcweb is RUNNING")

    def test_valid_cert_accepted(self, bmc_ip, bmc_tls_certs):
        """
        Test Case A — Valid client certificate is accepted.

        GET /redfish/v1 with the generated client cert + key verified by our CA.
        Must return HTTP 200.
        """
        response = requests.get(
            "https://{}/redfish/v1".format(bmc_ip),
            cert=(bmc_tls_certs["cert"], bmc_tls_certs["key"]),
            verify=bmc_tls_certs["ca"],
            timeout=30,
        )
        logger.info("GET /redfish/v1 (with cert) -> {}".format(response.status_code))

        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 with valid client cert, got: {}".format(response.status_code)
        )

    def test_cert_auth_on_authenticated_endpoint(self, bmc_ip, bmc_tls_certs):
        """
        Test Case B — Certificate-based auth works for an authenticated endpoint.

        GET /redfish/v1/Chassis/chassis using only client cert (no Basic Auth).
        Must return HTTP 200 with valid chassis data.
        """
        response = requests.get(
            "https://{}/redfish/v1/Chassis/chassis".format(bmc_ip),
            cert=(bmc_tls_certs["cert"], bmc_tls_certs["key"]),
            verify=bmc_tls_certs["ca"],
            timeout=30,
        )
        logger.info("GET /redfish/v1/Chassis/chassis (with cert) -> {}".format(
            response.status_code))

        pytest_assert(
            response.status_code == 200,
            "Expected HTTP 200 with valid client cert on authenticated endpoint, got: {}".format(
                response.status_code)
        )

        body = response.json()
        pytest_assert(
            "@odata.id" in body,
            "Response missing @odata.id: {}".format(body)
        )

    def test_no_cert_rejected(self, bmc_ip, bmc_tls_certs):
        """
        Test Case C — Missing certificate is rejected when TLSStrict=true.

        GET /redfish/v1 with no client cert must fail with a TLS error
        (TLSV13_ALERT_CERTIFICATE_REQUIRED) — not HTTP 200.
        """
        tls_error_raised = False
        try:
            response = requests.get(
                "https://{}/redfish/v1".format(bmc_ip),
                verify=bmc_tls_certs["ca"],
                timeout=30,
            )
            # If we get here, the BMC did not require a cert — check it's at least not 200
            logger.warning("No TLS error raised — BMC may not be enforcing TLSStrict. "
                           "HTTP status: {}".format(response.status_code))
            pytest_assert(
                response.status_code in (401, 403),
                "Expected TLS error or HTTP 401/403 without client cert, got: {}".format(
                    response.status_code)
            )
        except (requests.exceptions.SSLError, ssl.SSLError):
            tls_error_raised = True
            logger.info("TLS error raised as expected when no client cert is provided")

        if not tls_error_raised:
            logger.info("BMC returned HTTP error (401/403) instead of TLS error — both are valid")

    def test_wrong_ca_rejected(self, bmc_ip, bmc_tls_certs, tmp_path):
        """
        Test Case D — Certificate signed by an untrusted CA is rejected.

        Generates a fresh self-signed cert not signed by the BMC's trusted CA.
        The request must fail with an SSL error or HTTP 401/403.
        """
        import subprocess

        # Generate an untrusted self-signed cert on the fly
        untrusted_key = str(tmp_path / "untrusted-key.pem")
        untrusted_cert = str(tmp_path / "untrusted-cert.pem")

        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", untrusted_key,
            "-out", untrusted_cert,
            "-days", "1",
            "-subj", "/CN=untrusted-client",
        ], check=True, capture_output=True)

        tls_error_raised = False
        try:
            response = requests.get(
                "https://{}/redfish/v1".format(bmc_ip),
                cert=(untrusted_cert, untrusted_key),
                verify=bmc_tls_certs["ca"],
                timeout=30,
            )
            logger.warning("No TLS error raised for untrusted cert — HTTP status: {}".format(
                response.status_code))
            pytest_assert(
                response.status_code in (401, 403),
                "Expected TLS error or HTTP 401/403 for untrusted cert, got: {}".format(
                    response.status_code)
            )
        except (requests.exceptions.SSLError, ssl.SSLError):
            tls_error_raised = True
            logger.info("TLS error raised as expected for untrusted client cert")

        if not tls_error_raised:
            logger.info("BMC returned HTTP error (401/403) for untrusted cert — both are valid")
