"""
Tests for Redfish certificate-based (mTLS) authentication.

The bmc_tls_certs fixture (in conftest.py) runs before any test in this module:
  - Generates CA, server, and client certificates locally
  - Installs them on the BMC and enables TLSStrict in bmcweb
  - Yields the client cert/key/CA paths for use in requests
  - On teardown: removes the certs from BMC and restores Basic Auth mode
"""
import logging
import ssl
import pytest
import requests
import subprocess

from tests.common.helpers.assertions import pytest_assert
from tests.redfish.redfish_utils import BMC_TEST_CA_NAME, assert_status_ok, redfish_url

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

SERVICE_ROOT_PATH = "/redfish/v1"
UPDATE_SERVICE_PATH = "{}/UpdateService".format(SERVICE_ROOT_PATH)


class TestRedfishCertAuth:

    def test_cert_installed_on_bmc(self, bmc_tls_certs, bmc_exec):
        """
        Verify certs are installed on the BMC.

        Checks that:
        - The server cert exists at the expected container path
        - The CA cert is present in the truststore
        - bmcweb is running (supervisorctl shows RUNNING)
        """
        # Server cert — verify it was signed by our CA (not the default self-signed)
        stdout, _, _ = bmc_exec(
            "docker exec redfish openssl x509 -in /etc/ssl/certs/https/server.pem -noout -issuer"
        )
        pytest_assert(
            BMC_TEST_CA_NAME in stdout,
            "Server cert issuer must be our CA, got: {}".format(stdout)
        )

        # CA cert in truststore — verify subject matches our CA
        stdout, _, _ = bmc_exec(
            "docker exec redfish openssl x509 -in /etc/ssl/certs/authority/CA-cert.pem -noout -subject"
        )
        pytest_assert(
            BMC_TEST_CA_NAME in stdout,
            "CA cert subject must contain our CA name, got: {}".format(stdout)
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
        Valid client certificate is accepted.

        GET /redfish/v1 with the generated client cert + key verified by our CA.
        Must return HTTP 200.
        """
        response = requests.get(
            redfish_url(bmc_ip, SERVICE_ROOT_PATH),
            cert=(bmc_tls_certs["cert"], bmc_tls_certs["key"]),
            verify=bmc_tls_certs["ca"],
            timeout=30,
        )
        logger.info("GET {} (with cert) -> {}".format(SERVICE_ROOT_PATH, response.status_code))
        assert_status_ok(response, SERVICE_ROOT_PATH)

    def test_cert_auth_on_authenticated_endpoint(self, bmc_ip, bmc_tls_certs):
        """
        Certificate-based auth works for an authenticated endpoint.

        GET /redfish/v1/UpdateService using only client cert (no Basic Auth).
        Must return HTTP 200 with valid UpdateService data.
        """
        response = requests.get(
            redfish_url(bmc_ip, UPDATE_SERVICE_PATH),
            cert=(bmc_tls_certs["cert"], bmc_tls_certs["key"]),
            verify=bmc_tls_certs["ca"],
            timeout=30,
        )
        logger.info("GET {} (with cert) -> {}".format(
            UPDATE_SERVICE_PATH, response.status_code))

        assert_status_ok(response, UPDATE_SERVICE_PATH)
        pytest_assert(
            "@odata.id" in response.json(),
            "Response missing @odata.id"
        )

    def test_no_cert_rejected(self, bmc_ip, bmc_tls_certs):
        """
        Missing certificate is rejected when TLSStrict=true.

        GET /redfish/v1 with no client cert must fail with a TLS error
        (TLSV13_ALERT_CERTIFICATE_REQUIRED) — not HTTP 200.
        """
        tls_error_raised = False
        try:
            response = requests.get(
                redfish_url(bmc_ip, SERVICE_ROOT_PATH),
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
        Certificate signed by an untrusted CA is rejected.

        Generates a fresh self-signed cert not signed by the BMC's trusted CA.
        The request must fail with an SSL error or HTTP 401/403.
        """

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
                redfish_url(bmc_ip, SERVICE_ROOT_PATH),
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
