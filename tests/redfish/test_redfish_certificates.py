"""
Tests for the Redfish certificate provisioning pipeline and mTLS access.

The bmc_tls_certs fixture (conftest.py) provisions the BMC before any test
here: it delivers a generated CA, server and client certificate to the paths
configured in CONFIG_DB (REDFISH|certs), the way a provisioning agent does,
and waits for the device to report the set as applied. On teardown it returns
the device to the state it arrived in.

Groups:
  - Provisioning, auth and common name validation: what the pipeline stages
    and which clients are then allowed in.
  - Restart, fail closed and container recreate: a provisioned device never
    falls back to self-signed.
  - Negative input and first install mismatch: bad input must never cost the
    endpoint or mark the device provisioned.
  - Watcher resilience and observability: keeping up with change, and saying
    what state the device is in.
  - Bootstrap: what an unprovisioned device serves.
  - Configuration: delivery paths and published port come from CONFIG_DB.
  - CA rotation: how access is revoked.

Classes that disturb the device restore it before finishing, through a
restore fixture, so they can run in any order.
"""
import logging
import ssl
import subprocess
import time

import pytest
import requests

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    BMCWEB_CONTAINER,
    bmcweb_pid,
    build_cert_chain,
    CA_CERT_NAME,
    cert_status,
    CLIENT_CERT_NAME,
    CLIENT_CN,
    CLIENT_KEY_NAME,
    CREDENTIALS_DIR,
    corrupt_delivered_file,
    corrupt_staged_cert,
    db_set,
    DEFAULT_PORT,
    deliver_certs,
    deliver_single_file,
    DELIVERED_CA_CRT,
    DELIVERED_SERVER_CRT,
    DELIVERED_SERVER_KEY,
    DELIVERY_DIR,
    GUARD_RESTAGE_LOG,
    issue_client_cert,
    issue_server_cert,
    listening_port,
    logged_since,
    PRIVILEGED_PATH,
    program_state,
    PROVISIONED_MARKER,
    recreate_container,
    REDFISH_CERTS_TABLE,
    REDFISH_CONFIG_TABLE,
    remove_delivered_certs,
    remove_staged_certs,
    restore_delivered_certs,
    rotate_server_cert,
    served_serial,
    SERVER_CERT_NAME,
    SERVER_KEY_NAME,
    set_trusted_cnames,
    STAGED_CA_CRT,
    STAGED_SERVER_PEM,
    STAGING_POLL,
    STAGING_STAMP,
    supervisor,
    syslog_line_count,
    unprovision,
    wait_for_program,
    wait_for_staging,
)
from tests.redfish.redfish_utils import assert_status_ok, redfish_url

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

SERVICE_ROOT_PATH = "/redfish/v1"
UPDATE_SERVICE_PATH = "{}/UpdateService".format(SERVICE_ROOT_PATH)
FIRMWARE_INVENTORY_PATH = "{}/FirmwareInventory".format(UPDATE_SERVICE_PATH)
ALTERNATE_PORT = 8443
WATCHER = "credentials-watcher"

# One reconcile interval plus a settle margin, for the cases that assert
# nothing happened rather than waiting for something to happen.
RECONCILE_WINDOW = 90


def mtls_get(bmc_ip, certs, path, port=None):
    """Issue an mTLS Redfish GET with the provisioned client credentials.

    Addresses the session's port unless a test asks for another one.
    """
    return requests.get(
        redfish_url(bmc_ip, path, certs["port"] if port is None else port),
        cert=(certs["cert"], certs["key"]),
        verify=certs["ca"],
        timeout=30,
    )


def in_container(cmd):
    """Wrap a command so it runs inside the redfish container."""
    return "docker exec {} {}".format(BMCWEB_CONTAINER, cmd)


def staged_is_self_signed(bmc_exec):
    """True when the staged server certificate is its own issuer."""
    issuer, _, _ = bmc_exec(in_container(
        "openssl x509 -noout -issuer -in {}".format(STAGED_SERVER_PEM)))
    subject, _, _ = bmc_exec(in_container(
        "openssl x509 -noout -subject -in {}".format(STAGED_SERVER_PEM)))
    return issuer.split("=", 1)[-1] == subject.split("=", 1)[-1]


def local_serial(path):
    """Serial number of a certificate file on the test runner."""
    out = subprocess.run(
        ["openssl", "x509", "-noout", "-serial", "-in", path],
        check=True, capture_output=True, text=True).stdout
    return out.strip().split("=")[-1]


def restore_session_port(duthost, port):
    """Put the Redfish port back to the one the session started on."""
    if port == DEFAULT_PORT:
        duthost.shell('sonic-db-cli CONFIG_DB hdel "{}" port'.format(REDFISH_CONFIG_TABLE),
                      module_ignore_errors=True)
    else:
        db_set(duthost, "CONFIG_DB", REDFISH_CONFIG_TABLE, port=str(port))


def restart_service(duthost):
    """Restart the redfish service, the way an operator applies a port change."""
    duthost.shell("systemctl reset-failed redfish.service", module_ignore_errors=True)
    duthost.shell("systemctl restart redfish", module_ignore_errors=True)
    return wait_for_program(duthost, "bmcweb", "RUNNING")


def endpoint_is_down(bmc_ip, port):
    """True when nothing answers on the Redfish port.

    A device that has failed closed refuses the connection. It must never
    answer with a self-signed certificate instead, which is what this
    distinguishes: any completed TLS handshake here would be a failure.
    """
    try:
        requests.get(redfish_url(bmc_ip, SERVICE_ROOT_PATH, port), verify=False, timeout=5)
    except requests.exceptions.SSLError:
        return False        # a handshake happened: something is serving
    except requests.exceptions.RequestException:
        return True         # refused / unreachable, as expected
    return False


# sonic-dbus-bridge logs every refused common name at ERR. These tests refuse
# names on purpose, so those lines are expected rather than a fault.
EXPECTED_REFUSALS = [
    r".*ERR redfish#sonic-dbus-bridge.*GetUserInfo: no trusted common names configured; refusing.*",
    r".*ERR redfish#sonic-dbus-bridge.*GetUserInfo: common name .* matches none of the trusted.*",
]


@pytest.fixture(autouse=True)
def ignore_expected_refusals(loganalyzer):
    """Keep the deliberate common name refusals out of the log analysis."""
    if loganalyzer:
        for hostname in loganalyzer.keys():
            loganalyzer[hostname].ignore_regex.extend(EXPECTED_REFUSALS)


@pytest.fixture
def good_certs_after_test(bmc_duthost, bmc_tls_certs):
    """Put a valid trio back and wait for it to be applied."""
    yield
    restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
    wait_for_staging(bmc_duthost)


@pytest.fixture
def healthy_watcher_after_test(bmc_duthost, bmc_tls_certs):
    """Leave the watcher running and the device in sync."""
    yield
    if program_state(bmc_duthost, WATCHER) != "RUNNING":
        supervisor(bmc_duthost, "start", WATCHER)
        wait_for_program(bmc_duthost, WATCHER, "RUNNING")
    restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
    wait_for_staging(bmc_duthost)


@pytest.fixture
def provisioned_on_session_port(bmc_duthost, bmc_tls_certs):
    """Leave the device provisioned, in sync, on the port the session started on.

    The trusted names are put back too: a test that clears REDFISH|certs takes
    client_crt_cname with it, and the restart below is what applies it.
    """
    yield
    restore_session_port(bmc_duthost, bmc_tls_certs["port"])
    db_set(bmc_duthost, "CONFIG_DB", REDFISH_CERTS_TABLE,
           server_crt=DELIVERED_SERVER_CRT,
           server_key=DELIVERED_SERVER_KEY,
           ca_crt=DELIVERED_CA_CRT,
           client_crt_cname=CLIENT_CN)
    restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
    restart_service(bmc_duthost)
    wait_for_staging(bmc_duthost)


@pytest.fixture
def provisioned_after_test(bmc_duthost, bmc_tls_certs):
    """Restore the provisioned, serving state after a destructive case."""
    yield
    logger.info("Restoring the provisioned state")
    restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
    recreate_container(bmc_duthost)
    wait_for_program(bmc_duthost, "bmcweb", "RUNNING")
    wait_for_staging(bmc_duthost)


class TestRedfishCertProvisioning:

    def test_delivered_certs_are_staged(self, bmc_duthost, bmc_tls_certs, bmc_exec):
        """The pipeline reshapes the delivered files into what bmcweb reads."""
        # server.pem carries both the certificate and its key
        stdout, _, _ = bmc_exec(in_container(
            "grep -c BEGIN {}".format(STAGED_SERVER_PEM)))
        pytest_assert(stdout.strip() == "2",
                      "server.pem must hold cert and key, found {} PEM blocks".format(stdout))

        # and it is the certificate we delivered, not a self-signed one
        pytest_assert(
            served_serial(bmc_duthost) == local_serial(bmc_tls_certs["server_crt"]),
            "Served certificate is not the one delivered")

        pytest_assert(not staged_is_self_signed(bmc_exec), "Staged certificate is self-signed")

        # CA truststore, with the hash symlink OpenSSL needs for lookup
        ca_hash, _, _ = bmc_exec(in_container(
            "openssl x509 -hash -noout -in {}".format(STAGED_CA_CRT)))
        _, _, rc = bmc_exec(in_container(
            "test -L /etc/ssl/certs/authority/{}.0".format(ca_hash.strip())))
        pytest_assert(rc == 0,
                      "CA hash symlink {}.0 missing from the truststore".format(ca_hash.strip()))

        stdout, _, _ = bmc_exec(in_container("supervisorctl status bmcweb"))
        pytest_assert("RUNNING" in stdout,
                      "bmcweb is not running after provisioning: {}".format(stdout))

    def test_provisioned_state_is_recorded(self, bmc_tls_certs, bmc_exec):
        """Provisioning writes the marker and the staging stamp on the host mount."""
        stdout, _, rc = bmc_exec("cat {}".format(PROVISIONED_MARKER))
        pytest_assert(rc == 0, "Provisioned marker was not written")
        pytest_assert("provisioned_at=" in stdout,
                      "Marker carries no timestamp: {}".format(stdout))
        pytest_assert("Do not delete" in stdout,
                      "Marker should explain itself to an operator: {}".format(stdout))

        _, _, rc = bmc_exec("test -s {}".format(STAGING_STAMP))
        pytest_assert(rc == 0, "Staging stamp was not written")

    def test_status_is_published(self, bmc_duthost, bmc_tls_certs):
        """STATE_DB reports the provisioning result."""
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "true",
                      "in_sync should be true after successful provisioning")
        pytest_assert(cert_status(bmc_duthost, "mtls_enforced") == "true",
                      "mtls_enforced should be true once the CA is staged")
        pytest_assert(cert_status(bmc_duthost, "last_error") == "",
                      "last_error should be empty while in sync")
        pytest_assert(
            cert_status(bmc_duthost, "source_fingerprint") ==
            cert_status(bmc_duthost, "applied_fingerprint"),
            "Source and applied fingerprints should match while in sync")
        pytest_assert(cert_status(bmc_duthost, "served_serial") != "",
                      "served_serial should name the certificate being served")

    def test_rotation_is_picked_up(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """A rotated certificate is staged and served with no operator action."""
        before = served_serial(bmc_duthost)

        # Re-issue the server certificate from the same CA, then deliver it.
        rotate_server_cert(bmc_tls_certs["generator"], bmc_tls_certs["dir"])
        deliver_certs(bmc_duthost, bmc_tls_certs["dir"])

        pytest_assert(wait_for_staging(bmc_duthost),
                      "Rotation was not applied; last_error={}".format(
                          cert_status(bmc_duthost, "last_error")))

        after = served_serial(bmc_duthost)
        pytest_assert(after != before,
                      "Served serial did not change after rotation: {}".format(after))
        pytest_assert(cert_status(bmc_duthost, "served_serial") == after,
                      "STATE_DB served_serial does not match the served certificate")

        # mTLS still works, with the same CA and client certificate
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, SERVICE_ROOT_PATH),
                         SERVICE_ROOT_PATH)

    def test_mismatched_pair_is_not_staged(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """A certificate delivered without its matching key is never staged.

        This is the mid-rotation window: an agent replaces the certificate and
        the key as two separate operations, and the pipeline must not stage a
        pair that does not belong together.
        """
        before = served_serial(bmc_duthost)
        pid_before = bmcweb_pid(bmc_duthost)

        # Issue a new pair but deliver only the certificate half.
        rotate_server_cert(bmc_tls_certs["generator"], bmc_tls_certs["dir"])
        bmc_duthost.copy(src=str(bmc_tls_certs["dir"] / SERVER_CERT_NAME),
                         dest="/tmp/half-rotation.cer")
        bmc_duthost.shell("mv -f /tmp/half-rotation.cer {}".format(DELIVERED_SERVER_CRT))

        # Give the watcher more than one reconcile interval to look at it.
        time.sleep(RECONCILE_WINDOW)

        pytest_assert(served_serial(bmc_duthost) == before,
                      "Mismatched pair was staged: serial changed from {}".format(before))
        pytest_assert(bmcweb_pid(bmc_duthost) == pid_before,
                      "bmcweb was bounced for a half-delivered rotation")
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "A half-delivered rotation should report out of sync")

        # The endpoint keeps working on the previously staged certificate.
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, SERVICE_ROOT_PATH),
                         SERVICE_ROOT_PATH)

        # Completing the rotation lets it land.
        bmc_duthost.copy(src=str(bmc_tls_certs["dir"] / SERVER_KEY_NAME),
                         dest="/tmp/half-rotation.key")
        bmc_duthost.shell("mv -f /tmp/half-rotation.key {}".format(DELIVERED_SERVER_KEY))

        pytest_assert(wait_for_staging(bmc_duthost),
                      "Completed rotation was not applied")
        pytest_assert(served_serial(bmc_duthost) != before,
                      "Completed rotation did not change the served certificate")


class TestRedfishCertAuth:

    def test_valid_cert_accepted(self, bmc_ip, bmc_tls_certs):
        """A client certificate issued by the provisioned CA is accepted."""
        response = mtls_get(bmc_ip, bmc_tls_certs, SERVICE_ROOT_PATH)
        logger.info("GET {} (with cert) -> {}".format(
            SERVICE_ROOT_PATH, response.status_code))
        assert_status_ok(response, SERVICE_ROOT_PATH)

    def test_cert_auth_on_authenticated_endpoint(self, bmc_ip, bmc_tls_certs):
        """The certificate alone authorises an authenticated endpoint.

        There is no local user or password involved: the certificate is the
        only credential.
        """
        response = mtls_get(bmc_ip, bmc_tls_certs, UPDATE_SERVICE_PATH)
        logger.info("GET {} (with cert) -> {}".format(
            UPDATE_SERVICE_PATH, response.status_code))
        assert_status_ok(response, UPDATE_SERVICE_PATH)
        pytest_assert("@odata.id" in response.json(), "Response missing @odata.id")

    def test_service_root_readable_without_a_certificate(self, bmc_ip, bmc_tls_certs):
        """The service root answers a client that presents no certificate.

        DSP0266 13.3.2 requires the service root to be reachable without
        authentication, so that a client can identify the device and find the
        service before it has credentials. Refusing the handshake outright
        would close it.
        """
        response = requests.get(
            redfish_url(bmc_ip, SERVICE_ROOT_PATH, bmc_tls_certs["port"]),
            verify=bmc_tls_certs["ca"],
            timeout=30,
        )
        assert_status_ok(response, SERVICE_ROOT_PATH)
        pytest_assert("@odata.id" in response.json(),
                      "Service root did not return a Redfish body")

    def test_privileged_path_refused_without_a_certificate(self, bmc_ip, bmc_tls_certs):
        """Everything beyond the exempt resources needs a certificate.

        The certificate is the only credential that can succeed: the container
        carries no local accounts, so the password and session methods have
        nothing behind them.
        """
        response = requests.get(
            redfish_url(bmc_ip, PRIVILEGED_PATH, bmc_tls_certs["port"]),
            verify=bmc_tls_certs["ca"],
            timeout=30,
        )
        pytest_assert(
            response.status_code in (401, 403),
            "Expected 401 or 403 on {} without a client certificate, got {}".format(
                PRIVILEGED_PATH, response.status_code))

    def test_wrong_ca_rejected(self, bmc_ip, bmc_tls_certs, tmp_path):
        """A certificate signed by an untrusted CA does not authenticate.

        bmcweb completes the handshake and treats the client as having no
        certificate, so this is checked on a resource that needs a login.
        """
        build_cert_chain(tmp_path, bmc_ip, client_cn="untrusted-client",
                         ca_cn="Untrusted CA")
        untrusted_cert = str(tmp_path / CLIENT_CERT_NAME)
        untrusted_key = str(tmp_path / CLIENT_KEY_NAME)

        try:
            response = requests.get(
                redfish_url(bmc_ip, FIRMWARE_INVENTORY_PATH, bmc_tls_certs["port"]),
                cert=(untrusted_cert, untrusted_key),
                verify=bmc_tls_certs["ca"],
                timeout=30,
            )
            pytest_assert(
                response.status_code in (401, 403),
                "Expected 401 or 403 on {} for an untrusted certificate, got {}".format(
                    FIRMWARE_INVENTORY_PATH, response.status_code))
        except (requests.exceptions.SSLError, ssl.SSLError):
            logger.info("TLS handshake rejected for an untrusted client certificate, as expected")


class TestRedfishCommonNameValidation:
    """The trusted common name list decides which clients are authorized.

    Every case checks a privileged path rather than the service root: Redfish
    defines ServiceRoot as requiring no privileges, so it answers 200 even for
    a client whose common name was refused, and would hide the difference.
    """

    @pytest.fixture(scope="class", autouse=True)
    def restore_trusted_list(self, bmc_duthost):
        """Leave the device accepting the fixture's client certificate again.

        Every test sets its own list first, so restoring once after the class
        is enough.
        """
        yield
        set_trusted_cnames(bmc_duthost, CLIENT_CN)

    def test_unset_list_refuses_every_common_name(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """With no list configured, no certificate is trusted, even from the staged CA.

        An unset list fails closed, as the SONiC REST API server does with its own
        trusted common names, so a device is not open before the list is pushed.
        """
        pytest_assert(set_trusted_cnames(bmc_duthost, None),
                      "sonic-dbus-bridge did not come back after clearing the list")
        cert, key = issue_client_cert(bmc_tls_certs["generator"], bmc_tls_certs["dir"],
                                      "anything-at-all", "anycn")
        response = requests.get(
            redfish_url(bmc_ip, PRIVILEGED_PATH, bmc_tls_certs["port"]),
            cert=(cert, key), verify=bmc_tls_certs["ca"], timeout=30)
        pytest_assert(response.status_code == 403,
                      "With no trusted common names configured, a certificate must be "
                      "refused with 403, got {}".format(response.status_code))

    def test_exact_match_is_enforced(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """A configured list admits the listed name and refuses everything else."""
        pytest_assert(set_trusted_cnames(bmc_duthost, CLIENT_CN),
                      "sonic-dbus-bridge did not come back after configuring the list")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)

        pytest_assert(set_trusted_cnames(bmc_duthost, "someone-else"),
                      "sonic-dbus-bridge did not come back after configuring the list")
        response = mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH)
        pytest_assert(response.status_code == 403,
                      "A certificate whose common name is not trusted must be refused "
                      "with 403, got {}".format(response.status_code))

    def test_wildcard_matches_subdomains_only(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """*.example.com admits names under the domain, not the domain itself."""
        pytest_assert(set_trusted_cnames(bmc_duthost, "*.example.com"),
                      "sonic-dbus-bridge did not come back after configuring the list")

        cases = [("host.example.com", "sub", 200),
                 ("deep.host.example.com", "deepsub", 200),
                 ("example.com", "bare", 403),
                 ("example.com.evil.net", "suffixed", 403)]
        for common_name, slug, expected in cases:
            cert, key = issue_client_cert(bmc_tls_certs["generator"],
                                          bmc_tls_certs["dir"], common_name, slug)
            response = requests.get(
                redfish_url(bmc_ip, PRIVILEGED_PATH, bmc_tls_certs["port"]),
                cert=(cert, key), verify=bmc_tls_certs["ca"], timeout=30)
            pytest_assert(
                response.status_code == expected,
                "CN {} against *.example.com: expected {}, got {}".format(
                    common_name, expected, response.status_code))

    def test_list_entries_are_independent(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """Any entry in a comma separated list admits a client."""
        pytest_assert(set_trusted_cnames(bmc_duthost, "first,{},*.example.com".format(CLIENT_CN)),
                      "sonic-dbus-bridge did not come back after configuring the list")

        cases = [("first", "first", 200),
                 (CLIENT_CN, "middle", 200),
                 ("host.example.com", "wildcard", 200),
                 ("someone-else", "unlisted", 403)]
        for common_name, slug, expected in cases:
            cert, key = issue_client_cert(bmc_tls_certs["generator"],
                                          bmc_tls_certs["dir"], common_name, slug)
            response = requests.get(
                redfish_url(bmc_ip, PRIVILEGED_PATH, bmc_tls_certs["port"]),
                cert=(cert, key), verify=bmc_tls_certs["ca"], timeout=30)
            pytest_assert(
                response.status_code == expected,
                "CN {} against the list: expected {}, got {}".format(
                    common_name, expected, response.status_code))

    def test_service_root_stays_reachable_when_refused(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """A refused client can still read the service root, and nothing else.

        ServiceRoot carries no privilege requirement in Redfish, so it is
        readable by any client that completed the handshake. This records that
        boundary deliberately rather than leaving it to be discovered.
        """
        pytest_assert(set_trusted_cnames(bmc_duthost, "someone-else"),
                      "sonic-dbus-bridge did not come back after configuring the list")

        root = mtls_get(bmc_ip, bmc_tls_certs, SERVICE_ROOT_PATH)
        assert_status_ok(root, SERVICE_ROOT_PATH)

        privileged = mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH)
        pytest_assert(privileged.status_code == 403,
                      "Privileged paths must be refused for an untrusted common name, "
                      "got {}".format(privileged.status_code))


class TestRedfishCertRestartBehaviour:

    def test_bmcweb_restart_keeps_serving(self, bmc_duthost, bmc_ip, bmc_tls_certs, bmc_exec):
        """Restarting bmcweb alone reuses the staged files; the oneshot does not re-run."""
        before, _, _ = bmc_exec("docker exec {} openssl x509 -noout -serial -in {}".format(
            BMCWEB_CONTAINER, STAGED_SERVER_PEM))

        supervisor(bmc_duthost, "restart", "bmcweb")
        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "RUNNING"),
                      "bmcweb did not come back after a restart")

        after, _, _ = bmc_exec("docker exec {} openssl x509 -noout -serial -in {}".format(
            BMCWEB_CONTAINER, STAGED_SERVER_PEM))
        pytest_assert(before == after,
                      "Served certificate changed across a bmcweb restart")
        pytest_assert(program_state(bmc_duthost, "stage-credentials") == "EXITED",
                      "The oneshot should not run again on a bmcweb-only restart")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)

    def test_restart_with_source_removed(self, bmc_duthost, bmc_ip, bmc_tls_certs,
                                         provisioned_after_test):
        """A restart succeeds on the staged copy even with the delivery paths empty.

        Availability must not depend on the delivered files still being
        present and healthy at the moment bmcweb restarts.
        """
        remove_delivered_certs(bmc_duthost)
        supervisor(bmc_duthost, "restart", "bmcweb")

        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "RUNNING"),
                      "bmcweb refused to start although a valid staged certificate exists")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)

    def test_guard_self_heals_damaged_staged_cert(self, bmc_duthost, bmc_ip, bmc_tls_certs,
                                                  provisioned_after_test):
        """A damaged staged certificate is re-staged from the source at the next start.

        The watcher is stopped first, so the guard is the only thing that can
        repair the file. provisioned_after_test recreates the container, which
        brings the watcher back.
        """
        supervisor(bmc_duthost, "stop", WATCHER)
        supervisor(bmc_duthost, "stop", "bmcweb")
        corrupt_staged_cert(bmc_duthost)
        start = syslog_line_count(bmc_duthost)
        supervisor(bmc_duthost, "start", "bmcweb")

        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "RUNNING"),
                      "bmcweb did not start after the staged certificate was damaged")
        pytest_assert(served_serial(bmc_duthost) == local_serial(bmc_tls_certs["server_crt"]),
                      "The guard did not re-stage the delivered certificate")
        pytest_assert(wait_until(30, 2, 0, logged_since, bmc_duthost, start, GUARD_RESTAGE_LOG),
                      "The guard did not log the re-stage, so something else repaired the file")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)


class TestRedfishFailClosed:

    def test_fails_closed_with_nothing_valid(self, bmc_duthost, bmc_ip, bmc_tls_certs,
                                             provisioned_after_test):
        """With no certificate anywhere, a provisioned device refuses to serve.

        The marker records that the device was provisioned, so serving a
        self-signed certificate here would be a silent downgrade. It must fail
        closed instead.
        """
        remove_delivered_certs(bmc_duthost)
        supervisor(bmc_duthost, "stop", "bmcweb")
        remove_staged_certs(bmc_duthost)
        supervisor(bmc_duthost, "start", "bmcweb")

        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "FATAL"),
                      "bmcweb should end in FATAL when no valid certificate exists")
        pytest_assert(endpoint_is_down(bmc_ip, bmc_tls_certs["port"]),
                      "Something answered on the Redfish port: a provisioned device "
                      "must not fall back to a self-signed certificate")

        marker = bmc_duthost.shell("test -f {}".format(PROVISIONED_MARKER),
                                   module_ignore_errors=True)
        pytest_assert(marker["rc"] == 0,
                      "The provisioned marker must survive the fail-closed state")

    def test_recovers_when_certificates_return(self, bmc_duthost, bmc_ip, bmc_tls_certs,
                                               provisioned_after_test):
        """A failed-closed device recovers on its own once certificates are delivered.

        No operator action: supervisord has given up by this point, so the
        watcher is what stages the certificates and starts bmcweb again.
        """
        remove_delivered_certs(bmc_duthost)
        supervisor(bmc_duthost, "stop", "bmcweb")
        remove_staged_certs(bmc_duthost)
        supervisor(bmc_duthost, "start", "bmcweb")
        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "FATAL"),
                      "Precondition failed: bmcweb is not in the fail-closed state")

        restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])

        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "RUNNING", timeout=180),
                      "The watcher did not bring bmcweb back after certificates returned")
        pytest_assert(wait_for_staging(bmc_duthost), "Device did not return to in sync")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)

    def test_recreate_without_certificates_fails_closed(self, bmc_duthost, bmc_ip,
                                                        bmc_tls_certs, provisioned_after_test):
        """Recreating the container with no delivered certificates fails closed.

        The recreate wipes the staged copies, so this is the case where the
        marker is the only thing that remembers the device was provisioned.
        """
        remove_delivered_certs(bmc_duthost)
        recreate_container(bmc_duthost)

        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "FATAL"),
                      "bmcweb should fail closed after a recreate with no certificates")
        pytest_assert(endpoint_is_down(bmc_ip, bmc_tls_certs["port"]),
                      "A recreated device without certificates must not serve self-signed")


class TestRedfishContainerRecreate:

    def test_recreate_with_certificates_has_no_self_signed_window(
            self, bmc_duthost, bmc_ip, bmc_tls_certs, bmc_exec):
        """A recreate with certificates present comes up serving them directly.

        The oneshot stages before bmcweb's first start, so the device never
        serves a self-signed certificate on the way back up.
        """
        recreate_container(bmc_duthost)
        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "RUNNING"),
                      "bmcweb did not come up after the container was recreated")

        pytest_assert(not staged_is_self_signed(bmc_exec),
                      "Device is serving a self-signed certificate after the recreate")

        _, _, rc = bmc_exec("test -f {}".format(PROVISIONED_MARKER))
        pytest_assert(rc == 0, "The provisioned marker did not survive the recreate")

        pytest_assert(wait_for_staging(bmc_duthost), "Device did not report in sync")
        pytest_assert(cert_status(bmc_duthost, "mtls_enforced") == "true",
                      "mTLS should be enforced again after the recreate")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)


@pytest.mark.usefixtures("good_certs_after_test")
class TestRedfishNegativeInput:

    def test_corrupt_server_certificate_is_not_staged(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """A delivered server certificate that does not parse is refused."""
        before = served_serial(bmc_duthost)

        corrupt_delivered_file(bmc_duthost, DELIVERED_SERVER_CRT)
        time.sleep(RECONCILE_WINDOW)

        pytest_assert(served_serial(bmc_duthost) == before,
                      "A corrupt server certificate was staged")
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "A corrupt server certificate should report out of sync")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)

    def test_corrupt_ca_does_not_cause_flapping(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """A corrupt CA is refused before staging, so bmcweb is never bounced.

        The readiness check rejects it up front rather than staging and
        failing, which would otherwise produce a restart loop.
        """
        before = served_serial(bmc_duthost)
        pid_before = bmcweb_pid(bmc_duthost)

        corrupt_delivered_file(bmc_duthost, DELIVERED_CA_CRT)
        # Several intervals: a stage-fail retry loop would show up as repeated
        # restarts over this window, not in a single pass.
        time.sleep(RECONCILE_WINDOW * 2)

        pytest_assert(served_serial(bmc_duthost) == before,
                      "A corrupt CA was staged")
        pytest_assert(bmcweb_pid(bmc_duthost) == pid_before,
                      "bmcweb was bounced while a corrupt CA was present")
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "A corrupt CA should report out of sync")
        pytest_assert(program_state(bmc_duthost, "credentials-watcher") == "RUNNING",
                      "The watcher should survive a corrupt CA")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)

    def test_deleting_the_source_keeps_the_service_running(self, bmc_duthost, bmc_ip,
                                                           bmc_tls_certs):
        """Deleting the delivered files does not revoke access.

        Revocation is done by rotating the CA. Deletion leaves the running
        service on its already staged certificate.
        """
        before = served_serial(bmc_duthost)

        remove_delivered_certs(bmc_duthost)
        time.sleep(RECONCILE_WINDOW)

        pytest_assert(program_state(bmc_duthost, "credentials-watcher") == "RUNNING",
                      "The watcher should stay up when the source is deleted")
        pytest_assert(served_serial(bmc_duthost) == before,
                      "The served certificate changed after the source was deleted")
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "A deleted source should report out of sync")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)


@pytest.mark.usefixtures("good_certs_after_test")
class TestRedfishFirstInstallMismatch:
    """The pair guard on a device that has never been provisioned.

    test_mismatched_pair_is_not_staged covers a mismatch on a provisioned
    device, where the previous certificate keeps serving. Here there is
    nothing to fall back to, so the device must simply stay unprovisioned.
    """

    def test_mismatched_first_install_stays_in_bootstrap(self, bmc_duthost, bmc_ip,
                                                         bmc_tls_certs, bmc_exec):
        pytest_assert(unprovision(bmc_duthost),
                      "Device did not return to the unprovisioned state")

        # A certificate and a key from two different pairs, plus a valid CA.
        crt, _ = issue_server_cert(bmc_tls_certs["generator"], bmc_tls_certs["dir"], "firstA")
        _, key = issue_server_cert(bmc_tls_certs["generator"], bmc_tls_certs["dir"], "firstB")
        bmc_duthost.shell("mkdir -p {} {}".format(DELIVERY_DIR, CREDENTIALS_DIR))
        deliver_single_file(bmc_duthost, bmc_tls_certs["dir"], crt, DELIVERED_SERVER_CRT)
        deliver_single_file(bmc_duthost, bmc_tls_certs["dir"], key,
                            DELIVERED_SERVER_KEY)
        deliver_single_file(bmc_duthost, bmc_tls_certs["dir"], CA_CERT_NAME, DELIVERED_CA_CRT)
        time.sleep(RECONCILE_WINDOW)

        _, _, rc = bmc_exec("test -f {}".format(PROVISIONED_MARKER))
        pytest_assert(rc != 0,
                      "A mismatched first install must not mark the device provisioned")
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "A mismatched first install should report out of sync")

        pytest_assert(staged_is_self_signed(bmc_exec),
                      "Device should still be serving its self-signed certificate")

        # Completing the pair finishes the first install normally.
        restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
        pytest_assert(wait_for_staging(bmc_duthost),
                      "Delivering a matching pair did not complete the first install")
        _, _, rc = bmc_exec("test -f {}".format(PROVISIONED_MARKER))
        pytest_assert(rc == 0, "The marker was not written once the pair matched")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)


@pytest.mark.usefixtures("healthy_watcher_after_test")
class TestRedfishWatcherResilience:

    def test_change_made_while_down_is_reconciled(self, bmc_duthost, bmc_tls_certs):
        """A rotation delivered while the watcher is stopped is applied when it starts.

        No inotify event can have been acted on, because the process was not
        running, so this exercises the reconcile that runs before the watcher
        blocks for events.
        """
        before = served_serial(bmc_duthost)

        supervisor(bmc_duthost, "stop", WATCHER)
        pytest_assert(program_state(bmc_duthost, WATCHER) != "RUNNING",
                      "Precondition failed: the watcher is still running")

        crt, key = issue_server_cert(bmc_tls_certs["generator"],
                                     bmc_tls_certs["dir"], "whiledown")
        deliver_single_file(bmc_duthost, bmc_tls_certs["dir"], crt, DELIVERED_SERVER_CRT)
        deliver_single_file(bmc_duthost, bmc_tls_certs["dir"], key,
                            DELIVERED_SERVER_KEY)

        # Nothing should have moved while the watcher is down.
        time.sleep(STAGING_POLL)
        pytest_assert(served_serial(bmc_duthost) == before,
                      "The certificate changed while the watcher was stopped")

        supervisor(bmc_duthost, "start", WATCHER)
        pytest_assert(wait_for_program(bmc_duthost, WATCHER, "RUNNING"),
                      "The watcher did not come back")
        pytest_assert(wait_for_staging(bmc_duthost),
                      "The change made while the watcher was down was never applied")
        pytest_assert(served_serial(bmc_duthost) != before,
                      "The startup reconcile did not stage the missed change")

    def test_unchanged_content_does_not_bounce_bmcweb(self, bmc_duthost, bmc_tls_certs):
        """Re-delivering identical bytes causes no restage and no restart.

        The fingerprint is over content, so repeated delivery of the same
        certificates is a no-op however many events it generates.
        """
        pytest_assert(wait_for_staging(bmc_duthost), "Precondition failed: not in sync")
        serial_before = served_serial(bmc_duthost)
        pid_before = bmcweb_pid(bmc_duthost)
        applied_before = cert_status(bmc_duthost, "applied_fingerprint")

        # Same files, delivered again: events fire, content is identical.
        deliver_certs(bmc_duthost, bmc_tls_certs["dir"])
        time.sleep(RECONCILE_WINDOW)

        pytest_assert(bmcweb_pid(bmc_duthost) == pid_before,
                      "bmcweb was bounced for a delivery that changed nothing")
        pytest_assert(served_serial(bmc_duthost) == serial_before,
                      "The served certificate changed for identical content")
        pytest_assert(cert_status(bmc_duthost, "applied_fingerprint") == applied_before,
                      "The applied fingerprint moved for identical content")
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "true",
                      "Device should remain in sync across a no-op delivery")


@pytest.mark.usefixtures("healthy_watcher_after_test")
class TestRedfishObservability:

    def test_every_failure_reports_a_reason(self, bmc_duthost, bmc_tls_certs):
        """Each kind of bad input sets last_error, not only in_sync.

        Missing files, an unparseable certificate and a mismatched pair all
        report out of sync with a non-empty last_error. The script reports
        one reason for all three, so the test does not tell them apart.
        """
        # Missing files
        remove_delivered_certs(bmc_duthost)
        time.sleep(RECONCILE_WINDOW)
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "Missing files should report out of sync")
        missing_reason = cert_status(bmc_duthost, "last_error")
        pytest_assert(missing_reason != "", "No reason reported for missing files")

        # Unparseable certificate
        restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
        pytest_assert(wait_for_staging(bmc_duthost), "Could not restore a good state")
        corrupt_delivered_file(bmc_duthost, DELIVERED_CA_CRT)
        time.sleep(RECONCILE_WINDOW)
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "A corrupt CA should report out of sync")
        pytest_assert(cert_status(bmc_duthost, "last_error") != "",
                      "No reason reported for a corrupt CA")

        # Mismatched pair
        restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
        pytest_assert(wait_for_staging(bmc_duthost), "Could not restore a good state")
        crt, _ = issue_server_cert(bmc_tls_certs["generator"],
                                   bmc_tls_certs["dir"], "reasoncheck")
        deliver_single_file(bmc_duthost, bmc_tls_certs["dir"], crt, DELIVERED_SERVER_CRT)
        time.sleep(RECONCILE_WINDOW)
        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "A mismatched pair should report out of sync")
        pytest_assert(cert_status(bmc_duthost, "last_error") != "",
                      "No reason reported for a mismatched pair")

    def test_last_update_shows_whether_the_watcher_is_alive(self, bmc_duthost):
        """last_update advances while the watcher runs and stops when it does.

        This is the field monitoring uses to tell a quiet device from a dead
        watcher, so it has to move on its own.
        """
        pytest_assert(wait_for_staging(bmc_duthost), "Precondition failed: not in sync")

        first = cert_status(bmc_duthost, "last_update")
        time.sleep(RECONCILE_WINDOW)
        second = cert_status(bmc_duthost, "last_update")
        pytest_assert(second != first,
                      "last_update did not advance while the watcher was running")

        supervisor(bmc_duthost, "stop", WATCHER)
        stopped_at = cert_status(bmc_duthost, "last_update")
        time.sleep(RECONCILE_WINDOW)
        pytest_assert(cert_status(bmc_duthost, "last_update") == stopped_at,
                      "last_update advanced while the watcher was stopped")


@pytest.mark.usefixtures("provisioned_on_session_port")
class TestRedfishBootstrap:

    def test_unprovisioned_device_serves_self_signed(self, bmc_duthost, bmc_ip, bmc_exec,
                                                     redfish_port):
        """Before any certificate is delivered, the device still answers.

        Boot must not depend on a provisioning agent having run: the service
        root is reachable so the device can be discovered and diagnosed, and
        everything that needs authentication is refused because no credential
        of any kind exists yet.
        """
        pytest_assert(unprovision(bmc_duthost),
                      "Device did not return to the unprovisioned state")

        pytest_assert(staged_is_self_signed(bmc_exec),
                      "An unprovisioned device should serve a self-signed certificate")

        _, _, rc = bmc_exec("test -f {}".format(PROVISIONED_MARKER))
        pytest_assert(rc != 0, "An unprovisioned device must carry no marker")

        # Reachable without any credential, because the certificate is untrusted
        # a client has to skip verification to talk to it at all.
        root = requests.get(redfish_url(bmc_ip, SERVICE_ROOT_PATH, redfish_port),
                            verify=False, timeout=30)
        assert_status_ok(root, SERVICE_ROOT_PATH)

        privileged = requests.get(redfish_url(bmc_ip, PRIVILEGED_PATH, redfish_port),
                                  verify=False, timeout=30)
        pytest_assert(privileged.status_code == 401,
                      "Privileged paths must need authentication even in bootstrap, got {}".format(
                          privileged.status_code))

        pytest_assert(cert_status(bmc_duthost, "in_sync") == "false",
                      "An unprovisioned device is not in sync")
        pytest_assert(cert_status(bmc_duthost, "mtls_enforced") == "false",
                      "mTLS cannot be enforced before a CA is staged")


@pytest.mark.usefixtures("provisioned_on_session_port")
class TestRedfishConfiguredPaths:

    def test_certificates_are_read_from_the_configured_paths(self, bmc_duthost, bmc_ip,
                                                             bmc_tls_certs):
        """Delivery paths come from CONFIG_DB, including split directories.

        The server pair and the CA may be delivered to different places, so
        the watcher has to watch both.
        """
        alt_dir = "/etc/sonic/redfish-alt"
        alt_ca_dir = "/etc/sonic/credentials-alt"
        bmc_duthost.shell("mkdir -p {} {}".format(alt_dir, alt_ca_dir))
        try:
            db_set(bmc_duthost, "CONFIG_DB", REDFISH_CERTS_TABLE,
                   server_crt="{}/server.cer".format(alt_dir),
                   server_key="{}/server.key".format(alt_dir),
                   ca_crt="{}/ca.pem".format(alt_ca_dir))

            # The watcher re-reads its configuration on each wake, so the new paths
            # take effect without restarting anything.
            for local, remote in ((SERVER_CERT_NAME, "{}/server.cer".format(alt_dir)),
                                  (SERVER_KEY_NAME, "{}/server.key".format(alt_dir)),
                                  (CA_CERT_NAME, "{}/ca.pem".format(alt_ca_dir))):
                bmc_duthost.copy(src=str(bmc_tls_certs["dir"] / local), dest="/tmp/alt-file")
                bmc_duthost.shell("mv -f /tmp/alt-file {}".format(remote))

            pytest_assert(wait_for_staging(bmc_duthost),
                          "Certificates at the configured paths were not staged; last_error={}".format(
                              cert_status(bmc_duthost, "last_error")))
            assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH), PRIVILEGED_PATH)
        finally:
            bmc_duthost.shell("rm -rf {} {}".format(alt_dir, alt_ca_dir), module_ignore_errors=True)

    def test_defaults_apply_with_no_configuration(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """A device with no REDFISH tables still boots and can be provisioned.

        Production may ship with nothing configured, so the built-in defaults
        are what such a device runs on.
        """
        bmc_duthost.shell('sonic-db-cli CONFIG_DB del "{}"'.format(REDFISH_CERTS_TABLE),
                          module_ignore_errors=True)
        bmc_duthost.shell('sonic-db-cli CONFIG_DB del "{}"'.format(REDFISH_CONFIG_TABLE),
                          module_ignore_errors=True)

        # The defaults are the paths the fixture already delivers to.
        restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
        recreate_container(bmc_duthost)
        pytest_assert(wait_for_program(bmc_duthost, "bmcweb", "RUNNING"),
                      "Device did not come up with no Redfish configuration")
        pytest_assert(listening_port(bmc_duthost) == DEFAULT_PORT,
                      "With no configuration the published port should be {}".format(
                          DEFAULT_PORT))
        pytest_assert(wait_for_staging(bmc_duthost),
                      "Default paths were not used to stage certificates")
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, SERVICE_ROOT_PATH), SERVICE_ROOT_PATH)

        # Deleting REDFISH|certs also removed the trusted names, and an unset
        # list refuses every common name.
        response = mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH)
        pytest_assert(response.status_code == 403,
                      "With no trusted common names configured, expected 403 on {}, got {}".format(
                          PRIVILEGED_PATH, response.status_code))


@pytest.mark.usefixtures("provisioned_on_session_port")
class TestRedfishConfiguredPort:

    def test_default_port_is_443(self, bmc_duthost):
        """With no port configured, the API is published on the standard port."""
        bmc_duthost.shell('sonic-db-cli CONFIG_DB del "{}"'.format(REDFISH_CONFIG_TABLE),
                          module_ignore_errors=True)
        pytest_assert(restart_service(bmc_duthost), "Device did not restart")
        pytest_assert(listening_port(bmc_duthost) == DEFAULT_PORT,
                      "Expected the default port {}, got {}".format(
                          DEFAULT_PORT, listening_port(bmc_duthost)))

    def test_configured_port_is_applied_by_a_service_restart(self, bmc_duthost, bmc_ip,
                                                             bmc_tls_certs):
        """A configured port takes effect when the service restarts.

        bmcweb reads the port each time it starts, so a service restart applies
        it. The certificate flow has to survive that restart: the device comes
        back serving the same provisioned certificate, with no self-signed
        window.
        """
        new_port = ALTERNATE_PORT if bmc_tls_certs["port"] != ALTERNATE_PORT else ALTERNATE_PORT + 1
        db_set(bmc_duthost, "CONFIG_DB", REDFISH_CONFIG_TABLE, port=str(new_port))
        pytest_assert(restart_service(bmc_duthost), "Device did not restart")

        pytest_assert(listening_port(bmc_duthost) == new_port,
                      "Expected the configured port {}, got {}".format(
                          new_port, listening_port(bmc_duthost)))
        assert_status_ok(mtls_get(bmc_ip, bmc_tls_certs, PRIVILEGED_PATH, new_port),
                         PRIVILEGED_PATH)

        # The old port is no longer served.
        try:
            requests.get(redfish_url(bmc_ip, SERVICE_ROOT_PATH, bmc_tls_certs["port"]),
                         verify=False, timeout=5)
            pytest.fail("The previous port is still answering after the change")
        except requests.exceptions.RequestException:
            pass

        pytest_assert(wait_for_staging(bmc_duthost),
                      "Certificates were not re-staged after the port change")
        pytest_assert(cert_status(bmc_duthost, "mtls_enforced") == "true",
                      "mTLS should still be enforced after a port change")

    def test_invalid_port_falls_back_to_the_default(self, bmc_duthost):
        """An unusable port value must not stop the container from being created."""
        db_set(bmc_duthost, "CONFIG_DB", REDFISH_CONFIG_TABLE, port="notaport")
        pytest_assert(restart_service(bmc_duthost),
                      "An invalid port stopped the device from starting")
        pytest_assert(listening_port(bmc_duthost) == DEFAULT_PORT,
                      "An invalid port should fall back to {}, got {}".format(
                          DEFAULT_PORT, listening_port(bmc_duthost)))


@pytest.mark.usefixtures("provisioned_on_session_port")
class TestRedfishCaRotation:

    def test_ca_rotation_replaces_the_truststore(self, bmc_duthost, bmc_ip, bmc_tls_certs):
        """Rotating the CA is how access is revoked.

        Clients holding certificates from the old CA stop being accepted once
        the new CA is staged, which is the reason deleting files is not a
        revocation mechanism.
        """
        old_client = (bmc_tls_certs["cert"], bmc_tls_certs["key"])
        old_ca = bmc_tls_certs["ca"]

        # A second, independent chain: its own CA, server certificate and
        # client certificate, written under names that do not collide with the
        # chain currently in use.
        d = bmc_tls_certs["dir"]
        rotated = build_cert_chain(
            d, bmc_ip, client_cn=CLIENT_CN,
            ca_cn="SONiC BMC Test CA 2",
            ca_cert_name="CA2-cert.pem", ca_key_name="CA2-key.pem",
            server_cert_name="server2-cert.pem", server_key_name="server2-key.pem",
            client_cert_name="client2-cert.pem", client_key_name="client2-key.pem")
        logger.info("Issued a second CA: %s", rotated.ca_cn)

        deliver_certs(bmc_duthost, bmc_tls_certs["dir"],
                      server_crt="server2-cert.pem", server_key="server2-key.pem",
                      ca_crt="CA2-cert.pem")
        pytest_assert(wait_for_staging(bmc_duthost), "The rotated CA was not staged")

        new_client = (str(d / "client2-cert.pem"), str(d / "client2-key.pem"))
        new_ca = str(d / "CA2-cert.pem")

        response = requests.get(redfish_url(bmc_ip, PRIVILEGED_PATH, bmc_tls_certs["port"]),
                                cert=new_client, verify=new_ca, timeout=30)
        assert_status_ok(response, PRIVILEGED_PATH)

        # The old client certificate is no longer accepted: its issuer is gone
        # from the truststore. bmcweb completes the handshake and treats the
        # client as having no certificate, so the privileged path is refused.
        try:
            response = requests.get(redfish_url(bmc_ip, PRIVILEGED_PATH, bmc_tls_certs["port"]),
                                    cert=old_client, verify=new_ca, timeout=30)
            pytest_assert(response.status_code in (401, 403),
                          "A client from the old CA was still accepted after CA rotation: {}".format(
                              response.status_code))
        except (requests.exceptions.SSLError, ssl.SSLError):
            logger.info("TLS handshake rejected for the old CA's client, as expected")

        # Restore the original chain for the modules that follow.
        restore_delivered_certs(bmc_duthost, bmc_tls_certs["dir"])
        pytest_assert(wait_for_staging(bmc_duthost), "Could not restore the original CA")
        assert_status_ok(
            requests.get(redfish_url(bmc_ip, PRIVILEGED_PATH, bmc_tls_certs["port"]),
                         cert=old_client, verify=old_ca, timeout=30),
            PRIVILEGED_PATH)
