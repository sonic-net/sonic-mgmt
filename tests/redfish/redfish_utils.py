"""
Shared Redfish test utilities for SONiC BMC Redfish API tests.
"""
import ipaddress
import logging
import os
import socket
import ssl

import requests
from cryptography import x509

from tests.common.cert_utils import TlsCertificateGenerator
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


BMC_TEST_CA_NAME = "SONiC BMC Test CA"

# The standard HTTPS port, left out of URLs that use it.
DEFAULT_PORT = 443


# HOST_STATE|switch-host device_power_state values bmcctld leaves once an action
# has completed, with the device_status each goes with (pmon-bmc-design.md DB
# schema). The value names the last action, so whether the host is on follows
# from device_status, which is how sonic-dbus-bridge resolves it as well.
HOST_FINAL_POWER_STATES = {
    "POWERED_ON": "ONLINE",
    "POWER_CYCLE": "ONLINE",
    "POWERED_OFF": "OFFLINE",
    "GRACEFUL_SHUTDOWN": "OFFLINE",
}


def host_is_settled_on(host_state):
    """True when HOST_STATE|switch-host shows the switch host on with no action in flight."""
    power_state = host_state.get("device_power_state")
    return HOST_FINAL_POWER_STATES.get(power_state) == "ONLINE" and host_state.get("device_status") == "ONLINE"


REDFISH_ROOT = "/redfish/v1"
BMCWEB_CONTAINER = "redfish"

BMCWEB_READY_TIMEOUT = 60
BMCWEB_READY_POLL = 2


def redfish_netloc(host, port=DEFAULT_PORT):
    """Host and port for a Redfish URL, bracketing IPv6 and omitting 443."""
    try:
        if ipaddress.ip_address(host).version == 6:
            host = "[{}]".format(host)
    except ValueError:
        pass  # a hostname rather than an address literal: used as is
    return host if int(port) == DEFAULT_PORT else "{}:{}".format(host, port)


def redfish_url(bmc_ip, path, port=DEFAULT_PORT):
    """Build a full https URL for a Redfish path on the BMC."""
    return "https://{}{}".format(redfish_netloc(bmc_ip, port), path)


class RedfishClient:
    """HTTP client for Redfish API calls using mTLS client-certificate auth."""

    def __init__(self, bmc_ip, cert, key, ca, timeout=30, port=DEFAULT_PORT):
        self.base_url = "https://{}".format(redfish_netloc(bmc_ip, port))
        self.cert = (cert, key)
        self.verify = ca
        self.timeout = timeout

    def _request(self, method, path, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return requests.request(
            method, self.base_url + path,
            cert=self.cert, verify=self.verify,
            **kwargs,
        )

    def get(self, path, **kwargs):
        return self._request("GET", path, **kwargs)

    def post(self, path, json=None, **kwargs):
        return self._request("POST", path, json=json, **kwargs)

    def patch(self, path, json=None, **kwargs):
        return self._request("PATCH", path, json=json, **kwargs)

    def delete(self, path, **kwargs):
        return self._request("DELETE", path, **kwargs)


def assert_field_equals(body, field, expected):
    """Assert a top-level field equals an expected value."""
    actual = body.get(field, "")
    pytest_assert(
        actual == expected,
        "Field '{}' must be {!r}, got: {!r}".format(field, expected, actual)
    )


def assert_field_contains(body, field, substring):
    """Assert a top-level field contains a substring."""
    actual = body.get(field, "")
    pytest_assert(
        substring in actual,
        "Field '{}' must contain {!r}, got: {!r}".format(field, substring, actual)
    )


def assert_field_nonempty(body, field):
    """Assert a top-level field is a non-empty string."""
    actual = body.get(field, "")
    pytest_assert(
        isinstance(actual, str) and len(actual) > 0,
        "Field '{}' must be a non-empty string, got: {!r}".format(field, actual)
    )


def assert_field_in(body, field, valid_values):
    """Assert a top-level field is one of the valid values."""
    actual = body.get(field, "")
    pytest_assert(
        actual in valid_values,
        "Field '{}' must be one of {}, got: {!r}".format(field, valid_values, actual)
    )


def assert_status_ok(response, path):
    """Assert HTTP 200 from a given path."""
    pytest_assert(
        response.status_code == 200,
        "Expected HTTP 200 from {}, got: {}".format(path, response.status_code)
    )


def assert_member_count(body, minimum=1):
    """Assert Members@odata.count >= minimum and Members array has entries."""
    count = body.get("Members@odata.count", 0)
    pytest_assert(
        count >= minimum,
        "Members@odata.count must be >= {}, got: {}".format(minimum, count)
    )


def assert_no_content(response, path):
    """Assert HTTP 204 with an empty body from a given path."""
    pytest_assert(
        response.status_code == 204,
        "Expected HTTP 204 from {}, got: {} body={!r}".format(
            path, response.status_code, response.text[:500])
    )
    pytest_assert(
        not response.content,
        "Expected empty body with HTTP 204 from {}, got: {!r}".format(path, response.text[:500])
    )


def assert_redfish_error(response, status, message, message_args=None, prop=None):
    """Assert a Redfish error response carrying the given registry message.

    bmcweb reports some errors under body["error"] ("code" plus
    "@Message.ExtendedInfo") and property-scoped ones under
    "<prop>@Message.ExtendedInfo". With prop given only that annotation is
    searched; without it every ExtendedInfo list in the body is. MessageId is
    matched on its ".<message>" suffix so a Base registry version bump does
    not break callers.
    """
    pytest_assert(
        response.status_code == status,
        "Expected HTTP {}, got: {} body={!r}".format(status, response.status_code, response.text[:500])
    )
    try:
        body = response.json()
    except ValueError:
        body = None
    pytest_assert(
        isinstance(body, dict),
        "Expected a Redfish error object, got: {!r}".format(response.text[:300])
    )
    suffix = ".{}".format(message)
    if prop:
        infos = body.get("{}@Message.ExtendedInfo".format(prop), [])
    else:
        infos = list(body.get("error", {}).get("@Message.ExtendedInfo", []))
        for key, value in body.items():
            if key.endswith("@Message.ExtendedInfo") and isinstance(value, list):
                infos.extend(value)
    matched = [i for i in infos if i.get("MessageId", "").endswith(suffix)]
    pytest_assert(
        matched,
        "No ExtendedInfo entry with MessageId ending {!r} in: {!r}".format(suffix, body)
    )
    if message_args is not None:
        pytest_assert(
            any(i.get("MessageArgs") == message_args for i in matched),
            "MessageArgs must be {!r}, got: {!r}".format(
                message_args, [i.get("MessageArgs") for i in matched])
        )


def best_effort(fn, *args, **kwargs):
    """Run a teardown step, log and swallow any exception so later steps still run."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.warning("Teardown step %s(%s) failed: %s",
                       getattr(fn, "__name__", fn), args, e)
        return None


def _bmcweb_running(bmc_duthost):
    """True iff `supervisorctl status bmcweb` reports RUNNING in the redfish container.

    Used as the wait_until condition.
    """
    res = bmc_duthost.shell(
        "docker exec {} supervisorctl status bmcweb".format(BMCWEB_CONTAINER),
        module_ignore_errors=True,
    )
    return res["rc"] == 0 and "RUNNING" in res["stdout"]


# --- Certificate provisioning (staging pipeline) -----------------------------
# Helpers used by bmc_tls_certs to drive the pipeline the way a provisioning
# agent does, and by the tests to inspect what the pipeline produced.

REDFISH_CERTS_TABLE = "REDFISH|certs"
REDFISH_CONFIG_TABLE = "REDFISH|config"
CERT_STATUS_KEY = "REDFISH_CERT_STATUS|global"

# Common name the tests issue client certificates with, and configure the
# device to trust.
CLIENT_CN = "bmcweb"

# CONFIG_DB fields the tests overwrite. They are recorded before the run and
# put back afterwards: the suite borrows these tables from the device rather
# than owning them, so a device that arrived with its own Redfish
# configuration must leave with it intact.
OWNED_FIELDS = {
    REDFISH_CERTS_TABLE: ("server_crt", "server_key", "ca_crt", "client_crt_cname"),
    REDFISH_CONFIG_TABLE: ("port",),
}

# Delivery paths the tests configure in REDFISH|certs. They are where the REST
# API server's certificates live, which an unconfigured device must ignore.
DELIVERY_DIR = "/etc/sonic/credentials"
DELIVERED_SERVER_CRT = "{}/restapiserver.crt".format(DELIVERY_DIR)
DELIVERED_SERVER_KEY = "{}/restapiserver.key".format(DELIVERY_DIR)
DELIVERED_CA_CRT = "{}/restapica.crt".format(DELIVERY_DIR)

# Local file names the generator writes, and that deliver_certs() copies to the
# configured paths above.
CA_CERT_NAME = "CA-cert.pem"
CA_KEY_NAME = "CA-key.pem"
SERVER_CERT_NAME = "server-cert.pem"
SERVER_KEY_NAME = "server-key.pem"
CLIENT_CERT_NAME = "client-cert.pem"
CLIENT_KEY_NAME = "client-key.pem"

STAGED_SERVER_PEM = "/etc/ssl/certs/https/server.pem"
STAGED_CA_CRT = "/etc/ssl/certs/authority/CA-cert.pem"
PROVISIONED_MARKER = "/var/lib/bmcweb/provisioned"
STAGING_STAMP = "/var/lib/bmcweb/.staged-credentials.stamp"

# What the guard logs when it re-stages before starting bmcweb.
GUARD_RESTAGE_LOG = "guard: staged certificates missing or invalid; re-staging from source"

# The watcher reconciles at least once a minute, so allow two intervals plus
# the bmcweb bounce before calling a staging failure.
STAGING_TIMEOUT = 150
STAGING_POLL = 5


def listening_port(duthost):
    """Port bmcweb listens on, as an integer, or 0 when it is not listening.

    The redfish container runs on host networking, so bmcweb's listener is
    visible in the host's socket table.
    """
    out = duthost.shell("sudo ss -Hltnp", module_ignore_errors=True)["stdout"]
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 4 and '"bmcweb"' in line:
            return int(fields[3].rsplit(":", 1)[-1])
    return 0


def configured_port(duthost):
    """The port CONFIG_DB asks for, validated the way the container does it.

    An unset, non-numeric or out-of-range value means the standard port.
    """
    value = db_get(duthost, "CONFIG_DB", REDFISH_CONFIG_TABLE, "port")
    return int(value) if value.isdigit() and 1 <= int(value) <= 65535 else DEFAULT_PORT


def db_get(duthost, db, key, field):
    """Read one hash field from a database on the BMC."""
    res = duthost.shell('sonic-db-cli {db} hget "{key}" {field}'.format(
        db=db, key=key, field=field), module_ignore_errors=True)
    return res["stdout"].strip()


def db_set(duthost, db, key, **fields):
    """Write hash fields to a database on the BMC."""
    pairs = " ".join('{} "{}"'.format(f, v) for f, v in fields.items())
    duthost.shell('sonic-db-cli {db} hset "{key}" {pairs}'.format(
        db=db, key=key, pairs=pairs))


def db_hdel(duthost, db, key, field):
    """Remove one hash field. Redis drops the key when its last field goes."""
    best_effort(duthost.shell, 'sonic-db-cli {db} hdel "{key}" {field}'.format(
        db=db, key=key, field=field), module_ignore_errors=True)


def snapshot_redfish_config(duthost):
    """Record the REDFISH CONFIG_DB fields the tests are about to overwrite."""
    return {(table, field): db_get(duthost, "CONFIG_DB", table, field)
            for table, fields in OWNED_FIELDS.items()
            for field in fields}


def restore_redfish_config(duthost, snapshot):
    """Put the recorded fields back, clearing the ones that were unset.

    Deleting the tables outright would be wrong: a field that held an
    operator's value before the run has to come back, and one that was never
    set has to go. Writing back what was read does both, whether or not the
    original value was ever saved to disk.
    """
    for (table, field), value in sorted(snapshot.items()):
        if value:
            db_set(duthost, "CONFIG_DB", table, **{field: value})
        else:
            db_hdel(duthost, "CONFIG_DB", table, field)


def cert_status(duthost, field):
    """Read one field of the Redfish certificate status in STATE_DB."""
    return db_get(duthost, "STATE_DB", CERT_STATUS_KEY, field)


def _in_sync(duthost):
    return cert_status(duthost, "in_sync") == "true"


def place_file(duthost, local_path, remote):
    """Copy a file to the BMC and move it into place in one step.

    The copy lands next to its target, so the final move is a rename on the
    same filesystem and the watcher never sees a partially written file.
    """
    tmp = os.path.join(os.path.dirname(remote), ".{}.tmp".format(os.path.basename(remote)))
    duthost.copy(src=str(local_path), dest=tmp)
    duthost.shell("mv -f {} {}".format(tmp, remote))


def deliver_certs(duthost, cert_dir, server_crt=SERVER_CERT_NAME,
                  server_key=SERVER_KEY_NAME, ca_crt=CA_CERT_NAME):
    """Place certificates at the configured delivery paths, as an agent would."""
    for local, remote in (
        (server_crt, DELIVERED_SERVER_CRT),
        (server_key, DELIVERED_SERVER_KEY),
        (ca_crt, DELIVERED_CA_CRT),
    ):
        place_file(duthost, cert_dir / local, remote)


def applied_fingerprint(duthost):
    """Fingerprint of the certificate set the pipeline last applied."""
    return cert_status(duthost, "applied_fingerprint")


def wait_for_staging(duthost, timeout=STAGING_TIMEOUT, changed_from=None):
    """Wait until the pipeline reports the delivered certificates as applied.

    in_sync can still be true from the previous delivery until the watcher
    handles the new one. A caller that has just delivered different content
    passes the fingerprint read before the delivery, and the wait then also
    requires the applied set to have moved off it.
    """
    def applied():
        return _in_sync(duthost) and (changed_from is None or
                                      applied_fingerprint(duthost) != changed_from)
    return wait_until(timeout, STAGING_POLL, 0, applied)


# Files the suite overwrites or removes. A device that arrives provisioned keeps
# its own certificates and marker: they are set aside before the run and put
# back afterwards. The backups sit next to the originals, so a reboot during
# the run does not lose them.
DEVICE_STATE_FILES = (DELIVERED_SERVER_CRT, DELIVERED_SERVER_KEY, DELIVERED_CA_CRT,
                      PROVISIONED_MARKER, STAGING_STAMP)
BACKUP_SUFFIX = ".sonic-mgmt.bak"


def back_up_device_state(duthost):
    """Set aside any device state the suite would overwrite; return what was saved."""
    saved = []
    for path in DEVICE_STATE_FILES:
        res = duthost.shell("test -e {0} && cp -a {0} {0}{1}".format(path, BACKUP_SUFFIX),
                            module_ignore_errors=True)
        if res["rc"] == 0:
            saved.append(path)
    if saved:
        logger.info("Set aside existing device state: {}".format(", ".join(saved)))
    return saved


def restore_device_state(duthost, saved):
    """Put back what back_up_device_state() set aside."""
    for path in saved:
        best_effort(duthost.shell, "mv -f {0}{1} {0}".format(path, BACKUP_SUFFIX),
                    module_ignore_errors=True)


def reset_to_bootstrap(duthost, snapshot, saved=()):
    """Return the BMC to the state it was in before the suite ran.

    The provisioned marker is one-way by design, so the suite's own marker must
    be removed or every later module inherits a fail-closed device. Whatever the
    device had before the run is then put back, so a provisioned device comes
    back provisioned with its own certificates. Recreating the container clears
    the staged files and bmcweb's persistent configuration with them.
    """
    for path in DEVICE_STATE_FILES:
        best_effort(duthost.shell, "rm -f {}".format(path), module_ignore_errors=True)
    restore_device_state(duthost, saved)
    restore_redfish_config(duthost, snapshot)
    best_effort(duthost.shell, "systemctl stop redfish", module_ignore_errors=True)
    best_effort(duthost.shell, "docker rm -f {}".format(BMCWEB_CONTAINER),
                module_ignore_errors=True)
    best_effort(duthost.shell, "systemctl start redfish", module_ignore_errors=True)
    best_effort(wait_until, BMCWEB_READY_TIMEOUT, BMCWEB_READY_POLL, 0,
                _bmcweb_running, duthost)


# --- Lifecycle helpers -------------------------------------------------------
# Used by the tests that drive the device through restarts, container
# recreation and the fail-closed state.

# A privileged Redfish path. The service root is deliberately not used for
# authorization checks: Redfish defines ServiceRoot as requiring no
# privileges, so it answers 200 even for an identity with no privileges.
PRIVILEGED_PATH = "{}/Managers".format(REDFISH_ROOT)

BRIDGE_SERVICE = "sonic-dbus-bridge"


def supervisor(duthost, action, program):
    """Run a supervisorctl action on a program inside the redfish container."""
    return duthost.shell(
        "docker exec {} supervisorctl {} {}".format(BMCWEB_CONTAINER, action, program),
        module_ignore_errors=True)["stdout"]


def program_state(duthost, program):
    """RUNNING / FATAL / EXITED / ... for a program in the redfish container."""
    out = supervisor(duthost, "status", program)
    parts = out.split()
    return parts[1] if len(parts) > 1 else ""


def wait_for_program(duthost, program, state, timeout=BMCWEB_READY_TIMEOUT):
    return wait_until(timeout, BMCWEB_READY_POLL, 0,
                      lambda: program_state(duthost, program) == state)


def recreate_container(duthost):
    """Recreate the redfish container, as an image change or port change does.

    reset-failed first: repeatedly driving bmcweb into FATAL during these tests
    trips systemd's start limit, which would otherwise fail the restart for a
    reason unrelated to what is being tested.
    """
    duthost.shell("systemctl reset-failed redfish.service", module_ignore_errors=True)
    duthost.shell("systemctl stop redfish", module_ignore_errors=True)
    duthost.shell("docker rm -f {}".format(BMCWEB_CONTAINER), module_ignore_errors=True)
    duthost.shell("systemctl start redfish", module_ignore_errors=True)


def remove_delivered_certs(duthost):
    """Remove the delivered certificates, leaving the staged copies alone."""
    duthost.shell("rm -f {} {} {}".format(
        DELIVERED_SERVER_CRT, DELIVERED_SERVER_KEY, DELIVERED_CA_CRT),
        module_ignore_errors=True)


def remove_staged_certs(duthost):
    """Remove the staged server PEM inside the container."""
    duthost.shell("docker exec {} rm -f {}".format(BMCWEB_CONTAINER, STAGED_SERVER_PEM),
                  module_ignore_errors=True)


def corrupt_staged_cert(duthost):
    """Replace the staged server PEM inside the container with bytes that are not valid PEM."""
    duthost.shell("docker exec {} sh -c \"printf 'not a certificate' > {}\"".format(
        BMCWEB_CONTAINER, STAGED_SERVER_PEM))


def syslog_line_count(duthost):
    """Number of lines in the BMC syslog, to look only at what is logged after it."""
    return int(duthost.shell("sudo wc -l /var/log/syslog")["stdout"].split()[0])


def logged_since(duthost, start, text):
    """True when syslog has a line containing text after line number start."""
    res = duthost.shell("sudo tail -n +{} /var/log/syslog | grep -F -- '{}'".format(start + 1, text),
                        module_ignore_errors=True)
    return res["rc"] == 0


def restore_delivered_certs(duthost, cert_dir):
    """Put the generated certificates back at the delivery paths."""
    duthost.shell("mkdir -p {}".format(DELIVERY_DIR))
    deliver_certs(duthost, cert_dir)


# --- Trusted common name helpers --------------------------------------------


def set_trusted_cnames(duthost, value):
    """Configure the trusted client common names and apply them.

    The list is read once when sonic-dbus-bridge starts, the way the REST API
    server takes its own trusted names, so a change only takes effect after
    that service restarts. Pass None to remove the setting entirely.
    """
    if value is None:
        duthost.shell('sonic-db-cli CONFIG_DB hdel "{}" client_crt_cname'.format(
            REDFISH_CERTS_TABLE), module_ignore_errors=True)
    else:
        db_set(duthost, "CONFIG_DB", REDFISH_CERTS_TABLE, client_crt_cname=value)

    supervisor(duthost, "restart", BRIDGE_SERVICE)
    return wait_for_program(duthost, BRIDGE_SERVICE, "RUNNING")


# --- Negative input and observability helpers --------------------------------

def bmcweb_pid(duthost):
    """PID of the running bmcweb, or empty when it is not running.

    Used to prove bmcweb was not bounced: a changed PID means a restart.
    """
    tokens = supervisor(duthost, "status", "bmcweb").split()
    # RUNNING reads "bmcweb RUNNING pid 123, uptime ...". Any other state has
    # no pid token, and a date in its description must not be taken for one.
    if "pid" in tokens[:-1]:
        value = tokens[tokens.index("pid") + 1].rstrip(",")
        if value.isdigit():
            return value
    return ""


def served_serial(duthost):
    """Serial of the staged server certificate, read inside the container.

    This is what bmcweb loads when it starts, not necessarily what it is
    serving now; live_serial() reads the certificate from the listener.
    """
    out = duthost.shell(
        "docker exec {} openssl x509 -noout -serial -in {}".format(
            BMCWEB_CONTAINER, STAGED_SERVER_PEM), module_ignore_errors=True)["stdout"]
    return out.strip().split("=")[-1]


def live_serial(bmc_ip, port):
    """Serial of the certificate bmcweb presents in a TLS handshake, or None.

    Nothing is verified: the point is to see which certificate is on the
    wire, whoever issued it. None means nothing completed a handshake.
    """
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((bmc_ip, int(port)), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=bmc_ip) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    return x509.load_der_x509_certificate(der).serial_number


def file_serial(path):
    """Serial of a certificate file on the test runner."""
    with open(str(path), "rb") as handle:
        return x509.load_pem_x509_certificate(handle.read()).serial_number


def corrupt_delivered_file(duthost, path):
    """Replace a delivered certificate with bytes that are not valid PEM."""
    duthost.shell("printf 'not a certificate' > {}".format(path))


def deliver_single_file(duthost, local_path, remote_path):
    """Deliver one file, leaving the rest of the trio as it is.

    Used for the partial upload and mid-rotation cases, where the point is
    that the delivered set is incomplete or inconsistent.
    """
    place_file(duthost, local_path, remote_path)


def unprovision(duthost):
    """Return the device to the unprovisioned state and restart it there.

    Removes the delivered files, the marker and the stamp, then recreates the
    container so the staged copies and bmcweb's persistent configuration go
    with them.
    """
    remove_delivered_certs(duthost)
    duthost.shell("rm -f {} {}".format(PROVISIONED_MARKER, STAGING_STAMP),
                  module_ignore_errors=True)
    recreate_container(duthost)
    return wait_for_program(duthost, "bmcweb", "RUNNING")


# --- Certificate generation --------------------------------------------------
# Certificates come from the shared TlsCertificateGenerator, which backdates
# validity to absorb clock skew between the test host and the BMC.


def build_cert_chain(cert_dir, bmc_ip, client_cn=CLIENT_CN, **kwargs):
    """Generate a CA, a server certificate for this BMC, and a client certificate.

    Returns the generator, so later calls can issue more certificates from the
    same CA: a rotation must not replace the CA, and the common name cases need
    several client certificates that the staged truststore still trusts.
    """
    params = dict(
        server_cn=bmc_ip,
        client_cn=client_cn,
        ca_cn=BMC_TEST_CA_NAME,
        ca_cert_name=CA_CERT_NAME,
        ca_key_name=CA_KEY_NAME,
        server_cert_name=SERVER_CERT_NAME,
        server_key_name=SERVER_KEY_NAME,
        client_cert_name=CLIENT_CERT_NAME,
        client_key_name=CLIENT_KEY_NAME,
    )
    # Callers override any default, e.g. a second CA under its own names.
    params.update(kwargs)
    generator = TlsCertificateGenerator(server_ip=bmc_ip, **params)
    generator.write_all(str(cert_dir))
    return generator


def _write_pair(generator, cert_dir, key, cert, name):
    """Write one certificate and key under <name>-cert.pem / <name>-key.pem."""
    cert_path = os.path.join(str(cert_dir), "{}-cert.pem".format(name))
    key_path = os.path.join(str(cert_dir), "{}-key.pem".format(name))
    with open(cert_path, "wb") as handle:
        handle.write(generator._serialize_cert(cert))
    with open(key_path, "wb") as handle:
        handle.write(generator._serialize_key(key))
    return cert_path, key_path


def issue_server_cert(generator, cert_dir, name):
    """Issue another server certificate from the same CA.

    Used for rotation, and for the mismatch cases where a certificate and a
    key from two different issues are delivered together.
    """
    key, cert = generator._generate_server(generator._ca_key, generator._ca_cert)
    return _write_pair(generator, cert_dir, key, cert, name)


def issue_client_cert(generator, cert_dir, common_name, name):
    """Issue another client certificate from the same CA with a given CN."""
    original = generator.client_cn
    generator.client_cn = common_name
    try:
        key, cert = generator._generate_client(generator._ca_key, generator._ca_cert)
    finally:
        generator.client_cn = original
    return _write_pair(generator, cert_dir, key, cert, name)


def rotate_server_cert(generator, cert_dir):
    """Replace the delivered server pair with a fresh one from the same CA."""
    key, cert = generator._generate_server(generator._ca_key, generator._ca_cert)
    with open(os.path.join(str(cert_dir), SERVER_CERT_NAME), "wb") as handle:
        handle.write(generator._serialize_cert(cert))
    with open(os.path.join(str(cert_dir), SERVER_KEY_NAME), "wb") as handle:
        handle.write(generator._serialize_key(key))
