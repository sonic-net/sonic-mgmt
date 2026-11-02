import logging

import pytest

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.platform.bmc_utils import assert_bmc_clock_in_sync
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import (
    back_up_device_state,
    BMCWEB_CONTAINER,
    BMCWEB_READY_POLL,
    BMCWEB_READY_TIMEOUT,
    build_cert_chain,
    CA_CERT_NAME,
    cert_status,
    CLIENT_CERT_NAME,
    CLIENT_CN,
    CLIENT_KEY_NAME,
    configured_port,
    db_set,
    deliver_certs,
    DELIVERED_CA_CRT,
    DELIVERED_SERVER_CRT,
    DELIVERED_SERVER_KEY,
    DELIVERY_DIR,
    listening_port,
    REDFISH_CERTS_TABLE,
    REDFISH_ROOT,
    redfish_url,
    RedfishClient,
    reset_to_bootstrap,
    SERVER_CERT_NAME,
    SERVER_KEY_NAME,
    set_trusted_cnames,
    snapshot_redfish_config,
    STAGING_TIMEOUT,
    wait_for_staging,
)

logger = logging.getLogger(__name__)


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


@pytest.fixture(scope="module")
def redfish_base_url(bmc_ip, redfish_port):
    return redfish_url(bmc_ip, REDFISH_ROOT, redfish_port)


@pytest.fixture(scope="module")
def redfish_client(bmc_ip, bmc_tls_certs):
    """Return a RedfishClient configured for mTLS client-certificate auth.

    Depends on bmc_tls_certs so the BMC trusts the test CA and the client
    cert/key/CA paths are available before any Redfish request is issued.
    """
    return RedfishClient(
        bmc_ip,
        bmc_tls_certs["cert"],
        bmc_tls_certs["key"],
        bmc_tls_certs["ca"],
        port=bmc_tls_certs["port"],
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


@pytest.fixture(scope="session")
def bmc_clock_in_sync(bmc_duthost):
    """Fail cert tests early if BMC clock is skewed beyond the cert NotBefore window.

    Generated certs use the sonic-mgmt container's current time as NotBefore.
    If the BMC is behind that time, bmcweb sees the cert as not-yet-valid and
    fails the TLS handshake with SSLV3_ALERT_BAD_CERTIFICATE — surfacing as an
    opaque "bad certificate" error far from the actual cause.
    """
    assert_bmc_clock_in_sync(bmc_duthost)


@pytest.fixture(scope="module")
def redfish_feature_enabled(request, bmc_duthost, core_dump_and_config_check):
    """Make sure the redfish feature is enabled and its container is running.

    The image ships the redfish FEATURE row as "disabled" and expects it to be
    turned on at runtime, so the suite cannot assume the container is already
    up. Without this the first "docker exec redfish" in bmc_tls_certs fails with
    "No such container: redfish".

    Depends on the module config check so feature and TLS cleanup finish before
    config comparison/recovery. Restore the original state even if startup fails.
    """
    features, ok = bmc_duthost.get_feature_status()
    pyrequire(
        ok and BMCWEB_CONTAINER in features,
        "redfish FEATURE row not present on this DUT; the image was likely built "
        "without the redfish docker (INCLUDE_REDFISH=n)",
    )

    was_enabled = features[BMCWEB_CONTAINER] == "enabled"
    if not was_enabled:
        def restore_feature():
            logger.info("Restoring the original redfish feature state")
            bmc_duthost.shell(
                "sudo config feature state {} {}".format(BMCWEB_CONTAINER, features[BMCWEB_CONTAINER]))
        request.addfinalizer(restore_feature)
        logger.info("redfish feature is disabled, enabling it for this module")
        bmc_duthost.shell(
            "sudo config feature state {} enabled".format(BMCWEB_CONTAINER),
            module_ignore_errors=False,
        )

    pyrequire(
        wait_until(BMCWEB_READY_TIMEOUT, BMCWEB_READY_POLL, 0,
                   bmc_duthost.is_service_fully_started, BMCWEB_CONTAINER),
        "redfish container did not start within {}s of enabling the feature".format(
            BMCWEB_READY_TIMEOUT),
    )

    yield


@pytest.fixture(scope="module")
def redfish_port(bmc_duthost, redfish_feature_enabled):
    """The port the suite addresses the Redfish API on.

    The suite follows the device rather than reconfiguring it: the port bmcweb
    is actually listening on, else the one CONFIG_DB asks for.
    """
    port = listening_port(bmc_duthost) or configured_port(bmc_duthost)
    logger.info("Addressing the Redfish API on port {}".format(port))
    return port


@pytest.fixture(scope="module")
def bmc_tls_certs(request, bmc_duthost, bmc_ip, bmc_clock_in_sync, redfish_feature_enabled,
                  redfish_port, tmp_path_factory):
    """Provision TLS certificates for one module, then restore the original state.

    Certificates are delivered to the paths configured in CONFIG_DB, the way a
    provisioning agent does, rather than copied straight into the redfish
    container. The device therefore reaches mTLS by the same path it uses in
    production, and every Redfish module that needs client certificates gets
    them that way.

    Yields the local certificate paths: "cert"/"key"/"ca" for mTLS requests,
    plus "server_crt"/"server_key"/"dir"/"generator" so a test can re-deliver
    or reissue them to exercise rotation, and "port", the port to address.

    The redfish_feature_enabled dependency orders provisioning after the module
    config check's setup, and restoration before its teardown. A session-owned
    certificate set would otherwise outlive config recovery and lose its trusted
    client names. Originally provisioned devices retain their own certificates.
    """
    snapshot = snapshot_redfish_config(bmc_duthost)
    saved = back_up_device_state(bmc_duthost)

    # Registered before the device is touched, so it also runs when a setup
    # step below fails: code after the yield would be skipped in that case.
    def restore():
        logger.info("Restoring the BMC certificate and Redfish configuration state")
        reset_to_bootstrap(bmc_duthost, snapshot, saved)
    request.addfinalizer(restore)

    cert_dir = tmp_path_factory.mktemp("bmc_certs")
    logger.info("Generating TLS certificates in {}".format(cert_dir))

    # The client CN must match what the device is configured to trust, set in
    # client_crt_cname below.
    generator = build_cert_chain(cert_dir, bmc_ip, client_cn=CLIENT_CN)

    bmc_duthost.shell("mkdir -p {}".format(DELIVERY_DIR))
    db_set(bmc_duthost, "CONFIG_DB", REDFISH_CERTS_TABLE,
           server_crt=DELIVERED_SERVER_CRT,
           server_key=DELIVERED_SERVER_KEY,
           ca_crt=DELIVERED_CA_CRT)
    # sonic-dbus-bridge reads the trusted names once at startup, and an unset
    # list refuses everyone, so apply it through a bridge restart.
    pyrequire(set_trusted_cnames(bmc_duthost, CLIENT_CN),
              "sonic-dbus-bridge did not come back after configuring the trusted names")

    logger.info("Delivering certificates to the configured paths on {}".format(bmc_ip))
    deliver_certs(bmc_duthost, cert_dir)

    pyrequire(wait_for_staging(bmc_duthost),
              "Certificates were not staged within {}s; last_error={}".format(
                  STAGING_TIMEOUT, cert_status(bmc_duthost, "last_error")))
    logger.info("Certificates staged and mTLS enforced")

    yield {
        "cert": str(cert_dir / CLIENT_CERT_NAME),
        "key": str(cert_dir / CLIENT_KEY_NAME),
        "ca": str(cert_dir / CA_CERT_NAME),
        "server_crt": str(cert_dir / SERVER_CERT_NAME),
        "server_key": str(cert_dir / SERVER_KEY_NAME),
        "dir": cert_dir,
        "generator": generator,
        "port": redfish_port,
    }
