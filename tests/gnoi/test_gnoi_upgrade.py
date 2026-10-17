"""
Native gNOI image-upgrade test.

Stages a target image with the native gNOI client (``File.TransferToRemote`` +
``System.SetPackage``), reboots into it, and - the point of this test -
re-establishes the mTLS session across the image boundary with
:func:`tests.gnoi.gnoi_tls_setup.ensure_gnoi_ready` instead of persisting the
test configuration with ``config save``.

Why not ``config save`` the TLS setup across the upgrade
--------------------------------------------------------
On SONiC the test's ``GNMI_CLIENT_CERT`` row is version-gated in YANG and
``GNMI|certs`` points at ``/etc/sonic/telemetry`` (wiped on upgrade). Persisting
those rows and letting them cross config migration can leave the DUT with an
invalid config or a gnmi container crash-looping on missing certificate files
(see :mod:`tests.gnoi.gnoi_tls_setup`). The native suite keeps zero persistence
and re-provisions on the far side, which is one uniform path for a plain reboot
and an upgrade alike.

This test is skipped unless ``--base_image_list`` and ``--target_image_list`` are
provided, so it does not run in the plain virtual-switch loop. The
reboot-and-re-provision machinery it depends on is proven by
``test_gnoi_reboot.py``.
"""
import logging
import time

import pytest

from sonic_grpc.gnoi import common_pb2, file_pb2, system_pb2

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import wait_for_shutdown, wait_for_startup
from tests.gnoi import gnoi_tls_setup

logger = logging.getLogger(__name__)

DUT_IMAGE_PATH = "/var/tmp/sonic_image"

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.skip_check_dut_health,
    pytest.mark.disable_loganalyzer,
]


def _first(value):
    """Return the first image URL whether the option is a list or a scalar."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    if isinstance(value, str) and "," in value:
        return value.split(",")[0]
    return value


@pytest.mark.device_type("vs")
def test_gnoi_upgrade_and_reprovision(
    duthosts, rand_one_dut_hostname, localhost, request, gnoi_tls_bundle
):
    """Upgrade the DUT via native gNOI, then re-establish the mTLS session.

    Steps: TransferToRemote -> SetPackage -> System.Reboot -> wait down/up ->
    ensure_gnoi_ready -> assert the target image is current and gNOI is usable.
    """
    base_image = request.config.getoption("base_image_list")
    to_image = _first(request.config.getoption("target_image_list"))
    try:
        target_version = request.config.getoption("target_version")
    except (ValueError, KeyError):
        target_version = None

    if not base_image or not to_image:
        pytest.skip(
            "base_image_list/target_image_list not set; the native gNOI upgrade "
            "test requires a base/target image pair"
        )
    pytest_assert(
        target_version,
        "target_version must be set to validate the post-upgrade image",
    )

    upgrade_type = request.config.getoption("upgrade_type") or "cold"
    reboot_method = (
        system_pb2.RebootMethod.WARM
        if str(upgrade_type).lower() == "warm"
        else system_pb2.RebootMethod.COLD
    )

    duthost = duthosts[rand_one_dut_hostname]
    bundle = gnoi_tls_bundle

    duthost.shell("rm -f {}".format(DUT_IMAGE_PATH), module_ignore_errors=True)

    # 1) Transfer the image to the DUT the API way.
    client = bundle.open_client()
    try:
        client.file.TransferToRemote(
            file_pb2.TransferToRemoteRequest(
                local_path=DUT_IMAGE_PATH,
                remote_download=common_pb2.RemoteDownload(
                    path=to_image,
                    protocol=common_pb2.RemoteDownload.HTTP,
                ),
            ),
            timeout=3600,
        )
    finally:
        client.close()
    pytest_assert(
        duthost.shell("test -s {}".format(DUT_IMAGE_PATH), module_ignore_errors=True).get("rc", 1) == 0,
        "image not present on DUT after TransferToRemote: {}".format(DUT_IMAGE_PATH),
    )

    # 2) Stage it as the next-boot image (client-streaming SetPackage; a single
    #    request carries the metadata for an image already on the DUT).
    client = bundle.open_client()
    try:
        client.system.SetPackage(
            iter([
                system_pb2.SetPackageRequest(
                    package=system_pb2.Package(
                        filename=DUT_IMAGE_PATH,
                        version=target_version,
                        activate=True,
                    ),
                ),
            ]),
            timeout=3600,
        )
    finally:
        client.close()

    # 3) Reboot into the new image (trigger RPC; the channel may drop).
    client = bundle.open_client()
    try:
        client.system.Reboot(
            system_pb2.RebootRequest(
                method=reboot_method,
                message="native gNOI upgrade",
            ),
            timeout=60,
        )
    except Exception as exc:  # noqa: BLE001
        logger.info("System.Reboot trigger returned/raised (expected on drop): %s", exc)
    finally:
        client.close()

    reboot_start = time.time()
    wait_for_shutdown(duthost, localhost, delay=10, timeout=300)
    wait_for_startup(duthost, localhost, delay=10, timeout=600)
    wait_critical_processes(duthost)
    logger.info("DUT back up %.0fs after gNOI upgrade reboot", time.time() - reboot_start)

    # 4) Re-provision across the image boundary - NOT via config save.
    gnoi_tls_setup.ensure_gnoi_ready(duthost, bundle, timeout=300)

    # 5) Validate the boot image and that gNOI is usable on the new image.
    client = bundle.open_client()
    try:
        pytest_assert(
            client.system.Time(system_pb2.TimeRequest(), timeout=10).time > 0,
            "gNOI System.Time failed after upgrade",
        )
    finally:
        client.close()

    installed = duthost.shell("sonic-installer list", module_ignore_errors=False)["stdout"]
    logger.info("sonic-installer list after upgrade:\n%s", installed)
    pytest_assert(
        target_version in installed,
        "target version {} not present after upgrade:\n{}".format(target_version, installed),
    )
