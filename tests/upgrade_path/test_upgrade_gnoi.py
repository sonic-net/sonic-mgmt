import os
import logging
import pytest

# Ensure grpc fixtures are discovered (ptf_gnoi / setup_gnoi_tls_server)
from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    setup_gnoi_tls_server, ptf_gnoi, ptf_grpc
)

from tests.common.helpers.upgrade_helpers import perform_gnoi_upgrade

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.usefixtures("setup_gnoi_tls_server"),
]


@pytest.fixture(scope="module")
def gnoi_upgrade_path_lists(request):
    upgrade_type = request.config.getoption("upgrade_type")          # "warm" / "cold"
    from_list = request.config.getoption("base_image_list")
    image_url = request.config.getoption("target_image_list")
    restore_to_image = request.config.getoption("restore_to_image")

    dut_image_path = "/tmp/sonic_image"
    expected_to_version = os.environ.get("TARGET_IMAGE_VERSION")

    return upgrade_type, from_list, image_url, restore_to_image, dut_image_path, expected_to_version


@pytest.mark.device_type("vs")
def test_upgrade_via_gnoi(
    localhost, duthosts, ptfhost, rand_one_dut_hostname,
    nbrhosts, fanouthosts, tbinfo, request, restore_image,            # noqa: F811
    verify_dut_health, gnoi_upgrade_path_lists, ptf_gnoi
):
    duthost = duthosts[rand_one_dut_hostname]

    (upgrade_type, from_image, image_url, _restore_to_image, dut_image_path, expected_to_version) = gnoi_upgrade_path_lists

    logger.info("Test gNOI upgrade path from %s to %s", from_image, image_url)

    cur = duthost.shell("show version", module_ignore_errors=False)["stdout"]
    logger.info("Pre-upgrade show version:\n%s", cur)

    duthost.shell(f"rm -f {dut_image_path}", module_ignore_errors=True)

    assert image_url, "target_image_list must be set (used as image_url for gNOI TransferToRemote)"
    assert expected_to_version, "TARGET_IMAGE_VERSION must be set for post-upgrade version validation"

    perform_gnoi_upgrade(
        ptf_gnoi=ptf_gnoi,
        duthost=duthost,
        tbinfo=tbinfo,
        image_url=image_url,
        dut_image_path=dut_image_path,
        upgrade_type=upgrade_type,
        expected_to_version=expected_to_version,
        protocol="HTTP",
        allow_fail=False,
    )
