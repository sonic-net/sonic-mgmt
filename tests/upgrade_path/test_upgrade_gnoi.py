import os
import logging
import pytest

# Ensure grpc fixtures are discovered (ptf_grpc / setup_gnoi_tls_server)
import tests.common.fixtures.grpc_fixtures  # noqa: F401

from tests.common.helpers.upgrade_helpers import gnoi_upgrade_test_helper

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.usefixtures("setup_gnoi_tls_server")


@pytest.fixture(scope="module")
def gnoi_upgrade_path_lists(request):
    """
    Reuse the same CLI options as test_upgrade_path.py:
      --upgrade_type (warm/cold)
      --base_image_list
      --target_image_list
      --restore_to_image
      --enable_cpa

    Interpretation:
      - target_image_list is treated as image URL for gNOI TransferToRemote
      - local_path uses a common name (no extension) to avoid assuming .bin
      - upgrade_type is used for:
          * reboot_method mapping (WARM/COLD) for gNOI
          * reboot-cause keyword expectation ("warm"/"cold")
      - expected_to_version is provided explicitly via env var TARGET_IMAGE_VERSION
    """
    upgrade_type = request.config.getoption("upgrade_type")          # "warm" / "cold"
    from_list = request.config.getoption("base_image_list")
    to_list = request.config.getoption("target_image_list")
    restore_to_image = request.config.getoption("restore_to_image")
    enable_cpa = request.config.getoption("enable_cpa")

    image_url = to_list

    # TODO: use a better common path/naming convention
    local_path = "/tmp/sonic_image"

    expected_to_version = os.environ.get("TARGET_IMAGE_VERSION")

    return upgrade_type, from_list, to_list, restore_to_image, enable_cpa, image_url, local_path, expected_to_version


@pytest.mark.device_type("vs")
def test_upgrade_gnoi(
    localhost, duthosts, ptfhost, rand_one_dut_hostname,
    nbrhosts, fanouthosts, tbinfo, request, restore_image,            # noqa: F811
    verify_dut_health, gnoi_upgrade_path_lists, ptf_grpc
):
    """
    Integration test for gNOI-based SONiC upgrade (minimal MOP validation).

    This test follows the same structure and parameter model as test_upgrade_path.py:
    - Reuses existing pytest CLI options (upgrade_type/base_image_list/target_image_list/...).
    - Treats target_image_list as the remote image URL for gNOI File.TransferToRemote.
    - Executes the gNOI upgrade flow via a common helper:
        1) gnoi.file.File.TransferToRemote: download the image to a DUT local path
        2) gnoi.system.System.SetPackage: set the downloaded image as the install/boot package
        3) gnoi.system.System.Reboot: trigger reboot (typically non-blocking)

    TLS:
    All gNOI RPCs run with TLS enabled by default. The module uses the
    'setup_gnoi_tls_server' fixture so users do not need to manually configure TLS.

    Validations:
    - Asserts after each gNOI RPC call.
    - Validates the downloaded image exists on the DUT.
    - Waits for reboot completion by polling reboot-cause using the same
        wait_until(...) + check_reboot_cause(...) pattern as upgrade_test_helper.
    - Runs standard post-reboot health checks (services, neighbors, CoPP).
    - Verifies the running SONiC version after reboot matches the expected target
        version (provided via test inputs/pipeline, e.g. TARGET_IMAGE_VERSION).

    Notes:
    - gNOI System.Reboot may drop the gRPC connection during reboot; this is expected.
    - The authoritative success criteria are reboot-cause/health checks and the
        post-reboot running version match, not the Reboot RPC response alone.
    """
    duthost = duthosts[rand_one_dut_hostname]

    (upgrade_type, from_image, to_image, _restore_to_image, _enable_cpa,
     image_url, local_path, expected_to_version) = gnoi_upgrade_path_lists

    logger.info("Test gNOI upgrade path from %s to %s", from_image, to_image)

    def upgrade_path_preboot_setup():
        cur = duthost.shell("show version", module_ignore_errors=False)["stdout"]
        logger.info("Pre-upgrade show version:\n%s", cur)
        # Clean up any previous image at local_path
        duthost.shell(f"rm -f {local_path}", module_ignore_errors=True)

    upgrade_path_preboot_setup()

    assert image_url, "target_image_list must be set (used as image_url for gNOI TransferToRemote)"
    assert expected_to_version, "TARGET_IMAGE_VERSION must be set for post-upgrade version validation"

    # Map upgrade_type ("warm"/"cold") to gNOI reboot method enum ("WARM"/"COLD")
    reboot_method = "WARM" if str(upgrade_type).lower() == "warm" else "COLD"

    gnoi_upgrade_test_helper(
        ptf_grpc=ptf_grpc,
        duthost=duthost,
        image_url=image_url,
        local_path=local_path,
        reboot_method=reboot_method,       # gNOI expects enum-style string
        upgrade_type=upgrade_type,         # used for reboot-cause keyword match ("warm"/"cold")
        expected_to_version=expected_to_version,
        allow_fail=False,
    )
