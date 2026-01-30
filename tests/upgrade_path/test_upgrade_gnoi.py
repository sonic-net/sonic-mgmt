import os
import time
import logging
import pytest

# Import fixtures module to ensure pytest discovers them
import tests.common.fixtures.grpc_fixtures  # noqa: F401

logger = logging.getLogger(__name__)
# Enable TLS fixture by default for all tests in this module
pytestmark = pytest.mark.usefixtures("setup_gnoi_tls_server")

@pytest.fixture(scope="module")
def gnoi_upgrade_path_lists(request):
    """
    Mapping for gNOI flow:
      - image_url      := target_image_list
      - local_path     := /tmp/<basename(image_url)>
      - reboot_method  := "WARM" if upgrade_type == "warm" else "COLD"
    """
    upgrade_type = request.config.getoption("upgrade_type")
    from_list = request.config.getoption("base_image_list")
    to_list = request.config.getoption("target_image_list")
    restore_to_image = request.config.getoption("restore_to_image")
    enable_cpa = request.config.getoption("enable_cpa")

    # gNOI specific derived params
    image_url = to_list
    basename = os.path.basename(image_url) if image_url else "sonic-image.bin"
    local_path = f"/tmp/{basename}"

    reboot_method = "WARM" if str(upgrade_type).lower() == "warm" else "COLD"

    return upgrade_type, from_list, to_list, restore_to_image, enable_cpa, image_url, local_path, reboot_method


@pytest.mark.device_type("vs")
def test_gnoi_minimal_upgrade(ptf_grpc, ptf_gnoi, duthost, gnoi_upgrade_path_lists):
    (upgrade_type, from_image, to_image, restore_to_image, enable_cpa,
     image_url, local_path, reboot_method) = gnoi_upgrade_path_lists
    assert image_url, "target_image_list is required (used as gNOI image URL)"

    logger.info("gNOI minimal upgrade: upgrade_type=%s image_url=%s local_path=%s reboot=%s",
                upgrade_type, image_url, local_path, reboot_method)

    ptf_grpc.call_unary("gnoi.file.File", "TransferToRemote", {
        "local_path": local_path,
        "remote_download": {
            "path": image_url,
            "protocol": "HTTP",
        }
    })

    ptf_grpc.call_unary("gnoi.system.System", "SetPackage", {
        "package": {"filename": local_path}
    })

    try:
        ptf_grpc.call_unary("gnoi.system.System", "Reboot", {"method": reboot_method})
    except Exception as e:
        logger.warning("Reboot RPC error (may be expected): %s", e)

    t = ptf_gnoi.system_time()
    assert "time" in t and isinstance(t["time"], int)
    logger.info("Post-reboot System time: %s", t["time"])
