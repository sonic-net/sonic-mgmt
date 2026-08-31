import ipaddress
import logging
import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.secure_boot import (
    get_current_image,
    get_inactive_image,
    get_installed_images,
    require_secure_boot,
    restore_image_selection,
)


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

DOWNLOADED_IMAGE_PATH = "/host/secure_boot_duplicate_db_test_image"
EXTRACTED_DB_AUTH_PATH = "/tmp/secure_boot_duplicate_db_test.auth"
UEFI_DB_VARIABLE = (
    "/sys/firmware/efi/efivars/"
    "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
)

logger = logging.getLogger(__name__)


def _get_image_db_auth_path(image_name):
    version = image_name[len("SONiC-OS-"):] if image_name.startswith("SONiC-OS-") else image_name
    return "/host/image-{}/boot/DB.auth".format(version)


def _download_image(duthost, image_url, tbinfo):
    mgmt_gateway = duthost.get_extended_minigraph_facts(tbinfo).get(
        "minigraph_mgmt_interface", {}
    ).get("gwaddr")
    pytest_assert(mgmt_gateway, "The DUT does not have a management gateway")

    mgmt_gateway = ipaddress.IPv4Address(mgmt_gateway)
    route_info = duthost.get_ip_route_info(ipaddress.ip_network("0.0.0.0/0"))
    route_added = not any(mgmt_gateway == nexthop[0] for nexthop in route_info["nexthops"])

    try:
        if route_added:
            duthost.command("sudo ip route replace default via {}".format(mgmt_gateway))
        duthost.command(
            "sudo curl --fail --location --output {} {}".format(
                shlex.quote(DOWNLOADED_IMAGE_PATH),
                shlex.quote(image_url),
            )
        )
    finally:
        if route_added:
            duthost.command(
                "sudo ip route del default via {}".format(mgmt_gateway),
                module_ignore_errors=True,
            )


def _extract_db_auth(duthost):
    command = r"""
set -eu
image={image}
output={output}
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
header_size=$(sed '/^exit_marker$/q' "$image" | wc -c)
tail -c +$((header_size + 1)) "$image" |
    tar --occurrence=1 -xO installer/fs.zip 2>/dev/null > "$tmp_dir/fs.zip"
unzip -p "$tmp_dir/fs.zip" boot/DB.auth > "$output"
test -s "$output"
""".format(
        image=shlex.quote(DOWNLOADED_IMAGE_PATH),
        output=shlex.quote(EXTRACTED_DB_AUTH_PATH),
    )
    duthost.shell(command)


def _get_firmware_db_state(duthost):
    result = duthost.command("sudo efi-readvar -v db", module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "Failed to read the UEFI db variable: {}".format(result["stderr"]),
    )
    return result["stdout"].strip()


def _get_persisted_db_auth_state(duthost):
    command = (
        "sudo find /host/db-auth -maxdepth 1 -type f -name 'DB-*.auth' "
        "-exec sha256sum {} + | sort"
    )
    return duthost.shell(command)["stdout"].strip()


def _apply_installed_image_db_auth(duthost, image_name):
    db_auth_path = _get_image_db_auth_path(image_name)
    command = (
        "sudo chattr -i {db_variable} 2>/dev/null || true; "
        "sudo efi-updatevar -a -f {db_auth} db"
    ).format(
        db_variable=shlex.quote(UEFI_DB_VARIABLE),
        db_auth=shlex.quote(db_auth_path),
    )
    result = duthost.shell(
        command,
        module_ignore_errors=True,
    )
    if result["rc"] != 0:
        logger.info(
            "Firmware rejected the identical authenticated DB update replay: %s",
            "{}\n{}".format(result["stdout"], result["stderr"]).strip(),
        )


def test_reinstall_identical_db_certificate(duthost, request, tbinfo):
    """Verify that reinstalling an identical DB certificate creates no duplicate."""
    require_secure_boot(duthost)

    image_url = request.config.getoption("secure_boot_second_image_url")
    original_image = get_current_image(duthost)
    original_db_auth = _get_image_db_auth_path(original_image)
    installed_images_before = get_installed_images(duthost)
    target_version = None
    target_db_auth = None

    try:
        if image_url:
            _download_image(duthost, image_url, tbinfo)
            _extract_db_auth(duthost)
            target_db_auth = EXTRACTED_DB_AUTH_PATH
            target_version = duthost.command(
                "sonic-installer binary_version {}".format(shlex.quote(DOWNLOADED_IMAGE_PATH))
            )["stdout"].strip()
            if target_version in installed_images_before:
                pytest.skip("The second image version is already installed")
        else:
            target_version = get_inactive_image(installed_images_before, original_image)
            target_db_auth = _get_image_db_auth_path(target_version)

        same_certificate = duthost.command(
            "sudo cmp -s {} {}".format(
                shlex.quote(target_db_auth),
                shlex.quote(original_db_auth),
            ),
            module_ignore_errors=True,
        )
        if same_certificate["rc"] != 0:
            pytest.skip("The second image does not contain the same DB.auth as the running image")

        firmware_db_before = _get_firmware_db_state(duthost)
        persisted_auth_before = _get_persisted_db_auth_state(duthost)

        if image_url:
            install_result = duthost.reduce_and_add_sonic_images(save_as=DOWNLOADED_IMAGE_PATH)
            installed_version = install_result["ansible_facts"]["downloaded_image_version"]
            pytest_assert(
                installed_version == target_version,
                "Installed image {} does not match downloaded image {}".format(
                    installed_version,
                    target_version,
                ),
            )
        else:
            _apply_installed_image_db_auth(duthost, target_version)

        pytest_assert(
            _get_firmware_db_state(duthost) == firmware_db_before,
            "Reinstalling an identical DB certificate changed the UEFI db variable",
        )
        pytest_assert(
            _get_persisted_db_auth_state(duthost) == persisted_auth_before,
            "Reinstalling an identical DB certificate changed /host/db-auth",
        )
    finally:
        duthost.command(
            "sudo rm -f {} {}".format(
                shlex.quote(DOWNLOADED_IMAGE_PATH),
                shlex.quote(EXTRACTED_DB_AUTH_PATH),
            ),
            module_ignore_errors=True,
        )
        restore_image_selection(duthost, original_image)

        if image_url and target_version and target_version not in installed_images_before:
            duthost.command(
                "sudo sonic-installer remove {} -y".format(shlex.quote(target_version)),
                module_ignore_errors=True,
            )
