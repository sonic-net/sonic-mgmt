import ipaddress
import logging
import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.secure_boot import (
    require_secure_boot,
    restore_active_efi_bundle,
)
from tests.common.helpers.upgrade_helpers import (
    get_inactive_images,
    set_default_and_next_image,
)


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

DOWNLOADED_IMAGE_PATH = "/host/secure_boot_duplicate_db_test_image"
EXTRACTED_DB_AUTH_PATH = "/tmp/secure_boot_duplicate_db_test.auth"
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


def _get_firmware_db_fingerprints(duthost):
    command = r"""
set -eu
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
sudo efi-readvar -v db -o "$work/db.esl" >/dev/null
sudo sig-list-to-certs "$work/db.esl" "$work/db" >/dev/null
for cert in "$work"/db-*.der; do
    [ -e "$cert" ] || continue
    sudo openssl x509 -inform DER -in "$cert" -noout -fingerprint -sha256 |
        sed 's/^.*=//; s/://g' |
        tr '[:upper:]' '[:lower:]'
done
"""
    result = duthost.shell(command, module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "Failed to read UEFI db fingerprints: {}".format(result["stderr"]),
    )
    return sorted(result["stdout_lines"])


def _get_db_auth_fingerprints(duthost, auth_path):
    command = r"""
set -eu
auth={auth}
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
set -- $(sudo dd if="$auth" bs=1 skip=16 count=4 2>/dev/null | od -An -tu1)
[ "$#" -eq 4 ]
header_length=$((16 + $1 + ($2 * 256) + ($3 * 65536) + ($4 * 16777216)))
sudo dd if="$auth" of="$work/db.esl" bs=1 skip="$header_length" 2>/dev/null
test -s "$work/db.esl"
sudo sig-list-to-certs "$work/db.esl" "$work/db" >/dev/null
for cert in "$work"/db-*.der; do
    [ -e "$cert" ] || continue
    sudo openssl x509 -inform DER -in "$cert" -noout -fingerprint -sha256 |
        sed 's/^.*=//; s/://g' |
        tr '[:upper:]' '[:lower:]'
done | sort -u
""".format(auth=shlex.quote(auth_path))
    result = duthost.shell(command, module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "Failed to read DB.auth fingerprints from {}: {}".format(
            auth_path,
            result["stderr"],
        ),
    )
    return set(result["stdout_lines"])


def _get_persisted_db_auth_state(duthost):
    command = (
        "sudo find /host/db-auth -maxdepth 1 -type f -name 'DB-*.auth' "
        "-exec sha256sum {} + | sort"
    )
    return duthost.shell(command)["stdout"].strip()


def _get_matching_persisted_db_auth(duthost, db_auth_path):
    command = r"""
for persisted_auth in /host/db-auth/DB-*.auth; do
    [ -e "$persisted_auth" ] || continue
    if sudo cmp -s {db_auth} "$persisted_auth"; then
        printf '%s\n' "$persisted_auth"
    fi
done
""".format(
        db_auth=shlex.quote(db_auth_path),
    )
    return duthost.shell(command)["stdout_lines"]


def _assert_db_certificate_is_not_duplicated(duthost, db_auth_path):
    target_fingerprints = _get_db_auth_fingerprints(duthost, db_auth_path)
    pytest_assert(target_fingerprints, "DB.auth does not contain an X.509 certificate")

    firmware_fingerprints = _get_firmware_db_fingerprints(duthost)
    duplicate_fingerprints = {
        fingerprint: firmware_fingerprints.count(fingerprint)
        for fingerprint in target_fingerprints
        if firmware_fingerprints.count(fingerprint) != 1
    }
    pytest_assert(
        not duplicate_fingerprints,
        "DB certificate is missing or duplicated in UEFI db: {}".format(
            duplicate_fingerprints
        ),
    )

    persisted_matches = _get_matching_persisted_db_auth(duthost, db_auth_path)
    pytest_assert(
        len(persisted_matches) == 1,
        "Expected one persisted copy of DB.auth, found {}: {}".format(
            len(persisted_matches),
            persisted_matches,
        ),
    )


def test_reinstall_identical_db_certificate(duthost, request, tbinfo):
    """Verify that reinstalling an identical DB certificate creates no duplicate."""
    require_secure_boot(duthost)

    image_url = request.config.getoption("secure_boot_second_image_url")
    image_info = duthost.get_image_info()
    original_image = image_info["current"]
    original_db_auth = _get_image_db_auth_path(original_image)
    installed_images_before = image_info["installed_list"]
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
            inactive_images = get_inactive_images(duthost)
            if not inactive_images:
                pytest.skip("--secure_boot_second_image_url or an installed inactive image is required")
            target_version = inactive_images[0]
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

        firmware_db_before = _get_firmware_db_fingerprints(duthost)
        persisted_auth_before = _get_persisted_db_auth_state(duthost)
        _assert_db_certificate_is_not_duplicated(duthost, target_db_auth)

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

        pytest_assert(
            _get_firmware_db_fingerprints(duthost) == firmware_db_before,
            "Reinstalling an identical DB certificate changed the UEFI db variable",
        )
        pytest_assert(
            _get_persisted_db_auth_state(duthost) == persisted_auth_before,
            "Reinstalling an identical DB certificate changed /host/db-auth",
        )
        _assert_db_certificate_is_not_duplicated(duthost, target_db_auth)
    finally:
        duthost.command(
            "sudo rm -f {} {}".format(
                shlex.quote(DOWNLOADED_IMAGE_PATH),
                shlex.quote(EXTRACTED_DB_AUTH_PATH),
            ),
            module_ignore_errors=True,
        )
        set_default_and_next_image(duthost, original_image)

        if image_url and target_version and target_version not in installed_images_before:
            restore_active_efi_bundle(duthost, original_image)
            duthost.command(
                "sudo sonic-installer remove {} -y".format(shlex.quote(target_version)),
                module_ignore_errors=True,
            )
