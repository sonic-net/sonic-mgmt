import datetime
import ipaddress
import logging
import os
import re
import shlex
import struct
import sys
import tempfile

import pytest

from tests.common import reboot
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.secure_boot import (
    mount_efi_system_partition,
    require_secure_boot,
    restore_active_efi_bundle,
    unmount_efi_system_partition,
)
from tests.common.helpers.upgrade_helpers import set_default_and_next_image


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

DOWNLOADED_IMAGE_PATH = "/host/secure_boot_sbat_candidate_image"
EXTRACTED_BUNDLE_DIR = "/host/secure_boot_sbat_candidate_bundle"
EFI_COMPONENTS = ("shimx64.efi", "grubx64.efi", "mmx64.efi")
KVM_PLATFORM = "x86_64-kvm_x86_64-r0"
SBAT_TIMESTAMP_PATTERN = re.compile(
    rb"sbat,\d+,(\d{8}|\d{10}|\d{12}|\d{14})\n"
)

logger = logging.getLogger(__name__)


def _get_image_dir(image_name):
    version = image_name
    if version.startswith("SONiC-OS-"):
        version = version[len("SONiC-OS-"):]
    return "/host/image-{}".format(version)


def _get_image_boot_dir(image_name):
    return "{}/boot".format(_get_image_dir(image_name))


def _recover_kvm_pmon(duthost):
    if duthost.facts.get("platform") != KVM_PLATFORM:
        return

    duthost.shell(r"""
set -eu
if [ ! -e /dev/watchdog1 ]; then
    sudo mknod -m 0600 /dev/watchdog1 c 1 3
fi
sudo systemctl reset-failed pmon.service
sudo systemctl restart pmon.service
for attempt in $(seq 1 24); do
    if systemctl is-active --quiet pmon.service &&
            [ "$(docker inspect -f '{{.State.Running}}' pmon)" = true ]; then
        exit 0
    fi
    sleep 5
done
systemctl status --no-pager pmon.service || true
docker inspect pmon || true
exit 1
""")


def _reboot_for_sbat_test(duthost, localhost):
    if duthost.facts.get("platform") == KVM_PLATFORM:
        reboot(duthost, localhost)
        _recover_kvm_pmon(duthost)
    else:
        reboot(duthost, localhost, safe_reboot=True)


def _preserve_config_for_candidate_image(duthost, target_version):
    """Make sure the candidate image boots up with the current configuration.

    A freshly installed image does not carry over the currently running
    configuration. On minigraph-based testbeds, SONiC's first-boot
    config-setup only restores a previous ``config_db.json`` via its
    migration path, which this install flow does not trigger; otherwise it
    regenerates configuration purely from ``minigraph.xml``. That regenerated
    configuration does not include locally configured items such as
    AAA/user accounts, so the candidate image can come up with different
    login credentials than the rest of the test expects.

    The SBAT bundle tests install a candidate image that only differs in its
    SBAT/bootloader bundle, so it should come back up with the exact same
    configuration as the currently running image. Copy the running
    configuration directly into the candidate image's own config_db.json so
    its first boot uses it unmodified, instead of regenerating configuration
    from the minigraph.
    """
    target_config_dir = "{}/rw/etc/sonic".format(
        _get_image_dir(target_version)
    )
    target_config_db = "{}/config_db.json".format(target_config_dir)
    duthost.shell(
        "sudo mkdir -p {} && sudo cp /etc/sonic/config_db.json {}".format(
            shlex.quote(target_config_dir),
            shlex.quote(target_config_db),
        )
    )


def _download_image(duthost, image_url, tbinfo):
    mgmt_gateway = duthost.get_extended_minigraph_facts(tbinfo).get(
        "minigraph_mgmt_interface", {}
    ).get("gwaddr")
    pytest_assert(mgmt_gateway, "The DUT does not have a management gateway")

    route_info = duthost.get_ip_route_info(
        ipaddress.ip_network("0.0.0.0/0")
    )
    route_added = not any(
        str(nexthop[0]) == str(mgmt_gateway)
        for nexthop in route_info["nexthops"]
    )

    try:
        if route_added:
            duthost.command(
                "sudo ip route replace default via {}".format(mgmt_gateway)
            )
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


def _extract_bundle(duthost):
    command = r"""
set -eu
image={image}
output={output}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
header_size=$(sed '/^exit_marker$/q' "$image" | wc -c)
tail -c +$((header_size + 1)) "$image" |
    tar --occurrence=1 -xO installer/fs.zip 2>/dev/null > "$work/fs.zip"
rm -rf "$output"
mkdir -p "$output"
for file in shimx64.efi grubx64.efi mmx64.efi DB.auth; do
    unzip -p "$work/fs.zip" "boot/$file" > "$output/$file"
    test -s "$output/$file"
done
""".format(
        image=shlex.quote(DOWNLOADED_IMAGE_PATH),
        output=shlex.quote(EXTRACTED_BUNDLE_DIR),
    )
    duthost.shell(command)


def _get_bundle_hashes(duthost, bundle_dir):
    command = "sha256sum {}".format(
        " ".join(
            shlex.quote(os.path.join(bundle_dir, component))
            for component in EFI_COMPONENTS
        )
    )
    result = duthost.command(command, module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "Failed to hash EFI bundle {}: {}".format(
            bundle_dir,
            _get_command_output(result),
        ),
    )
    hashes = {}
    for line in result["stdout_lines"]:
        digest, path = line.split(None, 1)
        hashes[os.path.basename(path.strip())] = digest
    pytest_assert(
        set(hashes) == set(EFI_COMPONENTS),
        "Incomplete EFI bundle hashes for {}: {}".format(
            bundle_dir,
            hashes,
        ),
    )
    return hashes


def _get_section(data, section_name):
    pytest_assert(data[:2] == b"MZ", "Shim is missing its DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    pytest_assert(
        data[pe_offset:pe_offset + 4] == b"PE\0\0",
        "Shim is missing its PE signature",
    )

    coff_offset = pe_offset + 4
    section_count = struct.unpack_from("<H", data, coff_offset + 2)[0]
    optional_header_size = struct.unpack_from(
        "<H", data, coff_offset + 16
    )[0]
    section_offset = coff_offset + 20 + optional_header_size
    symbol_table_offset, symbol_count = struct.unpack_from(
        "<II", data, coff_offset + 8
    )
    string_table_offset = symbol_table_offset + symbol_count * 18

    for index in range(section_count):
        header_offset = section_offset + index * 40
        raw_name = data[header_offset:header_offset + 8].rstrip(b"\0")
        name = raw_name
        if raw_name.startswith(b"/"):
            name_offset = int(raw_name[1:])
            name_start = string_table_offset + name_offset
            name_end = data.find(b"\0", name_start)
            pytest_assert(name_end != -1, "Shim has an invalid section name")
            name = data[name_start:name_end]
        raw_size, raw_offset = struct.unpack_from(
            "<II", data, header_offset + 16
        )
        pytest_assert(
            raw_offset + raw_size <= len(data),
            "Shim section {} exceeds the file size".format(name),
        )
        if name == section_name:
            return data[raw_offset:raw_offset + raw_size]

    pytest_assert(False, "Shim is missing the .sbatlevel section")


def _read_sbat_timestamp(duthost, shim_path):
    with tempfile.NamedTemporaryFile() as local_shim:
        duthost.fetch(
            src=shim_path,
            dest=local_shim.name,
            flat=True,
        )
        local_shim.seek(0)
        section = _get_section(local_shim.read(), b".sbatlevel")

    pytest_assert(
        len(section) >= 12,
        "Shim has an invalid .sbatlevel header",
    )
    version, relative_offset = struct.unpack_from("<II", section, 0)
    pytest_assert(
        version == 0,
        "Shim has unsupported .sbatlevel version {}".format(version),
    )
    automatic_offset = 4 + relative_offset
    match = SBAT_TIMESTAMP_PATTERN.match(section, automatic_offset)
    pytest_assert(
        match is not None,
        "Shim is missing its automatic SBAT timestamp",
    )

    value = match.group(1).decode("ascii")
    date = datetime.datetime.strptime(value[:8], "%Y%m%d").date()
    sequence = int(value[8:] or "0")
    return (date, sequence), value


def _get_active_bundle_hashes(duthost):
    active_efi_dir = mount_efi_system_partition(duthost)
    try:
        return _get_bundle_hashes(duthost, active_efi_dir)
    finally:
        unmount_efi_system_partition(duthost)


def _read_active_sbat_timestamp(duthost):
    active_efi_dir = mount_efi_system_partition(duthost)
    try:
        return _read_sbat_timestamp(
            duthost,
            os.path.join(active_efi_dir, "shimx64.efi"),
        )
    finally:
        unmount_efi_system_partition(duthost)


def _get_command_output(result):
    return "{}\n{}".format(
        result.get("stdout", ""),
        result.get("stderr", ""),
    ).strip()


def _assert_booted_with_secure_boot(duthost, expected_image):
    image_info = duthost.get_image_info()
    pytest_assert(
        image_info["current"] == expected_image,
        "DUT booted {} instead of {}".format(
            image_info["current"],
            expected_image,
        ),
    )
    secure_boot_state = duthost.command(
        "mokutil --sb-state",
        module_ignore_errors=True,
    )
    pytest_assert(
        secure_boot_state["rc"] == 0
        and "SecureBoot enabled" in secure_boot_state["stdout"],
        "Secure Boot is not enabled after booting {}: {}".format(
            expected_image,
            _get_command_output(secure_boot_state),
        ),
    )


def _require_valid_firmware_db(duthost):
    command = r"""
set -eu
work=$(mktemp -d)
trap 'sudo chattr -i "$work/db.esl" 2>/dev/null || true; \
sudo rm -rf "$work"' EXIT
sudo efi-readvar -v db -o "$work/db.esl"
sudo chmod 0644 "$work/db.esl"
test -s "$work/db.esl"
mkdir "$work/certs"
timeout 30s sig-list-to-certs "$work/db.esl" "$work/certs/db" > /dev/null
find "$work/certs" -type f -name '*.der' -size +0c | grep -q .
"""
    result = duthost.shell(command, module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "The firmware Secure Boot db is empty or malformed: {}".format(
            _get_command_output(result)
        ),
    )


def _verify_sbat_bundle_selection(
    duthost,
    localhost,
    request,
    tbinfo,
    image_url_option,
    incoming_is_newer,
):
    if duthost.facts["asic_type"] != "vs":
        pytest.skip("The initial SBAT bundle tests support KVM only")
    require_secure_boot(duthost)
    _require_valid_firmware_db(duthost)

    image_url = request.config.getoption(image_url_option)
    pytest_assert(
        image_url,
        "--{} is required".format(image_url_option),
    )

    image_info = duthost.get_image_info()
    original_image = image_info["current"]
    installed_images_before = image_info["installed_list"]
    original_boot_dir = _get_image_boot_dir(original_image)
    target_version = None
    install_started = False

    try:
        original_bundle_hashes = _get_active_bundle_hashes(duthost)
        original_sbat, original_sbat_value = (
            _read_active_sbat_timestamp(duthost)
        )

        _download_image(duthost, image_url, tbinfo)
        _extract_bundle(duthost)

        incoming_bundle_hashes = _get_bundle_hashes(
            duthost,
            EXTRACTED_BUNDLE_DIR,
        )
        incoming_sbat, incoming_sbat_value = _read_sbat_timestamp(
            duthost,
            os.path.join(EXTRACTED_BUNDLE_DIR, "shimx64.efi"),
        )
        if incoming_is_newer:
            pytest_assert(
                incoming_sbat > original_sbat,
                "The candidate image shim SBAT level {} is not newer than "
                "the installed level {}".format(
                    incoming_sbat_value,
                    original_sbat_value,
                ),
            )
            expected_active_hashes = incoming_bundle_hashes
            expected_selection = "incoming"
        else:
            pytest_assert(
                incoming_sbat < original_sbat,
                "The candidate image shim SBAT level {} is not older than "
                "the installed level {}".format(
                    incoming_sbat_value,
                    original_sbat_value,
                ),
            )
            expected_active_hashes = original_bundle_hashes
            expected_selection = "installed"
        pytest_assert(
            incoming_bundle_hashes != original_bundle_hashes,
            "The candidate image contains the installed EFI bundle",
        )

        same_db_auth = duthost.command(
            "sudo cmp -s {} {}".format(
                shlex.quote(
                    os.path.join(EXTRACTED_BUNDLE_DIR, "DB.auth")
                ),
                shlex.quote(
                    os.path.join(original_boot_dir, "DB.auth")
                ),
            ),
            module_ignore_errors=True,
        )
        pytest_assert(
            same_db_auth["rc"] == 0,
            "The candidate image must use the running image's DB.auth",
        )

        target_version = duthost.command(
            "sonic-installer binary_version {}".format(
                shlex.quote(DOWNLOADED_IMAGE_PATH)
            )
        )["stdout"].strip()
        pytest_assert(target_version, "The candidate image version is empty")
        pytest_assert(
            target_version not in installed_images_before,
            "The candidate image {} is already installed".format(
                target_version
            ),
        )

        install_started = True
        install_result = duthost.reduce_and_add_sonic_images(
            save_as=DOWNLOADED_IMAGE_PATH
        )
        installed_version = install_result["ansible_facts"][
            "downloaded_image_version"
        ]
        pytest_assert(
            installed_version == target_version,
            "Installed image {} does not match candidate image {}".format(
                installed_version,
                target_version,
            ),
        )

        target_boot_dir = _get_image_boot_dir(target_version)
        pytest_assert(
            _get_bundle_hashes(duthost, target_boot_dir)
            == incoming_bundle_hashes,
            "The installed image EFI bundle differs from the candidate",
        )
        pytest_assert(
            _get_active_bundle_hashes(duthost) == expected_active_hashes,
            "The active EFI directory does not contain the complete {} "
            "bundle".format(expected_selection),
        )

        _preserve_config_for_candidate_image(duthost, target_version)
        set_default_and_next_image(duthost, target_version)
        _reboot_for_sbat_test(duthost, localhost)
        _assert_booted_with_secure_boot(duthost, target_version)
        pytest_assert(
            _get_active_bundle_hashes(duthost) == expected_active_hashes,
            "The active EFI directory does not contain the complete {} "
            "bundle after reboot".format(expected_selection),
        )
    finally:
        body_failed = sys.exc_info()[0] is not None
        cleanup_errors = []

        try:
            set_default_and_next_image(duthost, original_image)
        except Exception as error:
            cleanup_errors.append(
                "failed to select the original image: {}".format(error)
            )

        original_image_active = False
        try:
            cleanup_image_info = duthost.get_image_info()
            if cleanup_image_info["current"] != original_image:
                _reboot_for_sbat_test(duthost, localhost)
                _assert_booted_with_secure_boot(duthost, original_image)
                cleanup_image_info = duthost.get_image_info()
            original_image_active = (
                cleanup_image_info["current"] == original_image
            )
        except Exception as error:
            cleanup_errors.append(
                "failed to boot the original image: {}".format(error)
            )

        if install_started and not original_image_active:
            cleanup_errors.append(
                "skipped destructive cleanup because the original image "
                "is not running"
            )

        if install_started and original_image_active:
            try:
                restore_active_efi_bundle(duthost, original_image)
                restored_hashes = _get_active_bundle_hashes(duthost)
                if restored_hashes != original_bundle_hashes:
                    cleanup_errors.append(
                        "restored EFI bundle does not match the original"
                    )
            except Exception as error:
                cleanup_errors.append(
                    "failed to restore the original EFI bundle: {}".format(
                        error
                    )
                )

            if target_version:
                try:
                    installed_images = duthost.get_image_info()[
                        "installed_list"
                    ]
                    if target_version in installed_images:
                        remove_result = duthost.command(
                            "sudo sonic-installer remove {} -y".format(
                                shlex.quote(target_version)
                            ),
                            module_ignore_errors=True,
                        )
                        if remove_result["rc"] != 0:
                            cleanup_errors.append(
                                "failed to remove candidate image {}: "
                                "{}".format(
                                    target_version,
                                    _get_command_output(remove_result),
                                )
                            )
                except Exception as error:
                    cleanup_errors.append(
                        "failed to remove candidate image {}: {}".format(
                            target_version,
                            error,
                        )
                    )

        try:
            remove_result = duthost.command(
                "sudo rm -rf {} {}".format(
                    shlex.quote(DOWNLOADED_IMAGE_PATH),
                    shlex.quote(EXTRACTED_BUNDLE_DIR),
                ),
                module_ignore_errors=True,
            )
            if remove_result["rc"] != 0:
                cleanup_errors.append(
                    "failed to remove temporary artifacts: {}".format(
                        _get_command_output(remove_result)
                    )
                )
        except Exception as error:
            cleanup_errors.append(
                "failed to remove temporary artifacts: {}".format(error)
            )

        if cleanup_errors:
            cleanup_message = "Secure Boot cleanup failures: {}".format(
                "; ".join(cleanup_errors)
            )
            if body_failed:
                logger.error(cleanup_message)
            else:
                pytest_assert(False, cleanup_message)


def test_newer_sbat_bundle_replaces_installed_bundle(
    duthost,
    localhost,
    request,
    tbinfo,
):
    """Verify a newer shim SBAT level replaces the complete EFI bundle."""
    _verify_sbat_bundle_selection(
        duthost,
        localhost,
        request,
        tbinfo,
        "secure_boot_sbat_upgrade_image_url",
        True,
    )


def test_older_sbat_bundle_preserves_installed_bundle(
    duthost,
    localhost,
    request,
    tbinfo,
):
    """Verify an older shim SBAT level preserves the complete newer bundle."""
    _verify_sbat_bundle_selection(
        duthost,
        localhost,
        request,
        tbinfo,
        "secure_boot_sbat_downgrade_image_url",
        False,
    )
