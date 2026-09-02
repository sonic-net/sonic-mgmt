import logging
import re
import shlex
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.secure_boot import (
    require_secure_boot,
)
from tests.common.helpers.upgrade_helpers import (
    get_inactive_images,
    install_sonic,
    set_default_and_next_image,
)


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

CONSOLE_CAPTURE_TIMEOUT = 180
RECOVERY_TIMEOUT = 300
KERNEL_REJECTION_MESSAGES = (
    "bad shim signature",
    "verification failed",
    "invalid signature",
    "security violation",
    "prohibited by secure boot policy",
)
GRUB_CONTINUE_PATTERN = "(?i)press any key to continue"
KEY_UP = "\x1b[A"
KEY_DOWN = "\x1b[B"

logger = logging.getLogger(__name__)


# Select the configured second image URL or fall back to an inactive image already on the DUT.
def _get_target_image(request, duthost):
    second_image_url = request.config.getoption("secure_boot_second_image_url")
    if second_image_url:
        return second_image_url, None

    inactive_images = get_inactive_images(duthost)
    if not inactive_images:
        pytest.skip("--secure_boot_second_image_url or an installed inactive image is required")

    target_version = inactive_images[0]
    logger.info("Using preinstalled inactive image %s for the tampered-kernel test", target_version)
    return None, target_version


# Locate the kernel installed under the inactive target image.
def _find_target_kernel(duthost, target_version):
    image_name = target_version
    if image_name.startswith("SONiC-OS-"):
        image_name = image_name[len("SONiC-OS-"):]
    image_directory = "/host/image-{}".format(image_name)
    command = "sudo find {} -type f -name 'vmlinuz*' | head -n 1".format(shlex.quote(image_directory))
    kernel_path = duthost.shell(command)["stdout"].strip()
    pytest_assert(kernel_path, "No kernel was found under {}".format(image_directory))
    return kernel_path


def _get_grub_entry_index(duthost, image_name):
    output = duthost.command(
        "sudo grep '^menuentry ' /host/grub/grub.cfg"
    )["stdout"]
    entries = []
    for line in output.splitlines():
        entry = line[len("menuentry "):].strip()
        if entry.startswith("'"):
            entry = entry.split("'", 2)[1]
        else:
            entry = entry.split()[0]
        entries.append(entry)

    pytest_assert(
        image_name in entries,
        "Image {} is not present in the GRUB menu".format(image_name),
    )
    return entries.index(image_name)


# Back up the signed kernel and change one payload byte so its signature becomes invalid.
def _tamper_kernel(duthost, kernel_path, backup_path):
    quoted_kernel = shlex.quote(kernel_path)
    quoted_backup = shlex.quote(backup_path)
    duthost.command("sudo cp --preserve=all {} {}".format(quoted_kernel, quoted_backup))

    original_hash = duthost.command("sudo sha256sum {}".format(quoted_kernel))["stdout"].split()[0]
    command = r"""
sudo python3 - {kernel_path} <<'PY'
import os
import sys

kernel_path = sys.argv[1]
kernel_size = os.path.getsize(kernel_path)
if kernel_size <= 4096:
    raise RuntimeError("Kernel file is unexpectedly small")

with open(kernel_path, "r+b") as kernel_file:
    kernel_file.seek(4096)
    original_byte = kernel_file.read(1)
    kernel_file.seek(4096)
    kernel_file.write(bytes([original_byte[0] ^ 0x01]))
PY
""".format(kernel_path=quoted_kernel)
    duthost.shell(command)

    tampered_hash = duthost.command("sudo sha256sum {}".format(quoted_kernel))["stdout"].split()[0]
    pytest_assert(original_hash != tampered_hash, "The target kernel was not modified")


def _wait_for_console_pattern(duthost_console, pattern, occurrence=1):
    output = ""
    for unused in range(occurrence):
        output += duthost_console.read_until_pattern(
            pattern=pattern,
            read_timeout=CONSOLE_CAPTURE_TIMEOUT,
        )
    return output


def _select_grub_entry(duthost_console, current_index, target_index):
    offset = target_index - current_index
    key = KEY_DOWN if offset > 0 else KEY_UP
    for unused in range(abs(offset)):
        duthost_console.write_channel(key)
    duthost_console.write_channel(duthost_console.RETURN)
    time.sleep(1)


# Select the tampered image, then the known-good image after Secure Boot rejects it.
def _run_console_boot_sequence(
    duthost_console,
    target_index,
    original_index,
    original_image,
):
    menu_pattern = re.escape(original_image)
    console_output = _wait_for_console_pattern(
        duthost_console,
        menu_pattern,
        occurrence=2,
    )
    _select_grub_entry(duthost_console, original_index, target_index)

    console_output += _wait_for_console_pattern(
        duthost_console,
        GRUB_CONTINUE_PATTERN,
    )
    time.sleep(1)
    duthost_console.write_channel(duthost_console.RETURN)

    console_output += _wait_for_console_pattern(
        duthost_console,
        menu_pattern,
        occurrence=2,
    )
    _select_grub_entry(duthost_console, original_index, original_index)
    return console_output


# Power-cycle the KVM so it boots the unchanged default image.
def _recover_kvm(vmhost, duthost, localhost):
    vm_name = shlex.quote(duthost.hostname)
    tap_name = "{}-0".format(duthost.hostname)
    quoted_tap = shlex.quote(tap_name)
    bridge_result = vmhost.shell(
        "basename $(readlink /sys/class/net/{}/master)".format(quoted_tap),
        module_ignore_errors=True,
    )
    management_bridge = bridge_result["stdout"].strip() if bridge_result["rc"] == 0 else None

    vmhost.shell("sudo virsh destroy {}".format(vm_name), module_ignore_errors=True)
    start_result = vmhost.shell(
        "sudo virsh start {}".format(vm_name),
        module_ignore_errors=True,
    )
    pytest_assert(start_result["rc"] == 0, "Failed to restart KVM {} during recovery".format(duthost.hostname))

    if management_bridge:
        attach_result = vmhost.shell(
            "sudo ip link set {tap} master {bridge} && sudo ip link set {tap} up".format(
                tap=quoted_tap,
                bridge=shlex.quote(management_bridge),
            ),
            module_ignore_errors=True,
        )
        pytest_assert(attach_result["rc"] == 0, "Failed to reconnect {} to {}".format(
            tap_name, management_bridge
        ))

    startup_result = localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="started",
        delay=10,
        timeout=RECOVERY_TIMEOUT,
        module_ignore_errors=True,
    )
    pytest_assert(not startup_result.is_failed, "KVM did not return to the original image after recovery")


# Verify that GRUB refuses to boot a kernel whose signed payload was modified.
def test_tampered_kernel_is_rejected(
    duthost,
    duthost_console,
    localhost,
    vmhost,
    request,
    tbinfo,
):
    """Verify that Secure Boot prevents a tampered kernel from booting."""
    if duthost.facts["asic_type"] != "vs":
        pytest.skip("The initial tampered kernel test supports KVM only")

    require_secure_boot(duthost)

    if not vmhost:
        pytest.skip("The KVM host is unavailable")

    image_info = duthost.get_image_info()
    original_image = image_info["current"]
    installed_images = image_info["installed_list"]
    target_image, preinstalled_target = _get_target_image(request, duthost)

    target_version = preinstalled_target
    installed_by_test = False
    kernel_path = None
    backup_path = None
    reboot_attempted = False

    try:
        if target_image:
            target_version = install_sonic(duthost, target_image, tbinfo)
            installed_by_test = target_version not in installed_images

        pytest_assert(
            target_version != original_image,
            "The target image must differ from the running image",
        )

        kernel_path = _find_target_kernel(duthost, target_version)
        backup_path = "{}.secure_boot_test_backup".format(kernel_path)
        _tamper_kernel(duthost, kernel_path, backup_path)

        set_default_and_next_image(duthost, original_image)
        original_index = _get_grub_entry_index(duthost, original_image)
        target_index = _get_grub_entry_index(duthost, target_version)

        reboot_attempted = True
        duthost.shell("sudo nohup sh -c 'sleep 2; reboot' >/dev/null 2>&1 &")
        console_output = _run_console_boot_sequence(
            duthost_console,
            target_index,
            original_index,
            original_image,
        )

        recovery_startup = localhost.wait_for(
            host=duthost.mgmt_ip,
            port=22,
            state="started",
            delay=10,
            timeout=RECOVERY_TIMEOUT,
            module_ignore_errors=True,
        )
        if recovery_startup.is_failed:
            pytest_assert(
                False,
                "KVM did not boot the known-good image after rejection:\n{}".format(
                    console_output
                ),
            )

        normalized_console = console_output.lower()
        pytest_assert(
            any(message in normalized_console for message in KERNEL_REJECTION_MESSAGES),
            "The serial console did not report a kernel signature rejection:\n{}".format(console_output),
        )
        current_image = duthost.get_image_info()["current"]
        pytest_assert(current_image == original_image, "KVM did not recover to the original image")
        reboot_attempted = False
    finally:
        if reboot_attempted:
            _recover_kvm(vmhost, duthost, localhost)

        if backup_path and kernel_path:
            restore_result = duthost.command(
                "sudo mv {} {}".format(shlex.quote(backup_path), shlex.quote(kernel_path)),
                module_ignore_errors=True,
            )
            pytest_assert(restore_result["rc"] == 0, "Failed to restore the signed target kernel")

        set_default_and_next_image(duthost, original_image)

        if target_version and installed_by_test:
            remove_result = duthost.command(
                "sudo sonic-installer remove {} -y".format(shlex.quote(target_version)),
                module_ignore_errors=True,
            )
            pytest_assert(remove_result["rc"] == 0, "Failed to remove the image installed by the test")
