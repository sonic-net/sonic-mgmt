import logging
import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.grub_console import (
    GRUB_CONSOLE_SCRIPT_PATH,
    start_grub_entry_sequence,
)
from tests.common.helpers.secure_boot import (
    get_current_image,
    get_inactive_image,
    get_installed_images,
    require_secure_boot,
    restore_image_selection,
)
from tests.common.helpers.upgrade_helpers import install_sonic
from tests.common.utilities import get_host_visible_vars, get_inventory_files


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

logger = logging.getLogger(__name__)


# Select the configured second image URL or fall back to an inactive image already on the DUT.
def _get_target_image(request, installed_images, current_image):
    second_image_url = request.config.getoption("secure_boot_second_image_url")
    if second_image_url:
        return second_image_url, None

    target_version = get_inactive_image(installed_images, current_image)
    logger.info("Using preinstalled inactive image %s for the tampered-kernel test", target_version)
    return None, target_version


# Resolve the TCP serial port assigned to the KVM from the test inventory.
def _get_serial_port(request, duthost):
    host_vars = get_host_visible_vars(get_inventory_files(request), duthost.hostname)
    serial_port = host_vars.get("serial_port") if host_vars else None
    pytest_assert(serial_port, "The KVM inventory does not define a serial_port")
    return serial_port


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


# Select the tampered image, then the known-good image after Secure Boot rejects it.
def _start_console_boot_sequence(
    vmhost,
    duthost,
    serial_port,
    target_index,
    original_index,
    original_image,
):
    console_log = "/tmp/secure_boot_{}_console.log".format(duthost.hostname)
    return start_grub_entry_sequence(
        vmhost,
        serial_port,
        original_index,
        target_index,
        original_index,
        original_index,
        menu_pattern=original_image,
        menu_occurrence=2,
        wait_pattern=GRUB_CONTINUE_PATTERN,
        acknowledge_wait_pattern=True,
        timeout=CONSOLE_CAPTURE_TIMEOUT,
        log_path=console_log,
    )


# Stop the exact capture process and return all serial output collected so far.
def _stop_console_capture(vmhost, capture_pid, console_log):
    if capture_pid:
        vmhost.shell("kill {}".format(capture_pid), module_ignore_errors=True)
    result = vmhost.shell(
        "LC_ALL=C tr -cd '\\11\\12\\15\\40-\\176' < {}".format(shlex.quote(console_log)),
        module_ignore_errors=True,
    )
    pytest_assert(result.get("rc") == 0, "Failed to read the KVM serial console log: {}".format(
        result.get("msg", result.get("stderr", "unknown error"))
    ))
    return result["stdout"]


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
def test_tampered_kernel_is_rejected(duthost, localhost, vmhost, request, tbinfo):
    """Verify that Secure Boot prevents a tampered kernel from booting."""
    if duthost.facts["asic_type"] != "vs":
        pytest.skip("The initial tampered kernel test supports KVM only")

    require_secure_boot(duthost)

    if not vmhost:
        pytest.skip("The KVM host is unavailable")

    telnet = vmhost.shell("command -v telnet", module_ignore_errors=True)
    pytest_assert(telnet["rc"] == 0, "The KVM host requires telnet to capture the serial console")
    pexpect = vmhost.shell("python3 -c 'import pexpect'", module_ignore_errors=True)
    pytest_assert(pexpect["rc"] == 0, "The KVM host requires the Python pexpect module")

    serial_port = _get_serial_port(request, duthost)
    original_image = get_current_image(duthost)
    installed_images = get_installed_images(duthost)
    target_image, preinstalled_target = _get_target_image(request, installed_images, original_image)

    target_version = preinstalled_target
    installed_by_test = False
    kernel_path = None
    backup_path = None
    capture_pid = None
    console_log = None
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

        capture_pid, console_log = _start_console_boot_sequence(
            vmhost,
            duthost,
            serial_port,
            target_index,
            original_index,
            original_image,
        )
        reboot_attempted = True
        duthost.shell("sudo nohup sh -c 'sleep 2; reboot' >/dev/null 2>&1 &")

        shutdown_result = localhost.wait_for(
            host=duthost.mgmt_ip,
            port=22,
            state="stopped",
            delay=5,
            timeout=60,
            module_ignore_errors=True,
        )
        pytest_assert(not shutdown_result.is_failed, "KVM did not shut down for the tampered-kernel boot")

        recovery_startup = localhost.wait_for(
            host=duthost.mgmt_ip,
            port=22,
            state="started",
            delay=10,
            timeout=RECOVERY_TIMEOUT,
            module_ignore_errors=True,
        )
        if recovery_startup.is_failed:
            stopped_capture_pid = capture_pid
            capture_pid = None
            console_output = _stop_console_capture(
                vmhost,
                stopped_capture_pid,
                console_log,
            )
            pytest_assert(
                False,
                "KVM did not boot the known-good image after rejection:\n{}".format(
                    console_output
                ),
            )

        stopped_capture_pid = capture_pid
        capture_pid = None
        console_output = _stop_console_capture(vmhost, stopped_capture_pid, console_log)
        normalized_console = console_output.lower()
        pytest_assert(
            any(message in normalized_console for message in KERNEL_REJECTION_MESSAGES),
            "The serial console did not report a kernel signature rejection:\n{}".format(console_output),
        )
        current_image = get_current_image(duthost)
        pytest_assert(current_image == original_image, "KVM did not recover to the original image")
        reboot_attempted = False
    finally:
        if capture_pid and console_log:
            _stop_console_capture(vmhost, capture_pid, console_log)

        if reboot_attempted:
            _recover_kvm(vmhost, duthost, localhost)

        if backup_path and kernel_path:
            restore_result = duthost.command(
                "sudo mv {} {}".format(shlex.quote(backup_path), shlex.quote(kernel_path)),
                module_ignore_errors=True,
            )
            pytest_assert(restore_result["rc"] == 0, "Failed to restore the signed target kernel")

        restore_image_selection(duthost, original_image)

        if target_version and installed_by_test:
            remove_result = duthost.command(
                "sudo sonic-installer remove {} -y".format(shlex.quote(target_version)),
                module_ignore_errors=True,
            )
            pytest_assert(remove_result["rc"] == 0, "Failed to remove the image installed by the test")

        if console_log:
            vmhost.command(
                "rm -f {} {}".format(
                    shlex.quote(console_log),
                    shlex.quote(GRUB_CONSOLE_SCRIPT_PATH),
                ),
                module_ignore_errors=True,
            )
