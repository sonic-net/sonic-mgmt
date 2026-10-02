import os
import shlex

import pytest


EFI_MOUNTPOINT = "/mnt/secure_boot_esp"


def require_secure_boot(duthost):
    """Skip the test unless UEFI Secure Boot is enabled."""
    secure_boot_state = duthost.command(
        "mokutil --sb-state",
        module_ignore_errors=True,
    )
    if (
        secure_boot_state["rc"] != 0
        or "SecureBoot enabled" not in secure_boot_state["stdout"]
    ):
        pytest.skip("Secure Boot is not enabled")


def mount_efi_system_partition(duthost):
    """Mount the EFI system partition and return the SONiC loader directory."""
    command = r"""
set -eu
mountpoint={mountpoint}
sudo mkdir -p "$mountpoint"
if ! mountpoint -q "$mountpoint"; then
    device=$(lsblk -rpn -o NAME,PARTTYPE |
        grep -i c12a7328-f81f-11d2-ba4b-00a0c93ec93b |
        head -1 | cut -d ' ' -f1)
    test -n "$device"
    sudo mount "$device" "$mountpoint"
fi
test -d "$mountpoint/EFI/SONiC-OS"
printf '%s\n' "$mountpoint/EFI/SONiC-OS"
""".format(mountpoint=shlex.quote(EFI_MOUNTPOINT))
    return duthost.shell(command)["stdout"].strip()


def unmount_efi_system_partition(duthost):
    """Unmount the EFI system partition mounted by the Secure Boot tests."""
    command = r"""
mountpoint={mountpoint}
if mountpoint -q "$mountpoint"; then
    sudo umount "$mountpoint"
fi
sudo rmdir "$mountpoint" 2>/dev/null || true
""".format(mountpoint=shlex.quote(EFI_MOUNTPOINT))
    duthost.shell(command)


def restore_active_efi_bundle(duthost, image_name):
    """Restore the active and fallback EFI binaries from an installed image."""
    version = (
        image_name[len("SONiC-OS-"):]
        if image_name.startswith("SONiC-OS-")
        else image_name
    )
    source_dir = "/host/image-{}/boot".format(version)
    sonic_dir = mount_efi_system_partition(duthost)
    esp_dir = os.path.dirname(sonic_dir)
    command = r"""
set -eu
source_dir={source_dir}
sonic_dir={sonic_dir}
fallback_dir={fallback_dir}

for file in shimx64.efi mmx64.efi grubx64.efi; do
    test -s "$source_dir/$file"
done

sudo install -d "$sonic_dir" "$fallback_dir"
sudo install -m 0644 "$source_dir/shimx64.efi" "$sonic_dir/shimx64.efi"
sudo install -m 0644 "$source_dir/mmx64.efi" "$sonic_dir/mmx64.efi"
sudo install -m 0644 "$source_dir/grubx64.efi" "$sonic_dir/grubx64.efi"
sudo install -m 0644 "$source_dir/shimx64.efi" "$fallback_dir/BOOTX64.EFI"
sudo install -m 0644 "$source_dir/mmx64.efi" "$fallback_dir/mmx64.efi"
sudo install -m 0644 "$source_dir/grubx64.efi" "$fallback_dir/grubx64.efi"
sync
""".format(
        source_dir=shlex.quote(source_dir),
        sonic_dir=shlex.quote(sonic_dir),
        fallback_dir=shlex.quote(os.path.join(esp_dir, "BOOT")),
    )
    try:
        duthost.shell(command)
    finally:
        unmount_efi_system_partition(duthost)
