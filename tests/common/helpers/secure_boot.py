import shlex

import pytest


def require_secure_boot(duthost):
    """Skip the test unless UEFI Secure Boot is enabled."""
    secure_boot_state = duthost.command("mokutil --sb-state", module_ignore_errors=True)
    if secure_boot_state["rc"] != 0 or "SecureBoot enabled" not in secure_boot_state["stdout"]:
        pytest.skip("Secure Boot is not enabled")


def restore_active_efi_bundle(duthost, image_name):
    """Restore the active and fallback EFI binaries from an installed image."""
    version = image_name[len("SONiC-OS-"):] if image_name.startswith("SONiC-OS-") else image_name
    source_dir = "/host/image-{}/boot".format(version)
    command = r"""
set -eu
source_dir={source_dir}
sonic_dir=/boot/efi/EFI/SONiC-OS
fallback_dir=/boot/efi/EFI/BOOT

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
""".format(source_dir=shlex.quote(source_dir))
    duthost.shell(command)
