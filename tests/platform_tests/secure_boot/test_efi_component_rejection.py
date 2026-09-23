import re
import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.secure_boot import require_secure_boot
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

CONSOLE_CAPTURE_TIMEOUT = 180
RECOVERY_TIMEOUT = 300
EFI_REJECTION_PATTERN = (
    r"(?i)(security violation|access denied|verification failed|"
    r"failed to load image|image failed to load|bad shim signature)"
)
ACTIVE_GRUB_PATHS = (
    "/boot/efi/EFI/SONiC-OS/grubx64.efi",
    "/boot/efi/EFI/BOOT/grubx64.efi",
)
ACTIVE_SHIM_PATHS = (
    "/boot/efi/EFI/SONiC-OS/shimx64.efi",
    "/boot/efi/EFI/BOOT/BOOTX64.EFI",
)
ACTIVE_MOK_MANAGER_PATHS = (
    "/boot/efi/EFI/SONiC-OS/mmx64.efi",
    "/boot/efi/EFI/BOOT/mmx64.efi",
)
BACKUP_SUFFIX = ".secure_boot_test_backup"
EFI_PARTITION = "/dev/vda1"
MOK_TEST_KEY_PATH = "/tmp/secure_boot_mok_test.key"
MOK_TEST_CERT_PATH = "/tmp/secure_boot_mok_test.crt"
MOK_TEST_DER_PATH = "/tmp/secure_boot_mok_test.der"
MOK_TEST_HASH_PATH = "/tmp/secure_boot_mok_test.hash"


def _validate_offline_recovery(vmhost, duthost):
    command = r"""
set -eu
command -v qemu-nbd
command -v flock
command -v udevadm
command -v lsblk
command -v mountpoint

vm_name={vm_name}
disk=$(sudo virsh domblklist "$vm_name" --details | awk '$3 == "vda" {{ print $4; exit }}')
test -n "$disk"
test -r "$disk"

sudo modprobe nbd max_part=16
test "$(cat /sys/module/nbd/parameters/max_part)" -ge 16
exec 9>/tmp/secure_boot_efi_nbd.lock
flock 9

for sys_device in /sys/block/nbd*; do
    if [ ! -e "$sys_device/pid" ]; then
        exit 0
    fi
done
exit 1
""".format(vm_name=shlex.quote(duthost.hostname))
    result = vmhost.shell(command, module_ignore_errors=True)
    pytest_assert(
        result["rc"] == 0,
        "The KVM host cannot perform offline EFI recovery: {}".format(
            result.get("stderr", "")
        ),
    )


def _mount_efi_partition(duthost):
    result = duthost.shell(
        "sudo mkdir -p /boot/efi && "
        "mountpoint -q /boot/efi || sudo mount {} /boot/efi".format(
            shlex.quote(EFI_PARTITION)
        ),
        module_ignore_errors=True,
    )
    pytest_assert(result["rc"] == 0, "Failed to mount the KVM EFI system partition")


def _backup_efi_components(duthost, component_paths):
    original_hashes = {}
    for path in component_paths:
        quoted_path = shlex.quote(path)
        backup_path = "{}{}".format(path, BACKUP_SUFFIX)
        result = duthost.shell(
            "sudo test -s {path} && sudo cp {path} {backup}".format(
                path=quoted_path,
                backup=shlex.quote(backup_path),
            ),
            module_ignore_errors=True,
        )
        pytest_assert(result["rc"] == 0, "Failed to back up active EFI component {}".format(path))
        original_hashes[path] = duthost.command(
            "sudo sha256sum {}".format(quoted_path)
        )["stdout"].split()[0]
    return original_hashes


def _restore_efi_components_online(duthost, component_paths, original_hashes):
    cleanup_errors = []
    for path in component_paths:
        restore_result = duthost.shell(
            "sudo cp {backup} {path} && sudo sync".format(
                backup=shlex.quote("{}{}".format(path, BACKUP_SUFFIX)),
                path=shlex.quote(path),
            ),
            module_ignore_errors=True,
        )
        if restore_result["rc"] != 0:
            cleanup_errors.append(path)
            continue

        restored_hash = duthost.command(
            "sudo sha256sum {}".format(shlex.quote(path))
        )["stdout"].split()[0]
        if restored_hash != original_hashes[path]:
            cleanup_errors.append(path)
            continue

        duthost.command(
            "sudo rm -f {}".format(shlex.quote("{}{}".format(path, BACKUP_SUFFIX)))
        )

    pytest_assert(
        not cleanup_errors,
        "Failed to restore active EFI components: {}".format(", ".join(cleanup_errors)),
    )


def _tamper_pe_payload(duthost, component_path):
    command = r"""
sudo python3 - {path} <<'PY'
import struct
import sys

path = sys.argv[1]
with open(path, "r+b") as binary:
    dos_header = binary.read(64)
    if len(dos_header) != 64 or dos_header[:2] != b"MZ":
        raise RuntimeError("EFI component is not a PE/COFF image")

    pe_offset = struct.unpack_from("<I", dos_header, 0x3c)[0]
    binary.seek(pe_offset)
    if binary.read(4) != b"PE\x00\x00":
        raise RuntimeError("EFI component has an invalid PE signature")

    coff_header = binary.read(20)
    if len(coff_header) != 20:
        raise RuntimeError("EFI component has a truncated COFF header")
    section_count = struct.unpack_from("<H", coff_header, 2)[0]
    optional_header_size = struct.unpack_from("<H", coff_header, 16)[0]
    section_table_offset = pe_offset + 24 + optional_header_size

    for index in range(section_count):
        binary.seek(section_table_offset + (index * 40))
        section = binary.read(40)
        if len(section) != 40:
            raise RuntimeError("EFI component has a truncated section table")
        raw_size, raw_offset = struct.unpack_from("<II", section, 16)
        if raw_size:
            binary.seek(raw_offset)
            original_byte = binary.read(1)
            if not original_byte:
                raise RuntimeError("EFI component section data is truncated")
            binary.seek(raw_offset)
            binary.write(bytes([original_byte[0] ^ 0x01]))
            break
    else:
        raise RuntimeError("EFI component has no mutable PE section")
PY
""".format(path=shlex.quote(component_path))
    duthost.shell(command)


def _remove_pe_signature(duthost, component_path):
    command = r"""
sudo python3 - {path} <<'PY'
import os
import struct
import sys

path = sys.argv[1]
file_size = os.path.getsize(path)

with open(path, "r+b") as binary:
    dos_header = binary.read(64)
    if len(dos_header) != 64 or dos_header[:2] != b"MZ":
        raise RuntimeError("EFI component is not a PE/COFF image")

    pe_offset = struct.unpack_from("<I", dos_header, 0x3c)[0]
    binary.seek(pe_offset)
    if binary.read(4) != b"PE\x00\x00":
        raise RuntimeError("EFI component has an invalid PE signature")

    optional_header_offset = pe_offset + 24
    binary.seek(optional_header_offset)
    optional_magic_data = binary.read(2)
    if len(optional_magic_data) != 2:
        raise RuntimeError("EFI component has a truncated PE optional header")

    optional_magic = struct.unpack("<H", optional_magic_data)[0]
    if optional_magic == 0x20b:
        data_directory_offset = optional_header_offset + 112
    elif optional_magic == 0x10b:
        data_directory_offset = optional_header_offset + 96
    else:
        raise RuntimeError("EFI component has an unsupported PE optional header")

    certificate_entry_offset = data_directory_offset + (4 * 8)
    binary.seek(certificate_entry_offset)
    certificate_entry = binary.read(8)
    if len(certificate_entry) != 8:
        raise RuntimeError("EFI component has a truncated certificate table entry")

    certificate_offset, certificate_size = struct.unpack("<II", certificate_entry)
    certificate_end = certificate_offset + certificate_size
    if certificate_offset == 0 or certificate_size == 0:
        raise RuntimeError("EFI component does not contain an Authenticode signature")
    if certificate_end > file_size:
        raise RuntimeError("EFI component certificate table extends beyond the file")

    binary.seek(certificate_entry_offset)
    binary.write(b"\x00" * 8)
    if certificate_end == file_size:
        binary.truncate(certificate_offset)
PY
""".format(path=shlex.quote(component_path))
    duthost.shell(command)


def _queue_mok_import(duthost):
    temporary_paths = (
        MOK_TEST_KEY_PATH,
        MOK_TEST_CERT_PATH,
        MOK_TEST_DER_PATH,
        MOK_TEST_HASH_PATH,
    )
    command = r"""
set -eu
command -v mokutil
command -v openssl

if sudo mokutil --list-new 2>/dev/null | grep -q .; then
    echo "A MOK enrollment request is already pending" >&2
    exit 1
fi

openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
    -subj /CN=SONiC-Secure-Boot-MokManager-Test/ \
    -keyout {key_path} \
    -out {cert_path} >/dev/null 2>&1
openssl x509 -in {cert_path} -outform DER -out {der_path}
openssl rand -hex 12 | openssl passwd -6 -stdin > {hash_path}
test -s {hash_path}

sudo mokutil --import {der_path} --hash-file {hash_path}
sudo mokutil --list-new | grep -q "SONiC-Secure-Boot-MokManager-Test"
""".format(
        key_path=shlex.quote(MOK_TEST_KEY_PATH),
        cert_path=shlex.quote(MOK_TEST_CERT_PATH),
        der_path=shlex.quote(MOK_TEST_DER_PATH),
        hash_path=shlex.quote(MOK_TEST_HASH_PATH),
    )
    result = duthost.shell(command, module_ignore_errors=True)
    if result["rc"] != 0:
        duthost.command(
            "rm -f {}".format(" ".join(shlex.quote(path) for path in temporary_paths)),
            module_ignore_errors=True,
        )
    pytest_assert(
        result["rc"] == 0,
        "Failed to queue the MOK enrollment request: {}".format(
            result.get("stderr", "")
        ),
    )


def _clear_pending_mok_import(duthost):
    list_result = duthost.command(
        "sudo mokutil --list-new",
        module_ignore_errors=True,
    )
    pytest_assert(
        list_result["rc"] == 0,
        "Failed to inspect the pending MOK enrollment request",
    )

    if list_result["stdout"].strip():
        revoke_result = duthost.command(
            "sudo mokutil --revoke-import",
            module_ignore_errors=True,
        )
        pytest_assert(
            revoke_result["rc"] == 0,
            "Failed to revoke the pending MOK enrollment request",
        )

    temporary_paths = (
        MOK_TEST_KEY_PATH,
        MOK_TEST_CERT_PATH,
        MOK_TEST_DER_PATH,
        MOK_TEST_HASH_PATH,
    )
    cleanup_result = duthost.command(
        "rm -f {}".format(" ".join(shlex.quote(path) for path in temporary_paths)),
        module_ignore_errors=True,
    )
    pytest_assert(cleanup_result["rc"] == 0, "Failed to remove temporary MOK test files")


def _restore_efi_components_and_restart(
    vmhost,
    duthost,
    localhost,
    component_paths,
    original_hashes,
):
    relative_paths = " ".join(
        shlex.quote(path[len("/boot/efi/"):])
        for path in component_paths
    )
    restore_commands = []
    for path in component_paths:
        relative_path = path[len("/boot/efi/"):]
        restore_commands.extend([
            'sudo cp "$mount_dir/{backup}" "$mount_dir/{path}"'.format(
                backup="{}{}".format(relative_path, BACKUP_SUFFIX),
                path=relative_path,
            ),
            'test "$(sudo sha256sum "$mount_dir/{path}" | awk \'{{print $1}}\')" = {expected}'.format(
                path=relative_path,
                expected=shlex.quote(original_hashes[path]),
            ),
        ])

    vm_name = shlex.quote(duthost.hostname)
    tap_name = "{}-0".format(duthost.hostname)
    bridge_result = vmhost.shell(
        "basename $(readlink /sys/class/net/{}/master)".format(shlex.quote(tap_name)),
        module_ignore_errors=True,
    )
    management_bridge = bridge_result["stdout"].strip() if bridge_result["rc"] == 0 else ""

    command = r"""
set -eu
vm_name={vm_name}
relative_paths={relative_paths}
disk=$(sudo virsh domblklist "$vm_name" --details | awk '$3 == "vda" {{ print $4; exit }}')
test -n "$disk"

sudo modprobe nbd max_part=16
test "$(cat /sys/module/nbd/parameters/max_part)" -ge 16
exec 9>/tmp/secure_boot_efi_nbd.lock
flock 9

nbd=""
for sys_device in /sys/block/nbd*; do
    if [ ! -e "$sys_device/pid" ]; then
        nbd="/dev/${{sys_device##*/}}"
        break
    fi
done
test -n "$nbd"

mount_dir=$(mktemp -d)
vm_stopped=0
cleanup() {{
    mountpoint -q "$mount_dir" && sudo umount "$mount_dir" || true
    [ -n "$nbd" ] && sudo qemu-nbd --disconnect "$nbd" >/dev/null 2>&1 || true
    rmdir "$mount_dir" || true
    if [ "$vm_stopped" -eq 1 ]; then
        sudo virsh start "$vm_name" >/dev/null || true
    fi
}}
trap cleanup EXIT

sudo virsh destroy "$vm_name" >/dev/null
vm_stopped=1
test "$(sudo virsh domstate "$vm_name" | tr -d '\r')" = "shut off"
sudo qemu-nbd --connect="$nbd" "$disk"
sudo udevadm settle

partitions=""
for unused in $(seq 1 20); do
    partitions=$(lsblk -lnpo NAME,TYPE "$nbd" | awk '$2 == "part" {{ print $1 }}')
    [ -n "$partitions" ] && break
    sleep 1
done
test -n "$partitions"

restored=0
for partition in $partitions; do
    if sudo mount "$partition" "$mount_dir" 2>/dev/null; then
        found=1
        for relative_path in $relative_paths; do
            backup="$mount_dir/$relative_path{backup_suffix}"
            if [ ! -s "$backup" ]; then
                found=0
                break
            fi
        done
        if [ "$found" -eq 1 ]; then
{restore_commands}
            sync
            restored=1
            sudo umount "$mount_dir"
            break
        fi
        sudo umount "$mount_dir"
    fi
done
test "$restored" -eq 1
""".format(
        vm_name=vm_name,
        relative_paths=shlex.quote(relative_paths),
        backup_suffix=BACKUP_SUFFIX,
        restore_commands="\n".join("            {}".format(line) for line in restore_commands),
    )
    restore_result = vmhost.shell(command, module_ignore_errors=True)
    pytest_assert(
        restore_result["rc"] == 0,
        "Failed to restore the active EFI components: {}".format(
            restore_result.get("stderr", "")
        ),
    )

    if management_bridge:
        attach_result = vmhost.shell(
            (
                "for unused in $(seq 1 30); do "
                "test -e /sys/class/net/{tap} && break; sleep 1; done; "
                "sudo ip link set {tap} master {bridge} && sudo ip link set {tap} up"
            ).format(
                tap=shlex.quote(tap_name),
                bridge=shlex.quote(management_bridge),
            ),
            module_ignore_errors=True,
        )
        pytest_assert(
            attach_result["rc"] == 0,
            "Failed to reconnect {} to {}".format(tap_name, management_bridge),
        )

    startup_result = localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="started",
        delay=10,
        timeout=RECOVERY_TIMEOUT,
        module_ignore_errors=True,
    )
    pytest_assert(not startup_result.is_failed, "KVM did not recover after restoring the EFI bundle")
    pytest_assert(
        wait_until(RECOVERY_TIMEOUT, 10, 0, duthost.critical_services_fully_started),
        "KVM critical services did not recover after restoring the EFI bundle",
    )
    _mount_efi_partition(duthost)

    for path in component_paths:
        cleanup_result = duthost.command(
            "sudo rm -f {}".format(shlex.quote("{}{}".format(path, BACKUP_SUFFIX))),
            module_ignore_errors=True,
        )
        pytest_assert(cleanup_result["rc"] == 0, "Failed to remove the EFI backup for {}".format(path))


def _verify_efi_component_is_rejected(
    duthost,
    kvm_serial_console,
    localhost,
    vmhost,
    component_paths,
    component_modifier,
    component_description,
):
    if duthost.facts["asic_type"] != "vs":
        pytest.skip("The initial {} test supports KVM only".format(component_description))

    require_secure_boot(duthost)
    if not vmhost:
        pytest.skip("The KVM host is unavailable")

    _validate_offline_recovery(vmhost, duthost)
    _mount_efi_partition(duthost)

    original_hashes = _backup_efi_components(duthost, component_paths)
    reboot_attempted = False
    console_output = ""
    rejection_seen = False
    try:
        for path in component_paths:
            component_modifier(duthost, path)
            changed_hash = duthost.command(
                "sudo sha256sum {}".format(shlex.quote(path))
            )["stdout"].split()[0]
            pytest_assert(
                changed_hash != original_hashes[path],
                "{} was not modified".format(path),
            )
        duthost.command("sync")

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
        pytest_assert(
            not shutdown_result.is_failed,
            "KVM did not shut down for the {} test".format(component_description),
        )

        console_output, rejection_seen = kvm_serial_console.read_until_pattern_or_timeout(
            EFI_REJECTION_PATTERN,
            CONSOLE_CAPTURE_TIMEOUT,
        )
    finally:
        if reboot_attempted:
            _restore_efi_components_and_restart(
                vmhost,
                duthost,
                localhost,
                component_paths,
                original_hashes,
            )
        else:
            _restore_efi_components_online(duthost, component_paths, original_hashes)

    for path, original_hash in original_hashes.items():
        restored_hash = duthost.command(
            "sudo sha256sum {}".format(shlex.quote(path))
        )["stdout"].split()[0]
        pytest_assert(restored_hash == original_hash, "Failed to restore {}".format(path))

    pytest_assert(
        rejection_seen,
        "The serial console did not report rejection of the {}:\n{}".format(
            component_description,
            re.sub(r"[^\x09\x0a\x0d\x20-\x7e]", "", console_output),
        ),
    )


def test_tampered_grub_is_rejected(duthost, kvm_serial_console, localhost, vmhost):
    """Verify that shim rejects a GRUB binary modified after signing."""
    _verify_efi_component_is_rejected(
        duthost,
        kvm_serial_console,
        localhost,
        vmhost,
        ACTIVE_GRUB_PATHS,
        _tamper_pe_payload,
        "tampered GRUB",
    )


def test_unsigned_grub_is_rejected(duthost, kvm_serial_console, localhost, vmhost):
    """Verify that shim rejects a GRUB binary with no Authenticode signature."""
    _verify_efi_component_is_rejected(
        duthost,
        kvm_serial_console,
        localhost,
        vmhost,
        ACTIVE_GRUB_PATHS,
        _remove_pe_signature,
        "unsigned GRUB",
    )


def test_tampered_shim_is_rejected(duthost, kvm_serial_console, localhost, vmhost):
    """Verify that firmware rejects a shim binary modified after signing."""
    _verify_efi_component_is_rejected(
        duthost,
        kvm_serial_console,
        localhost,
        vmhost,
        ACTIVE_SHIM_PATHS,
        _tamper_pe_payload,
        "tampered shim",
    )


def test_unsigned_shim_is_rejected(duthost, kvm_serial_console, localhost, vmhost):
    """Verify that firmware rejects a shim binary with no Authenticode signature."""
    _verify_efi_component_is_rejected(
        duthost,
        kvm_serial_console,
        localhost,
        vmhost,
        ACTIVE_SHIM_PATHS,
        _remove_pe_signature,
        "unsigned shim",
    )


def test_unsigned_mok_manager_is_rejected(
    duthost,
    kvm_serial_console,
    localhost,
    vmhost,
):
    """Verify that shim rejects unsigned MokManager when a MOK request invokes it."""
    if duthost.facts["asic_type"] != "vs":
        pytest.skip("The initial unsigned MokManager test supports KVM only")

    require_secure_boot(duthost)
    if not vmhost:
        pytest.skip("The KVM host is unavailable")

    pytest_assert(
        duthost.critical_services_fully_started(),
        "The DUT did not complete its normal boot before the MokManager test",
    )
    _validate_offline_recovery(vmhost, duthost)
    _mount_efi_partition(duthost)

    original_hashes = _backup_efi_components(duthost, ACTIVE_MOK_MANAGER_PATHS)
    reboot_attempted = False
    mok_request_queued = False
    console_output = ""
    rejection_seen = False
    try:
        _queue_mok_import(duthost)
        mok_request_queued = True
        for path in ACTIVE_MOK_MANAGER_PATHS:
            _remove_pe_signature(duthost, path)
            unsigned_hash = duthost.command(
                "sudo sha256sum {}".format(shlex.quote(path))
            )["stdout"].split()[0]
            pytest_assert(
                unsigned_hash != original_hashes[path],
                "{} was not modified".format(path),
            )
        duthost.command("sync")

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
        pytest_assert(
            not shutdown_result.is_failed,
            "KVM did not shut down for the unsigned MokManager test",
        )

        console_output, rejection_seen = kvm_serial_console.read_until_pattern_or_timeout(
            EFI_REJECTION_PATTERN,
            CONSOLE_CAPTURE_TIMEOUT,
        )
    finally:
        try:
            if reboot_attempted:
                _restore_efi_components_and_restart(
                    vmhost,
                    duthost,
                    localhost,
                    ACTIVE_MOK_MANAGER_PATHS,
                    original_hashes,
                )
            else:
                _restore_efi_components_online(
                    duthost,
                    ACTIVE_MOK_MANAGER_PATHS,
                    original_hashes,
                )
        finally:
            if mok_request_queued:
                _clear_pending_mok_import(duthost)

    for path, original_hash in original_hashes.items():
        restored_hash = duthost.command(
            "sudo sha256sum {}".format(shlex.quote(path))
        )["stdout"].split()[0]
        pytest_assert(restored_hash == original_hash, "Failed to restore {}".format(path))

    pytest_assert(
        rejection_seen,
        "The serial console did not report rejection of unsigned MokManager:\n{}".format(
            re.sub(r"[^\x09\x0a\x0d\x20-\x7e]", "", console_output),
        ),
    )
