import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.secure_boot import require_secure_boot


pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

UNSIGNED_MODULE_PATH = "/tmp/secure_boot_unsigned_test.ko"
SIGNATURE_REJECTION_MESSAGES = (
    "key was rejected by service",
    "loading of unsigned module is rejected",
    "module verification failed",
    "required key not available",
)


# Select a module that matches the running kernel but is not currently loaded.
def _find_unloaded_kernel_module(duthost):
    command = r"""
loaded_modules=$(awk '{print $1}' /proc/modules | tr '-' '_')
find /lib/modules/"$(uname -r)" -type f \
    \( -name '*.ko' -o -name '*.ko.xz' -o -name '*.ko.gz' -o -name '*.ko.zst' \) |
while read -r module; do
    module_name=$(modinfo -F name "$module" 2>/dev/null | tr '-' '_')
    if [ -n "$module_name" ] && ! printf '%s\n' "$loaded_modules" | grep -Fxq "$module_name"; then
        printf '%s\n' "$module"
        break
    fi
done
"""
    return duthost.shell(command)["stdout"].strip()


# Copy the selected module to a temporary uncompressed file that can be modified.
def _copy_uncompressed_module(duthost, source_path):
    quoted_source = shlex.quote(source_path)
    quoted_destination = shlex.quote(UNSIGNED_MODULE_PATH)

    if source_path.endswith(".xz"):
        command = "xz -dc {} > {}".format(quoted_source, quoted_destination)
    elif source_path.endswith(".gz"):
        command = "gzip -dc {} > {}".format(quoted_source, quoted_destination)
    elif source_path.endswith(".zst"):
        command = "zstd -dc {} > {}".format(quoted_source, quoted_destination)
    else:
        command = "cp {} {}".format(quoted_source, quoted_destination)

    duthost.shell(command)


# Remove the appended Linux module signature without changing the module payload.
def _remove_module_signature(duthost):
    command = r"""
python3 - <<'PY'
import struct

module_path = "/tmp/secure_boot_unsigned_test.ko"
signature_magic = b"~Module signature appended~\n"
signature_header_size = 12

with open(module_path, "rb") as module_file:
    module_data = module_file.read()

signature_count = 0
while module_data.endswith(signature_magic):
    header_offset = len(module_data) - len(signature_magic) - signature_header_size
    signature_length = struct.unpack(">I", module_data[header_offset + 8:header_offset + 12])[0]
    unsigned_module_size = header_offset - signature_length
    if unsigned_module_size <= 0:
        raise RuntimeError("Selected kernel module has an invalid signature length")
    module_data = module_data[:unsigned_module_size]
    signature_count += 1

if signature_count == 0:
    raise RuntimeError("Selected kernel module does not contain an appended signature")

with open(module_path, "wb") as module_file:
    module_file.write(module_data)
PY
"""
    duthost.shell(command)


# Verify that the running Secure Boot kernel refuses the unsigned module.
def test_unsigned_kernel_module_is_rejected(duthost):
    """Verify that Secure Boot prevents an unsigned kernel module from loading."""
    require_secure_boot(duthost)

    source_path = _find_unloaded_kernel_module(duthost)
    pytest_assert(source_path, "No unloaded kernel module is available for the Secure Boot test")
    module_name = duthost.command(
        "modinfo -F name {}".format(shlex.quote(source_path))
    )["stdout"].strip()

    try:
        _copy_uncompressed_module(duthost, source_path)

        # Removing the signature keeps the module compatible with the running kernel
        # while making it untrusted by the Secure Boot chain of trust.
        _remove_module_signature(duthost)

        dmesg_before = duthost.command("sudo dmesg --notime")["stdout"]
        load_result = duthost.command(
            "sudo insmod {}".format(shlex.quote(UNSIGNED_MODULE_PATH)),
            module_ignore_errors=True,
        )
        dmesg_after = duthost.command("sudo dmesg --notime")["stdout"]

        new_dmesg = dmesg_after[len(dmesg_before):] if dmesg_after.startswith(dmesg_before) else dmesg_after
        rejection_output = "{}\n{}\n{}".format(
            load_result["stdout"],
            load_result["stderr"],
            new_dmesg,
        ).lower()

        pytest_assert(load_result["rc"] != 0, "The kernel loaded an unsigned module")
        pytest_assert(
            any(message in rejection_output for message in SIGNATURE_REJECTION_MESSAGES),
            "The module load failed without evidence of signature enforcement: {}".format(rejection_output),
        )
    finally:
        duthost.command(
            "sudo rmmod {}".format(shlex.quote(module_name)),
            module_ignore_errors=True,
        )
        duthost.command(
            "rm -f {}".format(shlex.quote(UNSIGNED_MODULE_PATH)),
            module_ignore_errors=True,
        )
