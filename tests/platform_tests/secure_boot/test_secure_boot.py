import shlex

import pytest

from tests.common.helpers.assertions import pytest_assert


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


def _require_secure_boot(duthost):
    secure_boot_state = duthost.command(
        "mokutil --sb-state",
        module_ignore_errors=True,
    )
    pytest_assert(
        secure_boot_state["rc"] == 0
        and "SecureBoot enabled" in secure_boot_state["stdout"],
        "Secure Boot PR testbed is not booted with Secure Boot enabled: "
        "{}".format(secure_boot_state),
    )

    secure_boot_image = duthost.command(
        "sonic-cfggen -y /etc/sonic/sonic_version.yml -v secure_boot_image",
        module_ignore_errors=True,
    )
    pytest_assert(
        secure_boot_image["rc"] == 0
        and secure_boot_image["stdout"].strip() == "yes",
        "Secure Boot PR testbed is not using a Secure Boot image: "
        "{}".format(secure_boot_image),
    )


def _find_unloaded_signed_kernel_module(duthost):
    command = r"""
loaded_modules=$(awk '{print $1}' /proc/modules | tr '-' '_')
find /lib/modules/"$(uname -r)" -type f \
    \( -name '*.ko' -o -name '*.ko.xz' -o -name '*.ko.gz' \
       -o -name '*.ko.zst' \) |
while read -r module; do
    module_name=$(modinfo -F name "$module" 2>/dev/null | tr '-' '_')
    signer=$(modinfo -F signer "$module" 2>/dev/null)
    if [ -n "$module_name" ] && [ -n "$signer" ] &&
            ! printf '%s\n' "$loaded_modules" | grep -Fxq "$module_name"; then
        printf '%s\n' "$module"
        break
    fi
done
"""
    return duthost.shell(command)["stdout"].strip()


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


def _remove_module_signature(duthost):
    command = r"""
python3 - {module_path} <<'PY'
import struct
import sys

module_path = sys.argv[1]
signature_magic = b"~Module signature appended~\n"
signature_header_size = 12

with open(module_path, "rb") as module_file:
    module_data = module_file.read()

signature_count = 0
while module_data.endswith(signature_magic):
    header_offset = (
        len(module_data) - len(signature_magic) - signature_header_size
    )
    signature_length = struct.unpack(
        ">I", module_data[header_offset + 8:header_offset + 12]
    )[0]
    unsigned_module_size = header_offset - signature_length
    if unsigned_module_size <= 0:
        raise RuntimeError(
            "Selected kernel module has an invalid signature length"
        )
    module_data = module_data[:unsigned_module_size]
    signature_count += 1

if signature_count == 0:
    raise RuntimeError(
        "Selected kernel module does not contain an appended signature"
    )

with open(module_path, "wb") as module_file:
    module_file.write(module_data)
PY
""".format(module_path=shlex.quote(UNSIGNED_MODULE_PATH))
    duthost.shell(command)


def _load_module(duthost):
    dmesg_before = duthost.command("sudo dmesg --notime")["stdout"]
    load_result = duthost.command(
        "sudo insmod {}".format(shlex.quote(UNSIGNED_MODULE_PATH)),
        module_ignore_errors=True,
    )
    dmesg_after = duthost.command("sudo dmesg --notime")["stdout"]
    if dmesg_after.startswith(dmesg_before):
        new_dmesg = dmesg_after[len(dmesg_before):]
    else:
        new_dmesg = dmesg_after
    rejection_output = "{}\n{}\n{}".format(
        load_result["stdout"],
        load_result["stderr"],
        new_dmesg,
    ).lower()
    return load_result, rejection_output


def test_unsigned_kernel_module_is_rejected(duthost):
    """Verify Secure Boot rejects an unsigned kernel module."""
    _require_secure_boot(duthost)

    source_path = _find_unloaded_signed_kernel_module(duthost)
    pytest_assert(
        source_path,
        "No unloaded signed kernel module is available",
    )
    module_name = duthost.command(
        "modinfo -F name {}".format(shlex.quote(source_path))
    )["stdout"].strip()

    try:
        _copy_uncompressed_module(duthost, source_path)
        _remove_module_signature(duthost)
        load_result, rejection_output = _load_module(duthost)

        pytest_assert(
            load_result["rc"] != 0,
            "The kernel loaded an unsigned module",
        )
        pytest_assert(
            any(
                message in rejection_output
                for message in SIGNATURE_REJECTION_MESSAGES
            ),
            "Module load failed without evidence of signature enforcement: "
            "{}".format(rejection_output),
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
