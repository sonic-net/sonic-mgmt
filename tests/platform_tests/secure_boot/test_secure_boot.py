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
UNTRUSTED_MODULE_PATH = "/tmp/secure_boot_untrusted_test.ko"
UNTRUSTED_KEY_PATH = "/tmp/secure_boot_untrusted_test.key"
UNTRUSTED_CERT_PATH = "/tmp/secure_boot_untrusted_test.crt"
UNTRUSTED_SIGNATURE_PATH = "/tmp/secure_boot_untrusted_test.p7s"
UNTRUSTED_SIGNER = "SONiC Secure Boot Untrusted Test"
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
def _copy_uncompressed_module(duthost, source_path, destination_path):
    quoted_source = shlex.quote(source_path)
    quoted_destination = shlex.quote(destination_path)

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
def _remove_module_signatures(duthost, module_path):
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
""".format(module_path=shlex.quote(module_path))
    duthost.shell(command)


# Sign the module with a temporary certificate that is not trusted by the running kernel.
def _sign_module_with_untrusted_key(duthost, module_path):
    command = r"""
set -eu

openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
    -subj {subject} \
    -keyout {key_path} \
    -out {cert_path} >/dev/null 2>&1

openssl cms -sign -binary -noattr -nosmimecap -md sha256 \
    -in {module_path} \
    -signer {cert_path} \
    -inkey {key_path} \
    -outform DER \
    -out {signature_path}

python3 - {module_path} {signature_path} <<'PY'
import struct
import sys

module_path, signature_path = sys.argv[1:]
signature_magic = b"~Module signature appended~\n"

with open(signature_path, "rb") as signature_file:
    signature = signature_file.read()
if not signature:
    raise RuntimeError("OpenSSL produced an empty PKCS#7 signature")

# struct module_signature: algo, hash, id_type, signer_len, key_id_len,
# three padding bytes, then a big-endian signature length.
signature_header = struct.pack(">BBBBB3xI", 0, 0, 2, 0, 0, len(signature))
with open(module_path, "ab") as module_file:
    module_file.write(signature)
    module_file.write(signature_header)
    module_file.write(signature_magic)
PY
""".format(
        subject=shlex.quote("/CN={}/".format(UNTRUSTED_SIGNER)),
        key_path=shlex.quote(UNTRUSTED_KEY_PATH),
        cert_path=shlex.quote(UNTRUSTED_CERT_PATH),
        module_path=shlex.quote(module_path),
        signature_path=shlex.quote(UNTRUSTED_SIGNATURE_PATH),
    )
    duthost.shell(command)

    signer = duthost.command(
        "modinfo -F signer {}".format(shlex.quote(module_path))
    )["stdout"].strip()
    pytest_assert(signer == UNTRUSTED_SIGNER, "The test module was not signed by the temporary certificate")


def _load_module(duthost, module_path):
    dmesg_before = duthost.command("sudo dmesg --notime")["stdout"]
    load_result = duthost.command(
        "sudo insmod {}".format(shlex.quote(module_path)),
        module_ignore_errors=True,
    )
    dmesg_after = duthost.command("sudo dmesg --notime")["stdout"]

    new_dmesg = dmesg_after[len(dmesg_before):] if dmesg_after.startswith(dmesg_before) else dmesg_after
    rejection_output = "{}\n{}\n{}".format(
        load_result["stdout"],
        load_result["stderr"],
        new_dmesg,
    ).lower()
    return load_result, rejection_output


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
        _copy_uncompressed_module(duthost, source_path, UNSIGNED_MODULE_PATH)

        # Removing the signature keeps the module compatible with the running kernel
        # while making it untrusted by the Secure Boot chain of trust.
        _remove_module_signatures(duthost, UNSIGNED_MODULE_PATH)
        load_result, rejection_output = _load_module(duthost, UNSIGNED_MODULE_PATH)

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


# Verify that a valid signature from a key outside the kernel trust store is rejected.
def test_untrusted_kernel_module_is_rejected(duthost):
    """Verify that Secure Boot prevents an untrusted signed kernel module from loading."""
    require_secure_boot(duthost)

    source_path = _find_unloaded_kernel_module(duthost)
    pytest_assert(source_path, "No unloaded kernel module is available for the Secure Boot test")
    module_name = duthost.command(
        "modinfo -F name {}".format(shlex.quote(source_path))
    )["stdout"].strip()

    try:
        _copy_uncompressed_module(duthost, source_path, UNTRUSTED_MODULE_PATH)
        _remove_module_signatures(duthost, UNTRUSTED_MODULE_PATH)
        _sign_module_with_untrusted_key(duthost, UNTRUSTED_MODULE_PATH)
        load_result, rejection_output = _load_module(duthost, UNTRUSTED_MODULE_PATH)

        pytest_assert(load_result["rc"] != 0, "The kernel loaded a module signed by an untrusted key")
        pytest_assert(
            any(message in rejection_output for message in SIGNATURE_REJECTION_MESSAGES),
            "The module load failed without evidence of signature enforcement: {}".format(rejection_output),
        )
    finally:
        duthost.command(
            "sudo rmmod {}".format(shlex.quote(module_name)),
            module_ignore_errors=True,
        )
        temporary_paths = (
            UNTRUSTED_MODULE_PATH,
            UNTRUSTED_KEY_PATH,
            UNTRUSTED_CERT_PATH,
            UNTRUSTED_SIGNATURE_PATH,
        )
        duthost.command(
            "rm -f {}".format(" ".join(shlex.quote(path) for path in temporary_paths)),
            module_ignore_errors=True,
        )
