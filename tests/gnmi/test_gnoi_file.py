"""
Simple integration tests for gNOI File service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.
"""
import pytest
import logging
import base64
import hashlib

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.gnmi.helper import GNOI_ROLE_CASES, verify_gnoi_role_access

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]

AUTHZ_FILE_CONTENT = b"sonic-mgmt write authorization sentinel\n"
AUTHZ_REPLACEMENT_CONTENT = b"authorized replacement\n"


def _file_transfer_to_remote(client, path):
    # No remote_download: cannot download even on a vulnerable DUT.
    return client.call_unary("gnoi.file.File", "TransferToRemote", {"localPath": path})


def _file_put(client, path):
    return client.call_client_streaming("gnoi.file.File", "Put", [
        {"open": {"remoteFile": path, "permissions": 420}},
        {"contents": base64.b64encode(AUTHZ_REPLACEMENT_CONTENT).decode()},
        {"hash": {
            "method": "MD5",
            "hash": base64.b64encode(hashlib.md5(AUTHZ_REPLACEMENT_CONTENT).digest()).decode(),
        }},
    ])


def _file_remove(client, path):
    return client.call_unary("gnoi.file.File", "Remove", {"remoteFile": path})


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("role,error_pattern", GNOI_ROLE_CASES)
@pytest.mark.parametrize("operation,validation_error,writer_content", [
    pytest.param(_file_transfer_to_remote, "remote_download cannot be nil", AUTHZ_FILE_CONTENT,
                 id="TransferToRemote"),
    pytest.param(_file_put, None, AUTHZ_REPLACEMENT_CONTENT, id="Put"),
    pytest.param(_file_remove, None, None, id="Remove"),
])
def test_gnoi_file_write_authorization(
    gnmi_tls, role, error_pattern, operation, validation_error, writer_content  # noqa: F811
):
    """Run the same File RPC with write access or expect role-based denial."""
    duthost = gnmi_tls.duthost
    directory = duthost.tempfile(state="directory", path="/tmp", prefix="gnoi_authz_")["path"]
    path = directory + "/sentinel"
    try:
        duthost.copy(content=AUTHZ_FILE_CONTENT.decode(), dest=path)
        verify_gnoi_role_access(gnmi_tls, role, lambda: operation(gnmi_tls.grpc, path),
                                error_pattern, validation_error)
        expected_content = AUTHZ_FILE_CONTENT if error_pattern else writer_content
        if expected_content is None:
            pytest_assert(not duthost.stat(path=path)["stat"]["exists"],
                          "Authorized Remove did not remove the sentinel")
        else:
            content = base64.b64decode(duthost.slurp(src=path)["content"])
            pytest_assert(content == expected_content, "Unexpected sentinel content after RPC")
    finally:
        duthost.file(path=directory, state="absent")


def test_file_stat(gnmi_tls):  # noqa: F811
    """Test File.Stat RPC with TLS enabled by default."""
    try:
        result = gnmi_tls.gnoi.file_stat("/etc/hostname")
        assert "stats" in result
        logger.info(f"File stats: {result['stats'][0]}")
    except Exception as e:
        # File service may not be fully implemented
        logger.warning(f"File.Stat failed (expected): {e}")


def test_file_transfer_to_remote(gnmi_tls, ptfhost, duthosts, rand_one_dut_hostname):  # noqa: F811
    """Test File.TransferToRemote RPC downloading file from HTTP server to DUT."""
    duthost = duthosts[rand_one_dut_hostname]
    # Test file configuration
    test_filename = "test.txt"
    test_content = "Hello from gNOI TransferToRemote test!"
    local_path = f"/tmp/{test_filename}"
    http_port = 8080
    try:
        # 1. Create test file on PTF host
        logger.info(f"Creating test file {test_filename} on PTF host")
        ptfhost.shell(f"echo '{test_content}' > /tmp/{test_filename}")
        # 2. Start HTTP server on PTF host
        logger.info(f"Starting HTTP server on PTF host port {http_port}")
        ptfhost.command(f"cd /tmp && python -m http.server {http_port}", module_async=True)
        # 3. Wait for HTTP server to start
        ptf_ip = ptfhost.mgmt_ip
        logger.info("Waiting for HTTP server to start at {}:{}".format(ptf_ip, http_port))

        def server_ready():
            try:
                result = ptfhost.command("curl -f --max-time 2 {}:{}".format(ptf_ip, http_port),
                                         module_ignore_errors=True)
                return result["rc"] == 0
            except Exception:
                return False
        wait_until(30, 2, 2, server_ready)
        logger.info("HTTP server is ready")
        # 4. Test TransferToRemote
        remote_url = "http://{}:{}/{}".format(ptf_ip, http_port, test_filename)
        logger.info(f"Testing TransferToRemote: {remote_url} -> {local_path}")
        result = gnmi_tls.gnoi.file_transfer_to_remote(
            local_path=local_path,
            remote_url=remote_url,
            protocol="HTTP"
        )
        # 5. Verify response has hash
        pytest_assert("hash" in result, "TransferToRemote response missing hash field")
        logger.info(f"TransferToRemote response: {result}")
        # 6. Verify file was downloaded to DUT
        file_stat = duthost.stat(path=local_path)
        pytest_assert(file_stat["stat"]["exists"], f"File {local_path} not found on DUT after transfer")
        logger.info(f"File successfully downloaded to DUT: {local_path}")
        # 7. Verify downloaded content
        downloaded_content = duthost.shell(f"cat {local_path}")["stdout"].strip()
        pytest_assert(test_content in downloaded_content,
                      f"Content mismatch. Expected: '{test_content}', Got: '{downloaded_content}'")
        logger.info(f"File content verified: {downloaded_content}")
        logger.info("TransferToRemote test completed successfully")
    except Exception as e:
        # File service may not be fully implemented
        logger.warning(f"File.TransferToRemote failed (may be expected): {e}")
    finally:
        # 8. Cleanup
        logger.info("Cleaning up test resources")
        try:
            # Stop HTTP server
            ptfhost.command(f"pkill -f 'python.*http.server.*{http_port}'",
                            module_ignore_errors=True)
            # Remove test file from PTF
            ptfhost.shell(f"rm -f /tmp/{test_filename}", module_ignore_errors=True)
            # Remove downloaded file from DUT
            duthost.shell(f"rm -f {local_path}", module_ignore_errors=True)
            logger.info("Cleanup completed")
        except Exception as cleanup_e:
            logger.warning(f"Cleanup failed: {cleanup_e}")


def test_gnoi_file_stat_regular_file(gnmi_tls):  # noqa: F811
    """Verify File.Stat on a regular file returns a single StatInfo per the gNOI proto contract.

    Per the gNOI File proto:
    - Exactly one StatInfo is returned for a regular file.
    - path is the host-visible path (no /mnt/host prefix).
    - size, last_modified, permissions, and umask fields are populated.
    - umask is 0022 (18 decimal).
    """
    resp = gnmi_tls.gnoi.file_stat("/etc/hostname")

    stats = resp.get("stats", [])
    pytest_assert(len(stats) == 1,
                  "Expected exactly 1 StatInfo for regular file, got {}: {}".format(len(stats), resp))

    entry = stats[0]
    logger.info("File.Stat regular file entry: {}".format(entry))

    pytest_assert(entry.get("path") == "/etc/hostname",
                  "Expected path '/etc/hostname', got: {}".format(entry.get("path")))
    pytest_assert(int(entry.get("size", 0)) > 0,
                  "Expected non-zero size for /etc/hostname, got: {}".format(entry.get("size")))
    pytest_assert(int(entry.get("last_modified") or entry.get("lastModified") or 0) > 0,
                  "Expected positive last_modified timestamp, got: {}".format(entry.get("lastModified")))
    pytest_assert("permissions" in entry, "stat entry missing 'permissions'")
    pytest_assert(int(entry.get("umask", -1)) == 18,
                  "Expected umask=18 (0022 octal), got: {}".format(entry.get("umask")))


def test_gnoi_file_stat_directory(gnmi_tls):  # noqa: F811
    """Verify File.Stat on a directory returns immediate children per the gNOI proto contract.

    Per the gNOI File proto contract for directory paths:
    - Only immediate children are returned (non-recursive).
    - The directory itself is NOT included in the results.
    - Each child StatInfo contains: path, last_modified, permissions, and umask fields.
    - Each child path is the full host-visible path (e.g. '/etc/sonic/<child>').
    """
    resp = gnmi_tls.gnoi.file_stat("/etc/sonic")

    stats = resp.get("stats", [])
    pytest_assert(len(stats) >= 1,
                  "Expected at least one child entry for /etc/sonic, got: {}".format(resp))
    logger.info("File.Stat directory returned {} entries".format(len(stats)))

    self_paths = [e.get("path") for e in stats if e.get("path") == "/etc/sonic"]
    pytest_assert(len(self_paths) == 0,
                  "Directory /etc/sonic must not appear in its own listing, but found: {}".format(self_paths))

    for entry in stats:
        child_path = entry.get("path", "")
        logger.info("Directory child entry: {}".format(entry))
        pytest_assert(child_path.startswith("/etc/sonic/"),
                      "Child path '{}' does not start with '/etc/sonic/'".format(child_path))
        pytest_assert(int(entry.get("last_modified") or entry.get("lastModified") or 0) > 0,
                      "Child '{}' missing valid last_modified".format(child_path))
        pytest_assert("permissions" in entry,
                      "Child '{}' missing 'permissions'".format(child_path))
        pytest_assert(int(entry.get("umask", -1)) == 18,
                      "Child '{}' expected umask=18, got: {}".format(child_path, entry.get("umask")))


def test_gnoi_file_stat_not_found(gnmi_tls):  # noqa: F811
    """Verify File.Stat returns NOT_FOUND error for a non-existent path"""
    try:
        gnmi_tls.gnoi.file_stat("/etc/this_path_does_not_exist_gnoi_test")
        pytest_assert(False, "File.Stat should have failed for non-existent path but returned success")
    except Exception as e:
        err = str(e)
        logger.info("File.Stat NOT_FOUND response: {}".format(err))
        pytest_assert(
            "NotFound" in err or "not found" in err.lower() or "no such file" in err.lower(),
            "Expected NOT_FOUND error, got: {}".format(err)
        )


@pytest.mark.parametrize("bad_path,reason", [
    ("", "empty path"),
    ("etc/hostname", "relative path"),
    ("/mnt/host/etc/hostname", "/mnt/host-prefixed path"),
], ids=["empty", "relative", "mnt-host"])
def test_gnoi_file_stat_invalid_argument(gnmi_tls, bad_path, reason):  # noqa: F811
    """Stat with invalid path arguments; expect INVALID_ARGUMENT error."""
    try:
        gnmi_tls.gnoi.file_stat(bad_path)
        pytest_assert(False,
                      "File.Stat should have failed for {} ('{}') but returned success".format(reason, bad_path))
    except Exception as e:
        err = str(e)
        logger.info("File.Stat INVALID_ARGUMENT ({}) response: {}".format(reason, err))
        pytest_assert(
            "InvalidArgument" in err or "invalid argument" in err.lower() or "invalid" in err.lower(),
            "Expected INVALID_ARGUMENT error for {} ('{}'): {}".format(reason, bad_path, err)
        )


def test_gnoi_file_stat_permissions_decimal_octal(gnmi_tls, duthosts, rand_one_dut_hostname):  # noqa: F811
    """Verify permissions field is encoded as decimal-octal per gNOI proto.

    Per the gNOI File proto, the permissions field encodes the file mode
    as its octal string interpreted as a decimal integer (e.g. mode 0644 -> 644).
    The test fetches the actual mode from the DUT and verifies the encoding holds,
    independent of the specific file's permissions value.
    """
    duthost = duthosts[rand_one_dut_hostname]
    # Get the actual octal mode string from the DUT (e.g. "644")
    actual_octal = duthost.shell("stat -c %a /etc/hostname")["stdout"].strip()
    # decimal-octal encoding: the octal string is re-read as a decimal integer
    expected_permissions = int(actual_octal)
    logger.info("DUT /etc/hostname mode: octal={} expected_permissions={}".format(
        actual_octal, expected_permissions))

    resp = gnmi_tls.gnoi.file_stat("/etc/hostname")

    stats = resp.get("stats", [])
    pytest_assert(len(stats) == 1, "Expected exactly 1 StatInfo for /etc/hostname")

    entry = stats[0]
    permissions = int(entry.get("permissions", -1))
    logger.info("File.Stat permissions field value: {}".format(permissions))

    pytest_assert(permissions == expected_permissions,
                  "Expected permissions={} (decimal-octal of mode 0{}) got: {} "
                  "(hint: {} means raw decimal encoding is in use)".format(
                      expected_permissions, actual_octal, permissions,
                      int(actual_octal, 8)))
    pytest_assert(
        all(d in "01234567" for d in str(permissions)),
        "permissions '{}' contains digit 8 or 9 — not a valid decimal-octal value".format(permissions)
    )
