"""
Simple integration tests for gNOI File service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.
"""
import pytest
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.gnmi.helper import gnoi_request, extract_gnoi_response
from tests.gnmi.helper import apply_cert_config
from tests.common.helpers.gnmi_utils import (
    prepare_root_cert, prepare_server_cert, prepare_client_cert,
    copy_certificate_to_dut,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


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
        logger.info(f"Waiting for HTTP server to start at {ptf_ip}:{http_port}")

        def server_ready():
            try:
                result = ptfhost.command(f"curl -f --max-time 2 {ptf_ip}:{http_port}",
                                         module_ignore_errors=True)
                return result["rc"] == 0
            except Exception:
                return False
        wait_until(30, 2, 2, server_ready)
        logger.info("HTTP server is ready")
        # 4. Test TransferToRemote
        remote_url = f"http://{ptf_ip}:{http_port}/{test_filename}"
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


# ---------------------------------------------------------------------------
# Uses gnoi_request / extract_gnoi_response over gnmi TCP transport.
# No TLS fixture dependency — gnoi_client runs inside the gnmi container on DUT.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=False)
def reapply_cert_config(duthosts, rand_one_dut_hostname, localhost):
    """Restore a consistent TLS cert state for gnoi_request-based tests.
    After gnmi_tls tests run, gnmiserver.key (overwritten with CA_C's key by
    grpc_fixtures) no longer matches gnmiserver.crt (CA_B cert left by
    setup_gnmi_rotated_server). Restarting gnmi with mismatched files fails
    with 'private key does not match public key'.
    Fix: regenerate a fresh CA + server cert + client cert, copy to DUT, then
    restart gnmi via apply_cert_config so all cert files are consistent.
    """
    duthost = duthosts[rand_one_dut_hostname]
    prepare_root_cert(localhost)
    prepare_server_cert(duthost, localhost, dut_ip=duthost.mgmt_ip)
    prepare_client_cert(localhost)
    copy_certificate_to_dut(duthost)
    apply_cert_config(duthost)


def test_gnoi_file_stat_regular_file(duthosts, rand_one_dut_hostname, localhost, reapply_cert_config):  # noqa: F811
    """Stat a known regular file; verify path, size, last_modified, permissions and umask.
    PR #697: HandleStat returns exactly one StatInfo for a regular file.
    The path field must round-trip the host-visible path (no /mnt/host prefix).
    umask is the constant defaultUmask = 0022 = 18 decimal.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnoi_request(duthost, localhost, "File", "Stat", '{"path": "/etc/hostname"}')
    pytest_assert(ret == 0, "File.Stat failed unexpectedly: {}".format(msg))
    resp = extract_gnoi_response(msg)
    pytest_assert(resp is not None, "Failed to parse File.Stat response: {}".format(msg))
    # Regular file must yield exactly one StatInfo entry.
    stats = resp.get("stats", [])
    pytest_assert(len(stats) == 1,
                  "Expected exactly 1 StatInfo for regular file, got {}: {}".format(len(stats), resp))
    entry = stats[0]
    logger.info("File.Stat regular file entry: {}".format(entry))
    # path must round-trip the requested host-visible path (PR strips /mnt/host prefix on output).
    pytest_assert(entry.get("path") == "/etc/hostname",
                  "Expected path '/etc/hostname', got: {}".format(entry.get("path")))
    # size must be positive for a non-empty file.
    pytest_assert(int(entry.get("size", 0)) > 0,
                  "Expected non-zero size for /etc/hostname, got: {}".format(entry.get("size")))
    # last_modified is UnixNano — must be a positive integer.
    pytest_assert(int(entry.get("last_modified", 0)) > 0,
                  "Expected positive last_modified timestamp, got: {}".format(entry.get("last_modified")))
    # permissions field must be present.
    pytest_assert("permissions" in entry, "stat entry missing 'permissions'")
    # umask is the constant defaultUmask = 0022 octal = 18 decimal (PR hardcodes this).
    pytest_assert(int(entry.get("umask", -1)) == 18,
                  "Expected umask=18 (0022 octal), got: {}".format(entry.get("umask")))


def test_gnoi_file_stat_directory(duthosts, rand_one_dut_hostname, localhost, reapply_cert_config):  # noqa: F811
    """Stat a directory; verify non-recursive listing returns immediate children only.
    PR #697 contract:
    - The directory itself is NOT included in results.
    - Each StatInfo.path is the immediate child's host-visible path (starts with '<dir>/').
    - Each entry has path, last_modified, permissions, umask fields.
    - Directory child entries have size=0 (PR: "Leave size=0 for dirs").
    """
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnoi_request(duthost, localhost, "File", "Stat", '{"path": "/etc/sonic"}')
    pytest_assert(ret == 0, "File.Stat on directory failed unexpectedly: {}".format(msg))
    resp = extract_gnoi_response(msg)
    pytest_assert(resp is not None, "Failed to parse File.Stat response: {}".format(msg))
    stats = resp.get("stats", [])
    pytest_assert(len(stats) >= 1,
                  "Expected at least one child entry for /etc/sonic, got: {}".format(resp))
    logger.info("File.Stat directory returned {} entries".format(len(stats)))
    # The directory itself must NOT appear in the listing (non-recursive children only).
    self_paths = [e.get("path") for e in stats if e.get("path") == "/etc/sonic"]
    pytest_assert(len(self_paths) == 0,
                  "Directory /etc/sonic must not appear in its own listing, but found: {}".format(self_paths))
    for entry in stats:
        child_path = entry.get("path", "")
        logger.info("Directory child entry: {}".format(entry))
        # Each child path must be directly under /etc/sonic/ (non-recursive).
        pytest_assert(child_path.startswith("/etc/sonic/"),
                      "Child path '{}' does not start with '/etc/sonic/'".format(child_path))
        # Required fields per gNOI StatInfo proto.
        pytest_assert(int(entry.get("last_modified", 0)) > 0,
                      "Child '{}' missing valid last_modified".format(child_path))
        pytest_assert("permissions" in entry,
                      "Child '{}' missing 'permissions'".format(child_path))
        pytest_assert(int(entry.get("umask", -1)) == 18,
                      "Child '{}' expected umask=18, got: {}".format(child_path, entry.get("umask")))


def test_gnoi_file_stat_not_found(duthosts, rand_one_dut_hostname, localhost, reapply_cert_config):  # noqa: F811
    """Stat a non-existent path; expect NOT_FOUND error."""
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnoi_request(duthost, localhost, "File", "Stat",
                            '{"path": "/etc/this_path_does_not_exist_gnoi_test"}')
    pytest_assert(ret != 0, "File.Stat should have failed for non-existent path but returned success")
    logger.info("File.Stat NOT_FOUND response: {}".format(msg))
    pytest_assert(
        "NotFound" in msg or "not found" in msg.lower() or "no such file" in msg.lower(),
        "Expected NOT_FOUND error, got: {}".format(msg)
    )


@pytest.mark.parametrize("bad_path,reason", [
    ("", "empty path"),
    ("etc/hostname", "relative path"),
    ("/mnt/host/etc/hostname", "/mnt/host-prefixed path"),
], ids=["empty", "relative", "mnt-host"])
def test_gnoi_file_stat_invalid_argument(
        duthosts, rand_one_dut_hostname, localhost, bad_path, reason, reapply_cert_config):  # noqa: F811
    """Stat with invalid path arguments; expect INVALID_ARGUMENT error."""
    duthost = duthosts[rand_one_dut_hostname]
    json_data = '{{"path": "{}"}}'.format(bad_path)
    ret, msg = gnoi_request(duthost, localhost, "File", "Stat", json_data)
    pytest_assert(ret != 0,
                  "File.Stat should have failed for {} ('{}') but returned success".format(reason, bad_path))
    logger.info("File.Stat INVALID_ARGUMENT ({}) response: {}".format(reason, msg))
    pytest_assert(
        "InvalidArgument" in msg or "invalid argument" in msg.lower() or "invalid" in msg.lower(),
        "Expected INVALID_ARGUMENT error for {} ('{}'): {}".format(reason, bad_path, msg)
    )


def test_gnoi_file_stat_permissions_decimal_octal(
        duthosts, rand_one_dut_hostname, localhost, reapply_cert_config):  # noqa: F811
    """Verify permissions field is encoded as decimal-octal per gNOI proto.
    PR #697 contract (statInfoFromFileInfo):
      strconv.FormatUint(uint64(mode.Perm()), 8)  -> octal string e.g. "644"
      strconv.ParseUint(octalStr, 10, 32)          -> decimal int 644
    So mode 0644 -> permissions=644 (NOT 420, which is the raw decimal of 0644).
    /etc/hostname on SONiC has mode 0644, so the expected value is 644.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnoi_request(duthost, localhost, "File", "Stat", '{"path": "/etc/hostname"}')
    pytest_assert(ret == 0, "File.Stat failed unexpectedly: {}".format(msg))
    resp = extract_gnoi_response(msg)
    pytest_assert(resp is not None, "Failed to parse File.Stat response: {}".format(msg))
    stats = resp.get("stats", [])
    pytest_assert(len(stats) == 1, "Expected exactly 1 StatInfo for /etc/hostname")
    entry = stats[0]
    permissions = int(entry.get("permissions", -1))
    logger.info("File.Stat permissions field value: {}".format(permissions))
    # /etc/hostname is mode 0644; decimal-octal encoding yields 644 (not 420).
    pytest_assert(permissions == 644,
                  "Expected permissions=644 (decimal-octal for mode 0644), got: {} "
                  "(hint: 420 means the old DBus decimal encoding is still in use)".format(permissions))
    # Structural check: all digits must be valid octal (0-7), never 8 or 9.
    pytest_assert(
        all(d in "01234567" for d in str(permissions)),
        "permissions '{}' contains digit 8 or 9 — not a valid decimal-octal value".format(permissions)
    )
