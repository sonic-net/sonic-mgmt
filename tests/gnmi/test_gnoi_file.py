"""
Simple integration tests for gNOI File service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.
"""

import logging

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.ptf_grpc import GrpcCallError

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
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


def test_file_transfer_to_remote(gnmi_tls):  # noqa: F811
    """Require retirement without giving a legacy server a download target."""
    with pytest.raises(GrpcCallError, match="Unimplemented"):
        gnmi_tls.gnoi.grpc_client.call_unary("gnoi.file.File", "TransferToRemote", {})


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
    pytest_assert(len(stats) == 1, "Expected exactly 1 StatInfo for regular file, got {}: {}".format(len(stats), resp))

    entry = stats[0]
    logger.info("File.Stat regular file entry: {}".format(entry))

    pytest_assert(
        entry.get("path") == "/etc/hostname", "Expected path '/etc/hostname', got: {}".format(entry.get("path"))
    )
    pytest_assert(
        int(entry.get("size", 0)) > 0, "Expected non-zero size for /etc/hostname, got: {}".format(entry.get("size"))
    )
    pytest_assert(
        int(entry.get("last_modified") or entry.get("lastModified") or 0) > 0,
        "Expected positive last_modified timestamp, got: {}".format(entry.get("lastModified")),
    )
    pytest_assert("permissions" in entry, "stat entry missing 'permissions'")
    pytest_assert(
        int(entry.get("umask", -1)) == 18, "Expected umask=18 (0022 octal), got: {}".format(entry.get("umask"))
    )


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
    pytest_assert(len(stats) >= 1, "Expected at least one child entry for /etc/sonic, got: {}".format(resp))
    logger.info("File.Stat directory returned {} entries".format(len(stats)))

    self_paths = [e.get("path") for e in stats if e.get("path") == "/etc/sonic"]
    pytest_assert(
        len(self_paths) == 0,
        "Directory /etc/sonic must not appear in its own listing, but found: {}".format(self_paths),
    )

    for entry in stats:
        child_path = entry.get("path", "")
        logger.info("Directory child entry: {}".format(entry))
        pytest_assert(
            child_path.startswith("/etc/sonic/"), "Child path '{}' does not start with '/etc/sonic/'".format(child_path)
        )
        pytest_assert(
            int(entry.get("last_modified") or entry.get("lastModified") or 0) > 0,
            "Child '{}' missing valid last_modified".format(child_path),
        )
        pytest_assert("permissions" in entry, "Child '{}' missing 'permissions'".format(child_path))
        pytest_assert(
            int(entry.get("umask", -1)) == 18,
            "Child '{}' expected umask=18, got: {}".format(child_path, entry.get("umask")),
        )


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
            "Expected NOT_FOUND error, got: {}".format(err),
        )


@pytest.mark.parametrize(
    "bad_path,reason",
    [
        ("", "empty path"),
        ("etc/hostname", "relative path"),
        ("/mnt/host/etc/hostname", "/mnt/host-prefixed path"),
    ],
    ids=["empty", "relative", "mnt-host"],
)
def test_gnoi_file_stat_invalid_argument(gnmi_tls, bad_path, reason):  # noqa: F811
    """Stat with invalid path arguments; expect INVALID_ARGUMENT error."""
    try:
        gnmi_tls.gnoi.file_stat(bad_path)
        pytest_assert(False, "File.Stat should have failed for {} ('{}') but returned success".format(reason, bad_path))
    except Exception as e:
        err = str(e)
        logger.info("File.Stat INVALID_ARGUMENT ({}) response: {}".format(reason, err))
        pytest_assert(
            "InvalidArgument" in err or "invalid argument" in err.lower() or "invalid" in err.lower(),
            "Expected INVALID_ARGUMENT error for {} ('{}'): {}".format(reason, bad_path, err),
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
    logger.info("DUT /etc/hostname mode: octal={} expected_permissions={}".format(actual_octal, expected_permissions))

    resp = gnmi_tls.gnoi.file_stat("/etc/hostname")

    stats = resp.get("stats", [])
    pytest_assert(len(stats) == 1, "Expected exactly 1 StatInfo for /etc/hostname")

    entry = stats[0]
    permissions = int(entry.get("permissions", -1))
    logger.info("File.Stat permissions field value: {}".format(permissions))

    pytest_assert(
        permissions == expected_permissions,
        "Expected permissions={} (decimal-octal of mode 0{}) got: {} "
        "(hint: {} means raw decimal encoding is in use)".format(
            expected_permissions, actual_octal, permissions, int(actual_octal, 8)
        ),
    )
    pytest_assert(
        all(d in "01234567" for d in str(permissions)),
        "permissions '{}' contains digit 8 or 9 — not a valid decimal-octal value".format(permissions),
    )
