"""
 * test_gnoi_oras.py -- Integration tests for gNOI ORAS Pull service.
 *
 * This module tests the sonic.gnoi.oras.v1.Oras service which allows
 * an orchestrator to instruct a SONiC switch to pull an OCI/ORAS
 * artifact (e.g. a SONiC OS image) from a container registry into
 * local storage on the device.
 *
 * The Pull RPC is a server-streaming call that returns:
 *   PullStarted  -> manifest resolved, total size known
 *   PullProgress -> periodic byte-count updates (~1/sec)
 *   PullResult   -> final digest, bytes written, elapsed time
 *
 * Prerequisites:
 *   - DUT must be running a sonic-gnmi build that includes the Oras
 *     service (PR #692 or later).
 *   - The registry (ksdatatest.azurecr.io) must be reachable from
 *     the DUT or via an HTTP proxy configured on the gnmi container.
 *   - Credentials are passed via environment variables:
 *       ORAS_TEST_USERNAME  (default: ksdatatest)
 *       ORAS_TEST_PASSWORD  (required)
"""

import os
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]

# ---------------------------------------------------------------------------
# Test configuration -- override via environment variables if needed
# ---------------------------------------------------------------------------

ORAS_REGISTRY = os.environ.get("ORAS_TEST_REGISTRY", "ksdatatest.azurecr.io")
ORAS_REPOSITORY = os.environ.get("ORAS_TEST_REPOSITORY", "sonic-os-images")
ORAS_TAG = os.environ.get(
    "ORAS_TEST_TAG", "sonic-broadcom-slim-20230531.46.bin"
)
ORAS_USERNAME = os.environ.get("ORAS_TEST_USERNAME", "ksdatatest")
ORAS_PASSWORD = os.environ.get("ORAS_TEST_PASSWORD", "")

# Where to store the pulled artifact on the DUT
ORAS_LOCAL_PATH = "/tmp/oras_test_image.bin"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def skip_if_no_password():
    """
     * Skip the test if ORAS_TEST_PASSWORD is not set.
     * We don't want tests to fail just because creds weren't configured.
    """
    if not ORAS_PASSWORD:
        pytest.skip(
            "ORAS_TEST_PASSWORD not set -- skipping ORAS pull test. "
            "Export the env var and re-run."
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_gnoi_oras_pull_basic_auth(duthosts, rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_basic_auth
     *
     * Verify the Oras.Pull RPC can download an artifact from ACR
     * using basic (username/password) authentication.
     *
     * Steps:
     *   1. Call Oras.Pull with registry, repo, tag, and credentials.
     *   2. Assert we receive a PullStarted message with total_bytes > 0.
     *   3. Assert the final PullResult contains a valid layer digest.
     *   4. Verify the file actually exists on the DUT at local_path.
     *   5. Clean up the downloaded file.
    """
    skip_if_no_password()

    duthost = duthosts[rand_one_dut_hostname]

    # -- Step 1: Call the Pull RPC ----------------------------------------
    logger.info(
        "Pulling {}/{}:{} -> {}".format(
            ORAS_REGISTRY, ORAS_REPOSITORY, ORAS_TAG, ORAS_LOCAL_PATH
        )
    )

    responses = gnmi_tls.gnoi.oras_pull(
        registry=ORAS_REGISTRY,
        repository=ORAS_REPOSITORY,
        local_path=ORAS_LOCAL_PATH,
        tag=ORAS_TAG,
        username=ORAS_USERNAME,
        password=ORAS_PASSWORD,
    )

    # -- Step 2: Validate PullStarted -------------------------------------
    #    First message in the stream should be PullStarted.
    pytest_assert(
        len(responses) >= 2,
        f"Expected at least 2 stream messages (started + result), got {len(responses)}"
    )

    first = responses[0]
    pytest_assert(
        "started" in first,
        f"First stream message should be 'started', got: {first}"
    )

    total_bytes = int(first["started"].get("totalBytes", 0))
    pytest_assert(
        total_bytes > 0,
        f"PullStarted.total_bytes should be > 0, got {total_bytes}"
    )
    logger.info(f"PullStarted: manifest resolved, total_bytes={total_bytes}")

    # -- Step 3: Validate PullResult --------------------------------------
    #    Last message in the stream should be PullResult.
    last = responses[-1]
    pytest_assert(
        "result" in last,
        f"Last stream message should be 'result', got: {last}"
    )

    result = last["result"]
    layer_digest = result.get("layerDigest", "")
    pytest_assert(
        layer_digest.startswith("sha256:"),
        "Expected layer_digest to start with 'sha256:', got: {}".format(layer_digest)
    )

    bytes_written = int(result.get("bytesWritten", 0))
    pytest_assert(
        bytes_written == total_bytes,
        f"bytes_written ({bytes_written}) should match total_bytes ({total_bytes})"
    )
    logger.info(f"PullResult: layer_digest={layer_digest}, bytes_written={bytes_written}")

    # -- Step 4: Verify file exists on DUT --------------------------------
    stat_cmd = f"stat --format='%s' {ORAS_LOCAL_PATH}"
    stat_result = duthost.shell(stat_cmd, module_ignore_errors=True)
    pytest_assert(
        stat_result["rc"] == 0,
        f"File {ORAS_LOCAL_PATH} not found on DUT after pull"
    )

    file_size = int(stat_result["stdout"].strip())
    pytest_assert(
        file_size == bytes_written,
        f"File size on disk ({file_size}) != bytes_written ({bytes_written})"
    )
    logger.info(f"File verified on DUT: {ORAS_LOCAL_PATH} ({file_size} bytes)")

    # -- Step 5: Cleanup --------------------------------------------------
    duthost.shell(f"rm -f {ORAS_LOCAL_PATH}", module_ignore_errors=True)
    logger.info("Cleanup complete")


def test_gnoi_oras_pull_invalid_path(gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_invalid_path
     *
     * Verify that the Oras.Pull RPC rejects a local_path that is
     * outside the allowed directories (/tmp, /var/tmp, /host).
     *
     * The server should return a FailedPrecondition (or InvalidArgument)
     * gRPC error without downloading anything.
    """
    skip_if_no_password()

    with pytest.raises(Exception) as exc_info:
        gnmi_tls.gnoi.oras_pull(
            registry=ORAS_REGISTRY,
            repository=ORAS_REPOSITORY,
            local_path="/etc/passwd",  # Not allowed!
            tag=ORAS_TAG,
            username=ORAS_USERNAME,
            password=ORAS_PASSWORD,
        )

    # The error should mention permission/precondition/allowlist
    error_msg = str(exc_info.value).lower()
    pytest_assert(
        any(term in error_msg for term in ["precondition", "permission", "allowlist", "invalid"]),
        f"Expected path rejection error, got: {exc_info.value}"
    )
    logger.info(f"Path correctly rejected: {exc_info.value}")


def test_gnoi_oras_pull_bad_credentials(gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_bad_credentials
     *
     * Verify that the Oras.Pull RPC returns Unauthenticated when
     * given wrong credentials.
    """
    with pytest.raises(Exception) as exc_info:
        gnmi_tls.gnoi.oras_pull(
            registry=ORAS_REGISTRY,
            repository=ORAS_REPOSITORY,
            local_path=ORAS_LOCAL_PATH,
            tag=ORAS_TAG,
            username="wrong_user",
            password="wrong_password",
        )

    error_msg = str(exc_info.value).lower()
    pytest_assert(
        any(term in error_msg for term in ["unauthenticated", "unauthorized", "401"]),
        f"Expected auth error, got: {exc_info.value}"
    )
    logger.info(f"Bad credentials correctly rejected: {exc_info.value}")


def test_gnoi_oras_pull_nonexistent_tag(gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_nonexistent_tag
     *
     * Verify that the Oras.Pull RPC returns an appropriate error
     * when the requested tag does not exist in the registry.
    """
    skip_if_no_password()

    with pytest.raises(Exception) as exc_info:
        gnmi_tls.gnoi.oras_pull(
            registry=ORAS_REGISTRY,
            repository=ORAS_REPOSITORY,
            local_path=ORAS_LOCAL_PATH,
            tag="this-tag-does-not-exist-12345",
            username=ORAS_USERNAME,
            password=ORAS_PASSWORD,
        )

    error_msg = str(exc_info.value).lower()
    pytest_assert(
        any(term in error_msg for term in ["not found", "404", "unavailable", "unknown"]),
        f"Expected not-found error, got: {exc_info.value}"
    )
    logger.info(f"Nonexistent tag correctly rejected: {exc_info.value}")


def test_gnoi_oras_pull_anonymous_denied(gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_anonymous_denied
     *
     * Verify that pulling from a private registry without credentials
     * returns an authentication error.
     *
     * Note: This test assumes ksdatatest.azurecr.io requires auth.
     * If the registry allows anonymous pulls, this test should be
     * updated or skipped.
    """
    with pytest.raises(Exception) as exc_info:
        gnmi_tls.gnoi.oras_pull(
            registry=ORAS_REGISTRY,
            repository=ORAS_REPOSITORY,
            local_path=ORAS_LOCAL_PATH,
            tag=ORAS_TAG,
            # No credentials -- anonymous
        )

    error_msg = str(exc_info.value).lower()
    pytest_assert(
        any(term in error_msg for term in ["unauthenticated", "unauthorized", "401"]),
        f"Expected auth error for anonymous pull, got: {exc_info.value}"
    )
    logger.info(f"Anonymous pull correctly denied: {exc_info.value}")
