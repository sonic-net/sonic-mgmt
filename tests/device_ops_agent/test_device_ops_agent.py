import pytest
import logging
import time
from tests.common.helpers.assertions import pytest_assert
from tests.device_ops_agent.conftest import (
    CONTAINER_NAME,
    grpcurl,
    grpcurl_raw,
    poll_preload_status,
    CA_CRT,
    CLIENT_KEY_TMP,
    AGENT_ADDR,
)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Basic health checks
# ---------------------------------------------------------------------------

def test_container_running(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify device-ops-agent container is running."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    output = duthost.shell(
        "docker ps --filter name={} --filter status=running -q".format(CONTAINER_NAME),
        module_ignore_errors=True,
    )
    pytest_assert(
        "stdout" in output,
        "shell command failed: {}".format(output.get("msg", "unknown error")),
    )
    pytest_assert(
        output["stdout"].strip() != "",
        "{} container is not running".format(CONTAINER_NAME),
    )


def test_supervisord_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify all supervisord processes are running."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    output = duthost.shell(
        "docker exec {} supervisorctl status".format(CONTAINER_NAME),
        module_ignore_errors=True,
    )
    pytest_assert(
        "stdout" in output,
        "shell command failed: {}".format(output.get("msg", "unknown error")),
    )
    pytest_assert(output["rc"] == 0, "supervisorctl status command failed")
    stdout = output["stdout"]
    logger.info("supervisorctl status output: {}".format(stdout))
    for line in stdout.splitlines():
        pytest_assert("FATAL" not in line, "Process in FATAL state: {}".format(line))
        pytest_assert("EXITED" not in line, "Process in EXITED state: {}".format(line))


def test_agent_process_running(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify device-ops-agent process is running inside the container."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    output = duthost.shell(
        "docker exec {} pgrep -f device-ops-agent".format(CONTAINER_NAME),
        module_ignore_errors=True,
    )
    pytest_assert(
        "stdout" in output,
        "shell command failed: {}".format(output.get("msg", "unknown error")),
    )
    pytest_assert(
        output["rc"] == 0,
        "device-ops-agent process is not running in the container",
    )
    pytest_assert(
        output["stdout"].strip() != "",
        "No PID found for device-ops-agent process",
    )


# ---------------------------------------------------------------------------
# gRPC connectivity
# ---------------------------------------------------------------------------

def test_grpc_reflection(
    duthosts, enum_rand_one_per_hwsku_hostname, check_grpcurl,
):
    """Verify gRPC reflection lists the DeviceOps service."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell(
        "grpcurl -cacert {ca} -cert {cert} -key {key} {addr} list".format(
            ca=CA_CRT, cert=CA_CRT, key=CLIENT_KEY_TMP, addr=AGENT_ADDR,
        ),
        module_ignore_errors=True,
    )
    pytest_assert(
        result["rc"] == 0,
        "gRPC reflection failed: {}".format(result.get("stderr", "")),
    )
    pytest_assert(
        "sonic.deviceops.v1.DeviceOps" in result["stdout"],
        "DeviceOps service not found in reflection output: {}".format(result["stdout"]),
    )


# ---------------------------------------------------------------------------
# Preload API — input validation (immediate gRPC errors)
# ---------------------------------------------------------------------------

def test_preload_missing_image_version(
    duthosts, enum_rand_one_per_hwsku_hostname,
    check_grpcurl, clean_preload_state,
):
    """TriggerPreloadImage with empty image_version returns InvalidArgument."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = grpcurl_raw(duthost, "TriggerPreloadImage", {
        "image_server_ips": ["10.0.0.1:8000"],
        "image_version": "",
    })
    pytest_assert(
        result["rc"] != 0,
        "Expected gRPC error for empty image_version but got rc=0",
    )
    output = result.get("stderr", "") + result.get("stdout", "")
    pytest_assert(
        "InvalidArgument" in output or "image_version required" in output,
        "Expected InvalidArgument error, got: {}".format(output),
    )


def test_preload_missing_server_ips(
    duthosts, enum_rand_one_per_hwsku_hostname,
    check_grpcurl, clean_preload_state,
):
    """TriggerPreloadImage with no image_server_ips returns InvalidArgument."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = grpcurl_raw(duthost, "TriggerPreloadImage", {
        "image_server_ips": [],
        "image_version": "202505.01",
    })
    pytest_assert(
        result["rc"] != 0,
        "Expected gRPC error for empty image_server_ips but got rc=0",
    )
    output = result.get("stderr", "") + result.get("stdout", "")
    pytest_assert(
        "InvalidArgument" in output or "image_server_ips required" in output,
        "Expected InvalidArgument error, got: {}".format(output),
    )


# ---------------------------------------------------------------------------
# Preload API — success path (requires image server fixture)
# ---------------------------------------------------------------------------

def test_preload_image_success(
    duthosts, enum_rand_one_per_hwsku_hostname,
    check_grpcurl, image_server, clean_preload_state,
):
    """Trigger preload, poll until SUCCEEDED, verify downloaded image sha256."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logger.info(
        "Triggering preload: version=%s server=%s",
        image_server["version"], image_server["image_server_ip"],
    )
    resp = grpcurl(duthost, "TriggerPreloadImage", {
        "image_server_ips": [image_server["image_server_ip"]],
        "image_version": image_server["version"],
    })
    logger.info("TriggerPreloadImage response: %s", resp)

    # Poll until terminal state
    status = poll_preload_status(duthost, timeout=120, interval=3)
    logger.info("Final preload status: %s", status)
    pytest_assert(
        status.get("state") == "SUCCEEDED",
        "Expected SUCCEEDED but got: {}".format(status),
    )

    # Verify the downloaded file exists and matches the served image
    expected_file = "/tmp/sonic-mellanox-{}.bin".format(image_server["version"])
    sha_result = duthost.shell(
        "sudo sha256sum {}".format(expected_file),
        module_ignore_errors=True,
    )
    pytest_assert(
        sha_result.get("rc") == 0,
        "Downloaded file not found at {}: {}".format(
            expected_file, sha_result.get("stderr", ""),
        ),
    )
    actual_sha = sha_result["stdout"].strip().split()[0]
    pytest_assert(
        actual_sha == image_server["sha256"],
        "sha256 mismatch: expected={} actual={}".format(
            image_server["sha256"], actual_sha,
        ),
    )
    logger.info("Image verified: sha256=%s", actual_sha)


def test_preload_status_after_success(
    duthosts, enum_rand_one_per_hwsku_hostname, check_grpcurl,
):
    """GetPreloadImageStatus returns a terminal state after a completed preload.

    Runs after test_preload_image_success to verify the status store
    retains the last result.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    status = grpcurl(duthost, "GetPreloadImageStatus", {})
    state = status.get("state", "")
    pytest_assert(
        state in ("SUCCEEDED", "FAILED"),
        "Expected terminal state in status store, got: {}".format(status),
    )


# ---------------------------------------------------------------------------
# Preload API — failure paths
# ---------------------------------------------------------------------------

def test_preload_image_unreachable_server(
    duthosts, enum_rand_one_per_hwsku_hostname,
    check_grpcurl, clean_preload_state,
):
    """Preload with an unreachable image server should reach FAILED state."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737), guaranteed not routable
    resp = grpcurl(duthost, "TriggerPreloadImage", {
        "image_server_ips": ["192.0.2.1:9999"],
        "image_version": "202505.99",
    })
    logger.info("TriggerPreloadImage (unreachable) response: %s", resp)

    # Poll — expect FAILED (gNOI TransferToRemote will timeout/fail)
    status = poll_preload_status(duthost, timeout=180, interval=5)
    logger.info("Unreachable server preload status: %s", status)
    pytest_assert(
        status.get("state") == "FAILED",
        "Expected FAILED for unreachable server, got: {}".format(status),
    )


def test_preload_duplicate_request(
    duthosts, enum_rand_one_per_hwsku_hostname,
    check_grpcurl, clean_preload_state,
):
    """A second TriggerPreloadImage while one is in-flight returns AlreadyExists."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Trigger a preload that will stay in-flight (unreachable server)
    resp = grpcurl(duthost, "TriggerPreloadImage", {
        "image_server_ips": ["192.0.2.1:9999"],
        "image_version": "202505.98",
    })
    logger.info("First trigger (slow): %s", resp)

    # Give the background goroutine a moment to start
    time.sleep(2)

    # Second trigger should fail with AlreadyExists
    result = grpcurl_raw(duthost, "TriggerPreloadImage", {
        "image_server_ips": ["192.0.2.1:9999"],
        "image_version": "202505.98",
    })
    output = result.get("stderr", "") + result.get("stdout", "")
    logger.info("Second trigger result: rc=%s output=%s", result["rc"], output)
    pytest_assert(
        result["rc"] != 0,
        "Expected gRPC error for duplicate request but got rc=0",
    )
    pytest_assert(
        "AlreadyExists" in output or "in flight" in output,
        "Expected AlreadyExists error, got: {}".format(output),
    )

    # Wait for the first operation to finish so we don't leak state
    poll_preload_status(duthost, timeout=180, interval=5)
