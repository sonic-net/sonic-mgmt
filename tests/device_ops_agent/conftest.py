import json
import pytest
import logging
import os
import time

logger = logging.getLogger(__name__)

GEN_CERT_SCRIPT = os.path.join(
    os.path.dirname(__file__), "scripts", "gen-server-cert.sh"
)
REMOTE_SCRIPT_PATH = "/tmp/gen-server-cert.sh"
CONTAINER_NAME = "device-ops-agent"

# mTLS cert paths on the DUT (written by gen-server-cert.sh / SONiC PKI)
CA_CRT = "/etc/sonic/telemetry/dsmsroot.cer"
CLIENT_KEY_SRC = "/etc/sonic/telemetry/dsmsroot.key"
CLIENT_KEY_TMP = "/tmp/dsmsroot-test.key"

# gRPC target (agent listens on :50050 by default)
AGENT_ADDR = "127.0.0.1:50050"

# Image server settings
IMAGE_SERVER_PORT = 8199
IMAGE_VERSION = "202505.01"
IMAGE_MAJOR = IMAGE_VERSION.split(".")[0]
IMAGE_SERVE_ROOT = "/tmp/doa-test-server"
IMAGE_REL_PATH = "networkfirmware/SONiC-{}/sonic-mellanox-{}.bin".format(
    IMAGE_MAJOR, IMAGE_VERSION
)
FAKE_IMAGE_SIZE_KB = 256


def pytest_addoption(parser):
    parser.addoption(
        "--device-ops-agent-image",
        action="store",
        default=None,
        help="Full image URL for device-ops-agent"
    )


# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def generate_device_ops_agent_certs(
    duthosts, enum_rand_one_per_hwsku_hostname
):
    """Generate TLS certs for device-ops-agent on the DUT.

    Copies gen-server-cert.sh to the DUT and runs it to mint a fresh
    server certificate signed by the on-disk dsmsroot CA. Certs are
    written to /etc/sonic/telemetry which is already bind-mounted into
    the container.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    logger.info("Copying gen-server-cert.sh to DUT")
    duthost.copy(src=GEN_CERT_SCRIPT, dest=REMOTE_SCRIPT_PATH, mode="0755")

    logger.info("Running gen-server-cert.sh on DUT")
    cert_result = duthost.shell(
        "sudo bash {}".format(REMOTE_SCRIPT_PATH),
        module_ignore_errors=True,
    )
    if cert_result.get("rc", 1) != 0:
        pytest.fail(
            "gen-server-cert.sh failed: {}".format(
                cert_result.get("stderr", "")
            )
        )
    logger.info("Certs generated: %s", cert_result.get("stdout", ""))

    yield


@pytest.fixture(scope="module", autouse=True)
def prepare_grpcurl_client_key(
    duthosts, enum_rand_one_per_hwsku_hostname,
    generate_device_ops_agent_certs,
):
    """Make the dsmsroot client key readable for grpcurl.

    dsmsroot.key is 0600 root:root. Copy to a temp path so grpcurl can
    read it without root.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell(
        "sudo cp {src} {dst} && sudo chmod 0644 {dst}".format(
            src=CLIENT_KEY_SRC, dst=CLIENT_KEY_TMP
        )
    )
    yield
    duthost.shell(
        "rm -f {}".format(CLIENT_KEY_TMP), module_ignore_errors=True
    )


@pytest.fixture(scope="module")
def check_grpcurl(duthosts, enum_rand_one_per_hwsku_hostname):
    """Skip all tests if grpcurl is not installed on the DUT."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("which grpcurl", module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        pytest.skip("grpcurl not installed on DUT")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def grpcurl(duthost, method, data=None):
    """Call a gRPC method on the device-ops-agent via mTLS.

    Returns the parsed JSON response dict on success.
    Raises AssertionError on gRPC failure.
    """
    result = grpcurl_raw(duthost, method, data)
    assert result["rc"] == 0, (
        "grpcurl {} failed (rc={}): {}".format(
            method, result["rc"],
            result.get("stderr", result.get("stdout", "")),
        )
    )
    stdout = result["stdout"].strip()
    if not stdout or stdout == "{}":
        return {}
    return json.loads(stdout)


def grpcurl_raw(duthost, method, data=None):
    """Call a gRPC method and return the raw shell result dict."""
    cmd = (
        "grpcurl"
        " -cacert {ca}"
        " -cert {cert}"
        " -key {key}"
    ).format(ca=CA_CRT, cert=CA_CRT, key=CLIENT_KEY_TMP)
    if data is not None:
        escaped = json.dumps(data).replace("'", "'\\''")
        cmd += " -d '{}'".format(escaped)
    cmd += " {} sonic.deviceops.v1.DeviceOps/{}".format(AGENT_ADDR, method)
    return duthost.shell(cmd, module_ignore_errors=True)


def poll_preload_status(duthost, target_states=None, timeout=120, interval=3):
    """Poll GetPreloadImageStatus until a terminal state is reached.

    Returns parsed OperationStatus JSON dict.
    Raises TimeoutError if deadline is exceeded.
    """
    if target_states is None:
        target_states = {"SUCCEEDED", "FAILED"}
    deadline = time.time() + timeout
    last_status = {}
    while time.time() < deadline:
        result = grpcurl_raw(duthost, "GetPreloadImageStatus", {})
        if result["rc"] == 0 and result["stdout"].strip():
            last_status = json.loads(result["stdout"])
            state = last_status.get("state", "")
            if state in target_states:
                return last_status
        time.sleep(interval)
    raise TimeoutError(
        "Preload status did not reach {} within {}s. Last: {}".format(
            target_states, timeout, last_status
        )
    )


def wait_for_no_inflight(duthost, timeout=120, interval=3):
    """Wait until no preload operation is in-flight (RUNNING/PENDING)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = grpcurl_raw(duthost, "GetPreloadImageStatus", {})
        if result["rc"] == 0:
            stdout = result["stdout"].strip()
            if not stdout or stdout == "{}":
                return
            status = json.loads(stdout)
            state = status.get("state", "")
            if state not in ("RUNNING", "PENDING"):
                return
        time.sleep(interval)
    raise TimeoutError(
        "Preload still in-flight after {}s".format(timeout)
    )


# ---------------------------------------------------------------------------
# Image server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def image_server(duthosts, enum_rand_one_per_hwsku_hostname):
    """Start a temporary HTTP image server on the DUT.

    Serves a fake SONiC image at the URL path the preload workflow
    expects:  /networkfirmware/SONiC-<MAJOR>/sonic-mellanox-<VERSION>.bin

    Yields a dict with server metadata (port, version, sha256, pid).
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    target_dir = "{}/{}".format(
        IMAGE_SERVE_ROOT,
        os.path.dirname(IMAGE_REL_PATH),
    )
    target_file = "{}/{}".format(IMAGE_SERVE_ROOT, IMAGE_REL_PATH)

    # Create directory structure mirroring ANM repo layout
    duthost.shell("mkdir -p {}".format(target_dir))

    # Create a deterministic fake image
    duthost.shell(
        "head -c {size} < /dev/urandom > {path}".format(
            size=FAKE_IMAGE_SIZE_KB * 1024, path=target_file
        )
    )

    # Record sha256 for later verification
    sha_result = duthost.shell("sha256sum {}".format(target_file))
    sha256 = sha_result["stdout"].strip().split()[0]
    logger.info("Fake image sha256: %s", sha256)

    # Check port is free
    port_check = duthost.shell(
        "ss -lnt sport = :{} | tail -n +2".format(IMAGE_SERVER_PORT),
        module_ignore_errors=True,
    )
    if port_check.get("stdout", "").strip():
        pytest.fail(
            "Port {} already in use on DUT: {}".format(
                IMAGE_SERVER_PORT, port_check["stdout"]
            )
        )

    # Start HTTP server in background
    duthost.shell(
        "cd {root} && nohup python3 -m http.server"
        " --bind 0.0.0.0 {port}"
        " > /tmp/doa-test-httpd.log 2>&1 &"
        " echo $!".format(root=IMAGE_SERVE_ROOT, port=IMAGE_SERVER_PORT)
    )
    time.sleep(2)

    # Grab the PID
    pid_result = duthost.shell(
        "lsof -ti :{} || true".format(IMAGE_SERVER_PORT),
        module_ignore_errors=True,
    )
    pid = pid_result["stdout"].strip().split("\n")[0] if pid_result["stdout"].strip() else ""
    logger.info("Image server started: port=%s, pid=%s", IMAGE_SERVER_PORT, pid)

    # Sanity: verify the server responds
    curl_check = duthost.shell(
        "curl -sf -o /dev/null http://127.0.0.1:{}/{}".format(
            IMAGE_SERVER_PORT, IMAGE_REL_PATH
        ),
        module_ignore_errors=True,
    )
    if curl_check.get("rc", 1) != 0:
        pytest.fail(
            "Image server not responding at http://127.0.0.1:{}/{}".format(
                IMAGE_SERVER_PORT, IMAGE_REL_PATH
            )
        )

    yield {
        "port": IMAGE_SERVER_PORT,
        "version": IMAGE_VERSION,
        "sha256": sha256,
        "pid": pid,
        "image_server_ip": "127.0.0.1:{}".format(IMAGE_SERVER_PORT),
    }

    # Teardown: kill server, clean up files
    if pid:
        duthost.shell(
            "kill {} 2>/dev/null || true".format(pid),
            module_ignore_errors=True,
        )
    duthost.shell(
        "rm -rf {} /tmp/doa-test-httpd.log".format(IMAGE_SERVE_ROOT),
        module_ignore_errors=True,
    )


@pytest.fixture(scope="function")
def clean_preload_state(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure no preload operation is in-flight before starting a test."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    wait_for_no_inflight(duthost, timeout=180)
    yield
    # Clean up downloaded file after each test
    duthost.shell(
        "sudo rm -f /tmp/sonic-mellanox-*.bin",
        module_ignore_errors=True,
    )
