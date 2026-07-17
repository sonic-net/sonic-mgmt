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
 * Registry: by default the tests are fully self-contained -- the
 * oras_registry fixture starts a minimal pull-only OCI registry
 * (gnmi/oras/registry_server.py, TLS + basic auth) on the PTF host,
 * pre-loads it with a single-layer OCI artifact, and installs the
 * CA into the DUT gnmi container trust store so the gNOI server can
 * verify the registry certificate. The DUT reaches the registry at
 * the PTF management IP (works on both virtual and physical
 * testbeds; no internet/DNS/default route required).
 *
 * To test against an external registry instead (tests/gnmi/conftest.py):
 *   --oras_test_registry     e.g. "myregistry.azurecr.io" (enables external mode)
 *   --oras_test_repository   repository/image name
 *   --oras_test_tag          tag to pull
 *   --oras_test_username     registry username
 * The password is never hardcoded or passed on the CLI -- it is resolved
 * from the Ansible-managed (vaulted) secrets for the testbed via
 * creds_on_dut() ('oras_registry_password'). External-mode tests skip if
 * it isn't configured.
 *
 * Prerequisites:
 *   - DUT must be running a sonic-gnmi build that includes the Oras
 *     service (PR #692 or later).
"""

import hashlib
import json
import logging
import os
import shutil
import tempfile

import pytest
import requests

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import creds_on_dut
from tests.common.cert_utils import TlsCertificateGenerator
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

# Where to store the pulled artifact on the DUT
ORAS_LOCAL_PATH = "/tmp/oras_test_image.bin"

# Local registry (hermetic mode) settings -- served from the PTF host
LOCAL_REGISTRY_PORT = 15000
PTF_REGISTRY_DIR = "/root/oras_registry"          # data dir on the PTF host
PTF_REGISTRY_SCRIPT = "/root/oras_registry_server.py"
LOCAL_REPOSITORY = "sonic-oras-test"
LOCAL_TAG = "sonic-oras-test-artifact"
LOCAL_USERNAME = "orastest"
# Local-only credential for the throwaway per-run registry; not a secret.
LOCAL_PASSWORD = "orastest-Secret-1"
LOCAL_PAYLOAD_SIZE = 1024 * 1024  # 1 MiB single-layer artifact


# ---------------------------------------------------------------------------
# Local registry helpers
# ---------------------------------------------------------------------------


def _write_artifact_files(workdir, payload, tag):
    """
     * Write the files for a single-layer OCI artifact (config blob + one
     * layer + manifest) in the layout registry_server.py serves from:
     *   blobs/<digest>   and   manifests/<tag>
     * Returns the layer digest.
    """
    blobs_dir = os.path.join(workdir, "blobs")
    manifests_dir = os.path.join(workdir, "manifests")
    os.makedirs(blobs_dir)
    os.makedirs(manifests_dir)

    # Content-addressable IDs: blobs are stored/fetched by their sha256
    layer_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    config_blob = b"{}"  # minimal empty-JSON config (OCI manifests require one)
    config_digest = "sha256:" + hashlib.sha256(config_blob).hexdigest()
    for data, digest in ((payload, layer_digest), (config_blob, config_digest)):
        with open(os.path.join(blobs_dir, digest), "wb") as f:
            f.write(data)

    # The manifest ties config + layer together and is looked up by tag
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_blob),
        },
        "layers": [
            {
                "mediaType": "application/octet-stream",
                "digest": layer_digest,
                "size": len(payload),
                "annotations": {"org.opencontainers.image.title": tag},
            }
        ],
    }
    manifest_bytes = json.dumps(manifest).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    # oras clients resolve the tag first, then fetch the manifest again by
    # its digest -- so serve the same bytes under both names
    for name in (tag, manifest_digest):
        with open(os.path.join(manifests_dir, name), "wb") as f:
            f.write(manifest_bytes)
    return layer_digest


def _find_gnmi_container(duthost):
    """Return the name of the gNMI/telemetry container on the DUT."""
    # NF-based awk instead of --format '{{.Names}}': double braces would be
    # eaten by Ansible's Jinja2 templating of module args.
    names = duthost.shell("docker ps | awk 'NR>1 {print $NF}'")["stdout_lines"]
    container = next((c for c in ("gnmi", "telemetry") if c in names), None)
    if container is None:
        pytest.skip("No gnmi/telemetry container running on DUT")
    return container


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def oras_registry(request, duthosts, rand_one_dut_hostname, ptfhost):
    """
     * Provide registry connection info for the ORAS pull tests.
     *
     * External mode (--oras_test_registry passed on the CLI): registry/
     * repository/tag/username come from CLI options (tests/gnmi/conftest.py),
     * password from the Ansible-managed (vaulted) secrets for the testbed
     * via creds_on_dut() ('oras_registry_password'). No setup is performed.
     *
     * Local mode (default -- no CLI options needed): run a minimal
     * pull-only OCI registry (gnmi/oras/registry_server.py, TLS + basic
     * auth) on the PTF host, pre-loaded with a 1 MiB single-layer
     * artifact, and trust the CA inside the DUT gnmi container. The DUT
     * reaches it at the PTF management IP, which works on virtual and
     * physical testbeds alike. Torn down completely at module end.
     *
     * Yields a dict:
     *   registry, repository, tag, username, password,
     *   expected_layer_digest (local mode only), expected_size (local only)
    """
    external_registry = (request.config.getoption("--oras_test_registry", default=None) or "").strip()
    if external_registry:
        duthost = duthosts[rand_one_dut_hostname]
        creds = creds_on_dut(duthost)
        repository = (request.config.getoption("--oras_test_repository", default=None) or "").strip()
        tag = (request.config.getoption("--oras_test_tag", default=None) or "").strip()
        username = (request.config.getoption("--oras_test_username", default=None) or "").strip()
        password = (creds.get("oras_registry_password") or "").strip()
        logger.info("Using external registry %s", external_registry)
        yield {
            "registry": external_registry,
            "repository": repository,
            "tag": tag,
            "username": username,
            "password": password,
            "external": True,
        }
        return

    duthost = duthosts[rand_one_dut_hostname]
    ptf_ip = ptfhost.mgmt_ip
    if not ptf_ip:
        pytest.skip("PTF host has no IPv4 management address -- cannot host local registry")
    registry = "{}:{}".format(ptf_ip, LOCAL_REGISTRY_PORT)
    base_url = "https://{}".format(registry)
    gnmi_container = _find_gnmi_container(duthost)

    workdir = tempfile.mkdtemp(prefix="oras_registry_")
    ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
    try:
        # -- TLS certs: CA + server cert with the PTF IP in the SAN --------
        cert_gen = TlsCertificateGenerator(server_ip=ptf_ip)
        cert_gen.write_all(workdir)
        ca_file = os.path.join(workdir, "ca.crt")

        # -- Build the test artifact locally --------------------------------
        # Random 1 MiB payload => unique digest per run, no stale-cache hits
        payload = os.urandom(LOCAL_PAYLOAD_SIZE)
        layer_digest = _write_artifact_files(workdir, payload, LOCAL_TAG)

        # -- Deploy artifact + certs + server script to the PTF host --------
        logger.info("Starting local ORAS registry at %s on PTF %s", registry, ptfhost.hostname)
        ptfhost.shell("pkill -9 -f {}".format(PTF_REGISTRY_SCRIPT),
                      module_ignore_errors=True)
        ptfhost.shell("rm -rf {dir} && mkdir -p {dir}".format(dir=PTF_REGISTRY_DIR))
        # Copying a directory (no trailing slash) copies it recursively
        for name in ("blobs", "manifests", "server.crt", "server.key"):
            ptfhost.copy(src=os.path.join(workdir, name),
                         dest="{}/".format(PTF_REGISTRY_DIR))
        ptfhost.copy(src="gnmi/oras/registry_server.py", dest=PTF_REGISTRY_SCRIPT)

        # -- Start the registry server (same interpreter the gNMI CRL -------
        #    server on the PTF already relies on)
        ptfhost.shell(
            "nohup /root/env-python3/bin/python {script} "
            "--port {port} --dir {dir} --username {user} --password {pw} "
            "> {dir}/server.log 2>&1 &".format(
                script=PTF_REGISTRY_SCRIPT, port=LOCAL_REGISTRY_PORT,
                dir=PTF_REGISTRY_DIR, user=LOCAL_USERNAME, pw=LOCAL_PASSWORD)
        )

        def _registry_up():
            try:
                # 200 = serving, 401 = serving but wants auth -- both mean "up"
                code = requests.get("{}/v2/".format(base_url),
                                    verify=ca_file, timeout=5).status_code
                return code in (200, 401)
            except Exception:
                return False

        pytest_assert(wait_until(60, 2, 0, _registry_up),
                      "Local registry did not become ready at {}".format(base_url))
        logger.info("Serving test artifact %s/%s:%s layer=%s size=%d",
                    registry, LOCAL_REPOSITORY, LOCAL_TAG,
                    layer_digest, len(payload))

        # -- Trust the CA inside the DUT gnmi container ----------------------
        #    The gNOI Oras client verifies the registry cert against the
        #    container's system trust store; append our CA (backing up the
        #    original bundle for teardown). Survives gnmi process restarts.
        duthost.copy(src=ca_file, dest="/tmp/oras_test_ca.crt")
        duthost.shell(
            "docker exec {c} sh -c 'cp {b} {b}.oras_bak'".format(
                c=gnmi_container, b=ca_bundle))
        # Stream via stdin: docker cp can't reach tmpfs-backed paths like /tmp
        duthost.shell(
            "docker exec -i {c} sh -c 'cat >> {b}' < /tmp/oras_test_ca.crt".format(
                c=gnmi_container, b=ca_bundle))

        yield {
            "registry": registry,
            "repository": LOCAL_REPOSITORY,
            "tag": LOCAL_TAG,
            "username": LOCAL_USERNAME,
            "password": LOCAL_PASSWORD,
            "expected_layer_digest": layer_digest,
            "expected_size": len(payload),
            "external": False,
        }
    finally:
        # -- Teardown: restore trust store, stop and remove registry ---------
        duthost.shell(
            "docker exec {c} sh -c 'mv {b}.oras_bak {b}'".format(
                c=gnmi_container, b=ca_bundle),
            module_ignore_errors=True)
        duthost.shell("rm -f /tmp/oras_test_ca.crt", module_ignore_errors=True)
        ptfhost.shell("pkill -9 -f {}".format(PTF_REGISTRY_SCRIPT),
                      module_ignore_errors=True)
        ptfhost.shell("rm -rf {} {}".format(PTF_REGISTRY_DIR, PTF_REGISTRY_SCRIPT),
                      module_ignore_errors=True)
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def skip_if_external_and_no_password(cfg):
    """
     * In external-registry mode the tests need a real credential; skip
     * if it wasn't provided. Local mode always has working credentials.
    """
    if cfg.get("external") and not cfg["password"]:
        pytest.skip(
            "External ORAS registry configured but 'oras_registry_password' "
            "is not set in the Ansible secrets for this testbed -- skipping."
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_gnoi_oras_pull_basic_auth(duthosts, rand_one_dut_hostname, oras_registry, gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_basic_auth
     *
     * Verify the Oras.Pull RPC can download an artifact from a registry
     * using basic (username/password) authentication.
     *
     * Steps:
     *   1. Call Oras.Pull with registry, repo, tag, and credentials.
     *   2. Assert we receive a PullStarted message with total_bytes > 0.
     *   3. Assert the final PullResult contains a valid layer digest.
     *   4. Verify the file actually exists on the DUT at local_path.
     *   5. Clean up the downloaded file.
    """
    cfg = oras_registry
    skip_if_external_and_no_password(cfg)

    duthost = duthosts[rand_one_dut_hostname]

    # -- Step 1: Call the Pull RPC ----------------------------------------
    logger.info(
        f"Pulling {cfg['registry']}/{cfg['repository']}:{cfg['tag']} "
        f"-> {ORAS_LOCAL_PATH}"
    )

    # Blocks until the server-side stream finishes; returns the list of
    # streamed messages (started / progress / result) as parsed dicts
    responses = gnmi_tls.gnoi.oras_pull(
        registry=cfg["registry"],
        repository=cfg["repository"],
        local_path=ORAS_LOCAL_PATH,
        tag=cfg["tag"],
        username=cfg["username"],
        password=cfg["password"],
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
        f"Expected layer_digest to start with 'sha256:', got: {layer_digest}"
    )

    # In local mode we know exactly what was pushed -- verify end to end.
    if cfg.get("expected_layer_digest"):
        pytest_assert(
            layer_digest == cfg["expected_layer_digest"],
            f"layer_digest {layer_digest} != pushed digest {cfg['expected_layer_digest']}"
        )
        pytest_assert(
            total_bytes == cfg["expected_size"],
            f"total_bytes {total_bytes} != pushed size {cfg['expected_size']}"
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


def test_gnoi_oras_pull_invalid_path(oras_registry, gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_invalid_path
     *
     * Verify that the Oras.Pull RPC rejects a local_path that is
     * outside the allowed directories (/tmp, /var/tmp, /host).
     *
     * The server should return a FailedPrecondition (or InvalidArgument)
     * gRPC error without downloading anything.
    """
    cfg = oras_registry
    skip_if_external_and_no_password(cfg)

    with pytest.raises(Exception) as exc_info:
        gnmi_tls.gnoi.oras_pull(
            registry=cfg["registry"],
            repository=cfg["repository"],
            local_path="/etc/passwd",  # Not allowed!
            tag=cfg["tag"],
            username=cfg["username"],
            password=cfg["password"],
        )

    # The error should mention permission/precondition/allowlist
    error_msg = str(exc_info.value).lower()
    pytest_assert(
        any(term in error_msg for term in ["precondition", "permission", "allowlist", "invalid"]),
        f"Expected path rejection error, got: {exc_info.value}"
    )
    logger.info(f"Path correctly rejected: {exc_info.value}")


def test_gnoi_oras_pull_bad_credentials(oras_registry, gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_bad_credentials
     *
     * Verify that the Oras.Pull RPC returns Unauthenticated when
     * given wrong credentials.
    """
    cfg = oras_registry

    with pytest.raises(Exception) as exc_info:
        gnmi_tls.gnoi.oras_pull(
            registry=cfg["registry"],
            repository=cfg["repository"],
            local_path=ORAS_LOCAL_PATH,
            tag=cfg["tag"],
            username="wrong_user",
            password="wrong_password",
        )

    error_msg = str(exc_info.value).lower()
    pytest_assert(
        any(term in error_msg for term in ["unauthenticated", "unauthorized", "401"]),
        f"Expected auth error, got: {exc_info.value}"
    )
    logger.info(f"Bad credentials correctly rejected: {exc_info.value}")


def test_gnoi_oras_pull_nonexistent_tag(oras_registry, gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_nonexistent_tag
     *
     * Verify that the Oras.Pull RPC returns an appropriate error
     * when the requested tag does not exist in the registry.
    """
    cfg = oras_registry
    skip_if_external_and_no_password(cfg)

    with pytest.raises(Exception) as exc_info:
        gnmi_tls.gnoi.oras_pull(
            registry=cfg["registry"],
            repository=cfg["repository"],
            local_path=ORAS_LOCAL_PATH,
            tag="this-tag-does-not-exist-12345",
            username=cfg["username"],
            password=cfg["password"],
        )

    error_msg = str(exc_info.value).lower()
    pytest_assert(
        any(term in error_msg for term in ["not found", "notfound", "404", "unavailable", "unknown"]),
        f"Expected not-found error, got: {exc_info.value}"
    )
    logger.info(f"Nonexistent tag correctly rejected: {exc_info.value}")


def test_gnoi_oras_pull_anonymous_denied(oras_registry, gnmi_tls):  # noqa: F811
    """
     * test_gnoi_oras_pull_anonymous_denied
     *
     * Verify that pulling from a private registry without credentials
     * returns an authentication error.
     *
     * The local registry fixture always requires auth; in external mode
     * this assumes the configured registry does too.
    """
    cfg = oras_registry

    with pytest.raises(Exception) as exc_info:
        gnmi_tls.gnoi.oras_pull(
            registry=cfg["registry"],
            repository=cfg["repository"],
            local_path=ORAS_LOCAL_PATH,
            tag=cfg["tag"],
            # No credentials -- anonymous
        )

    # Registries answering with a Bearer challenge (e.g. ACR) yield a 401
    # ("unauthenticated"/"unauthorized"); registries with a Basic realm make
    # oras-go fail client-side with "basic credential not found". Both mean
    # anonymous access was denied.
    error_msg = str(exc_info.value).lower()
    pytest_assert(
        any(term in error_msg for term in
            ["unauthenticated", "unauthorized", "401", "credential not found"]),
        f"Expected auth error for anonymous pull, got: {exc_info.value}"
    )
    logger.info(f"Anonymous pull correctly denied: {exc_info.value}")
