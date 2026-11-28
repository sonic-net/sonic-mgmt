"""Healthz artifact read authorization, without triggering diagnostic collection."""

import base64
import hashlib
import logging

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.ptf_grpc import PtfGrpcError
from tests.gnmi.helper import set_gnoi_client_role

pytestmark = [pytest.mark.topology("any")]
logger = logging.getLogger(__name__)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize(
    "role,allowed",
    [
        pytest.param("gnoi_readonly", True, id="readonly"),
        pytest.param("gnoi_noaccess", False, id="noaccess"),
    ],
)
def test_gnoi_artifact_read_authorization(gnmi_tls, role, allowed):  # noqa: F811
    """Requires #814 and #807; use only a test-owned artifact on the host."""
    dut = gnmi_tls.duthost
    gnmi_tls.grpc.configure_max_time(30)
    # Artifact maps this host path to /mnt/host/tmp/dump inside the container.
    # mkdir without -p atomically records whether this test created the directory.
    created_directory = dut.command("mkdir -m 0755 /tmp/dump", module_ignore_errors=True)["rc"] == 0
    path = None
    content = b"gNOI synthetic diagnostic artifact\n"
    try:
        assert dut.stat(path="/tmp/dump")["stat"].get("isdir"), "Cannot prepare Healthz artifact directory"
        path = dut.tempfile(state="file", path="/tmp/dump", prefix="gnoi-auth-")["path"]
        dut.copy(content=content.decode(), dest=path, mode="0644")
        set_gnoi_client_role(gnmi_tls, role)
        if not allowed:
            # Final status only: the existing wrapper cannot prove absence of partial data.
            with pytest.raises(PtfGrpcError, match=r"\bCode: PermissionDenied\b"):
                gnmi_tls.grpc.call_server_streaming("gnoi.healthz.Healthz", "Artifact", {"id": path})
            return
        messages = gnmi_tls.grpc.call_server_streaming("gnoi.healthz.Healthz", "Artifact", {"id": path})
        header = messages[0]["header"]
        assert header["id"] == path
        assert int(header["file"]["size"]) == len(content)
        assert header["file"]["hash"]["method"] == "SHA256"
        assert base64.b64decode(header["file"]["hash"]["hash"]) == hashlib.sha256(content).digest()
        assert all("bytes" in message for message in messages[1:-1])
        assert b"".join(base64.b64decode(message["bytes"]) for message in messages[1:-1]) == content
        assert "trailer" in messages[-1]
    finally:
        try:
            if path is not None:
                dut.file(path=path, state="absent")
        finally:
            if created_directory:
                # Never recursively remove a shared artifact directory. Another
                # collector may have populated it while this test was running.
                result = dut.command("rmdir /tmp/dump", module_ignore_errors=True)
                if result["rc"] != 0:
                    logger.warning("Preserved /tmp/dump: rmdir failed: %s", result.get("stderr", ""))
