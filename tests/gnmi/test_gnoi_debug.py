"""OpenConfig Debug transport boundary; SONiC Debug is a different service."""

import base64
from pathlib import Path

import pytest

from tests.common.dut_grpc import DutGrpc
from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    _ensure_grpcurl_on_dut,
    gnmi_tls,
)
from tests.common.ptf_grpc import PtfGrpcError

pytestmark = [pytest.mark.topology("any")]


@pytest.mark.parametrize("transport", ["tls", "uds"])
def test_gnoi_debug_transport(gnmi_tls, ptfhost, transport):  # noqa: F811
    """Requires #813, a v1 policy enabling uptime, and the host executor.

    gnmi_tls is the sole configuration owner for both cases. Missing required
    image/socket/policy support fails rather than silently skipping coverage.
    """
    if transport == "tls":
        host, client = ptfhost, gnmi_tls.grpc
    else:
        host = gnmi_tls.duthost
        _ensure_grpcurl_on_dut(host)
        assert host.shell("test -S /var/run/gnmi/gnmi.sock", module_ignore_errors=True)["rc"] == 0
        client = DutGrpc(host)
    client.configure_max_time(30)
    proto_path = host.tempfile(state="file", suffix=".proto", prefix="gnoi-debug-")["path"]
    try:
        host.copy(src=str(Path(__file__).parent / "files" / "debug.proto"), dest=proto_path)
        request = {"mode": "MODE_CLI", "command": base64.b64encode(b"uptime").decode()}
        if transport == "tls":
            with pytest.raises(PtfGrpcError, match=r"\bCode: Unimplemented\b") as error:
                client.call_server_streaming("gnoi.debug.Debug", "Debug", request, proto_file=proto_path)
            assert "unknown service gnoi.debug.Debug" in str(error.value)
            return
        messages = client.call_server_streaming("gnoi.debug.Debug", "Debug", request, proto_file=proto_path)
        assert messages[0]["request"]["command"] == request["command"]
        assert all("data" in message for message in messages[1:-1])
        output = b"".join(base64.b64decode(message["data"]) for message in messages[1:-1])
        assert output, "uptime returned no diagnostic output"
        assert int(messages[-1]["status"].get("code", 0)) == 0
    finally:
        host.file(path=proto_path, state="absent")
