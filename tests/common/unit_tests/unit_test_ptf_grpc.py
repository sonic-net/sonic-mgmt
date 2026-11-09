"""Check grpcurl streaming request forwarding and complete frame parsing.

Run with --noconftest --confcutdir=tests/common/unit_tests to avoid testbed
dependencies, following the other standalone tests in this directory.
"""

import ast
import json
import logging
from pathlib import Path
from unittest.mock import Mock

import pytest


@pytest.fixture
def streaming_client():
    source = Path(__file__).resolve().parents[1] / "ptf_grpc.py"
    tree = ast.parse(source.read_text())
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    namespace = {"json": json, "logger": logging.getLogger(__name__),
                 "List": list, "Dict": dict, "Union": __import__("typing").Union}
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(source), "exec"), namespace)
    ptf = Mock()
    return namespace["PtfGrpc"](ptf, "192.0.2.1:50052", plaintext=True), namespace["PtfGrpcError"]


@pytest.mark.parametrize("formatted", [False, True])
def test_streaming_forwards_request_and_metadata_and_decodes_all_frames(streaming_client, formatted):
    client, _ = streaming_client
    frames = [{"header": {"id": "archive"}}, {"bytes": "cGF5bG9hZA=="}, {"trailer": {}}]
    client.ptfhost.command.return_value = {
        "rc": 0, "stdout": "\n".join(json.dumps(frame, indent=2 if formatted else None) for frame in frames) + "\n \t",
    }
    assert client.call_server_streaming("gnoi.healthz.Healthz", "Artifact", {"id": "archive"},
                                        metadata={"username": "reader"}) == frames
    kwargs = client.ptfhost.command.call_args.kwargs
    assert json.loads(kwargs["argv"][kwargs["argv"].index("-d") + 1]) == {"id": "archive"}
    assert "username: reader" in kwargs["argv"]
    assert "stdin" not in kwargs


@pytest.mark.parametrize("output", ["", '{"header":{}}\n{"bytes":', '{"header":{}}\nnull',
                                      '{"header":{}}\nnot JSON'])
def test_streaming_rejects_empty_truncated_or_non_object_frames(streaming_client, output):
    client, error = streaming_client
    client.ptfhost.command.return_value = {"rc": 0, "stdout": output}
    with pytest.raises(error):
        client.call_server_streaming("gnoi.healthz.Healthz", "Artifact", {"id": "archive"})


def test_streaming_keeps_rpc_failure(streaming_client):
    client, error = streaming_client
    client.ptfhost.command.return_value = {"rc": 1, "stderr": "Code: NotFound\nMessage: missing archive"}
    with pytest.raises(error, match="NotFound"):
        client.call_server_streaming("gnoi.healthz.Healthz", "Artifact", {"id": "archive"})
