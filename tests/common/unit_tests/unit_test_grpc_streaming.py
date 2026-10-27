"""Offline regressions: pytest --noconftest --confcutdir=tests/common/unit_tests <file>."""

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def load_adapter(filename):
    # Avoid tests.common's Ansible imports; execute the actual adapter source.
    path = Path(__file__).resolve().parents[1] / filename
    tree = ast.parse(path.read_text())
    tree.body = [node for node in tree.body if not (
        isinstance(node, ast.ImportFrom) and node.module == "tests.common.grpc_config"
    )]
    namespace = {}
    exec(compile(tree, str(path), "exec"), namespace)
    return SimpleNamespace(**namespace)


@pytest.fixture(params=["ptf", "dut"])
def adapter(request):
    host = Mock()
    result = {"rc": 0, "stdout": '{\n "data": "eA=="\n}\n{\n "status": {}\n}\n', "stderr": ""}
    host.command.return_value = result
    host.shell.return_value = result
    if request.param == "ptf":
        module = load_adapter("ptf_grpc.py")
        client = module.PtfGrpc(host, "127.0.0.1:8080", plaintext=True)
        error = module.PtfGrpcError
    else:
        module = load_adapter("dut_grpc.py")
        client = module.DutGrpc(host)
        error = module.DutGrpcError
    return request.param, host, client, result, error


def test_stream_request_metadata_and_multiline_json(adapter):
    kind, host, client, _, _ = adapter
    client.configure_max_time(30)
    messages = client.call_server_streaming(
        "gnoi.debug.Debug", "Debug", {"command": "eA=="},
        metadata={"test-header": "value"}, proto_file="/tmp/debug.proto",
    )
    assert messages == [{"data": "eA=="}, {"status": {}}]
    if kind == "ptf":
        args = host.command.call_args.kwargs
        argv = args["argv"]
        assert argv[argv.index("-d") + 1] == "@"
        assert float(argv[argv.index("-max-time") + 1]) == 30
        assert args["stdin"] == '{"command": "eA=="}'
        assert argv[argv.index("-H") + 1] == "test-header: value"
        assert argv[argv.index("-proto") + 1] == "debug.proto"
        assert argv[argv.index("-import-path") + 1] == "/tmp"
        assert argv[-1] == "gnoi.debug.Debug/Debug"
    else:
        command = host.shell.call_args.args[0]
        assert "-H 'test-header: value'" in command
        assert "-max-time 30.0" in command
        assert "-import-path /tmp -proto debug.proto" in command
        assert "-d '{\"command\": \"eA==\"}'" in command


@pytest.mark.parametrize("output", ["", '{"data": "eA=="}\n{broken'])
def test_incomplete_stream_is_not_silently_accepted(adapter, output):
    _, _, client, result, error = adapter
    result["stdout"] = output
    with pytest.raises(error):
        client.call_server_streaming("gnoi.debug.Debug", "Debug")


def test_final_error_is_not_converted_to_stream_success(adapter):
    _, _, client, result, error = adapter
    result.update(rc=7, stderr="ERROR:\n  Code: PermissionDenied\n  Message: denied")
    with pytest.raises(error, match="Code: PermissionDenied"):
        client.call_server_streaming("gnoi.debug.Debug", "Debug")
    # Deliberately no assertion of zero messages: stdout already contains data.
