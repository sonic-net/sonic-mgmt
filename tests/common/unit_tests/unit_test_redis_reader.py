"""Check ordinary-user transport selection without testbed fixtures."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

spec = importlib.util.spec_from_file_location("redis_reader", Path(__file__).resolve().parents[1] / "helpers/redis_reader.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


@pytest.mark.parametrize("port,expected", [(0, "sonic-db-cli -s"), (6379, "sonic-db-cli")])
@pytest.mark.parametrize("bmp_port", [0, 6400])
def test_database_instance_owns_reader_transport(port, expected, bmp_port):
    metadata = {"INSTANCES": {"redis": {"port": port, "unix_socket_path": "/primary.sock"},
                              "redis_bmp": {"port": bmp_port, "unix_socket_path": "/bmp.sock"}},
                "DATABASES": {"CONFIG_DB": {"instance": "redis"}, "BMP_STATE_DB": {"instance": "redis_bmp"}}}
    def command(**kwargs):
        assert kwargs == {"argv": ["cat", "/var/run/redis/sonic-db/database_config.json"]}
        return {"stdout": json.dumps(metadata)}
    assert reader.redis_reader_cli(SimpleNamespace(command=command), "CONFIG_DB") == expected


def test_missing_socket_with_tcp_disabled_fails():
    metadata = {"INSTANCES": {"redis": {"port": 0}}, "DATABASES": {"CONFIG_DB": {"instance": "redis"}}}
    host = SimpleNamespace(command=lambda **kw: {"stdout": json.dumps(metadata)})
    with pytest.raises(ValueError, match="Unix socket"):
        reader.redis_reader_cli(host, "CONFIG_DB")
