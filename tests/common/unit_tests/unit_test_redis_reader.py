"""Check ordinary-user transport selection without testbed fixtures."""
import importlib.util
from pathlib import Path
import pytest

path = Path(__file__).resolve().parents[1] / "helpers/redis_reader.py"
spec = importlib.util.spec_from_file_location("redis_reader", path)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


@pytest.mark.parametrize('use_tcp, expected', [(True, 'sonic-db-cli'), (False, 'sonic-db-cli -s')])
def test_ordinary_reader_uses_scenario_transport(use_tcp, expected):
    assert reader.redis_reader_cli(use_tcp=use_tcp) == expected
