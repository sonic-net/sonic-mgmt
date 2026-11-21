"""Check SpyTest Redis commands without testbed fixtures."""

import importlib.util
import json
from pathlib import Path
import shlex
import sys
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def client(monkeypatch):
    class SpyTest:
        mode = "1"
        metadata = ""

        def get_dut_var(self, dut, name):
            return self.mode

        def config(self, dut, command, **kwargs):
            self.command = command
            self.options = kwargs
            return self.metadata if command.startswith("cat ") else command

        def show(self, dut, command, **kwargs):
            return command

        def upload_file_to_dut(self, dut, source, destination):
            self.uploaded = Path(source).read_text()

        def is_dry_run(self):
            return False

        def getenv(self, name, default):
            return default

        def remove_prompt(self, dut, text):
            return text

    spytest = ModuleType("spytest")
    spytest.st = SpyTest()
    utilities = ModuleType("utilities.utils")
    utilities.remove_last_line_from_string = lambda text: text
    monkeypatch.setitem(sys.modules, "spytest", spytest)
    monkeypatch.setitem(sys.modules, "utilities.utils", utilities)
    spec = importlib.util.spec_from_file_location("local_redis_cli", ROOT / "spytest/apis/common/redis.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.db_port_map = {"CONFIG_DB": 0, "STATE_DB": 6400}
    module.db_socket_map = {"CONFIG_DB": "/run/redis/primary.sock", "STATE_DB": "/run/redis/bmp.sock"}
    return module


def test_database_metadata_keeps_each_process_endpoint(client):
    client.st.metadata = json.dumps({
        "INSTANCES": {"redis": {"port": 0, "unix_socket_path": "/primary.sock"},
                      "redis_bmp": {"port": 6400, "unix_socket_path": "/bmp.sock"}},
        "DATABASES": {"CONFIG_DB": {"instance": "redis"}, "STATE_DB": {"instance": "redis_bmp"}}})
    client.db_map_read("dut")
    assert client.db_port_map == {"CONFIG_DB": 0, "STATE_DB": 6400}
    assert client.db_socket_map == {"CONFIG_DB": "/primary.sock", "STATE_DB": "/bmp.sock"}


@pytest.mark.parametrize("mode", ["0", "1", "2"])
def test_existing_cli_preferences(client, mode):
    client.st.mode = mode
    assert client._prefix("dut", "CONFIG_DB") == {
        "0": "redis-cli -s /run/redis/primary.sock -n 4",
        "1": "redis-cli -s /run/redis/primary.sock -n 4",
        "2": "sonic-db-cli -s CONFIG_DB"}[mode]


def test_positive_port_stays_explicit_tcp(client):
    assert client._prefix("dut", "STATE_DB") == "redis-cli -p 6400 -n 6"


def test_socket_is_quoted_and_missing_socket_fails(client):
    client.db_socket_map["CONFIG_DB"] = "/run/redis/socket with spaces.sock"
    assert shlex.split(client._prefix("dut", "CONFIG_DB")) == [
        "redis-cli", "-s", "/run/redis/socket with spaces.sock", "-n", "4"]
    del client.db_socket_map["CONFIG_DB"]
    with pytest.raises(ValueError, match="Missing Unix socket"):
        client._prefix("dut", "CONFIG_DB")


def test_native_scan_and_named_dump_keep_filters(client):
    assert client.scan("dut", "CONFIG_DB", "PORT|*") == \
        "redis-cli -s /run/redis/primary.sock -n 4 --scan --pattern 'PORT|*'"
    assert client.dump("dut", "CONFIG_DB", "PORT|*") == "sonic-db-dump -t unix_socket -n CONFIG_DB -k 'PORT|*' -y"


@pytest.mark.parametrize('mode', ['0', '1', '2'])
def test_writers_use_named_cli_without_quoting_the_entire_command(client, mode):
    client.st.mode = mode
    command = 'HSET "PORT|test" field "value with spaces"'
    assert client.config('dut', 'CONFIG_DB', command) == 'sonic-db-cli -s --authenticate CONFIG_DB ' + command


@pytest.mark.parametrize("mode", ["0", "1", "2"])
@pytest.mark.parametrize("port", [0, 6400])
def test_multi_keeps_native_stdin_for_all_cli_preferences(client, mode, port):
    client.st.mode = mode
    client.db_port_map["CONFIG_DB"] = port
    command = client.multi("dut", "CONFIG_DB", ['HSET "PORT|test" field value', 'HGET "PORT|test" field'])
    if port == 0:
        assert command.startswith("sudo python3 - /run/redis/primary.sock 4 ")
        assert client.st.options["sudo"] is False
        assert client.st.options["split_cmds"] is False
        assert 'from swsscommon.redis import UnixConnection' in command
        assert 'UnixConnection(path=socket_path, db=int(database), authenticate=True)' in command
        assert 'connection.connect()' in command
        assert 'connection.send_packed_command([payload' in command
    else:
        assert command.startswith("redis-cli -p 6400 -n 4 -x < ")
        assert command.endswith(" | tee")
    assert client.st.uploaded == 'multi\nHSET "PORT|test" field value\nHGET "PORT|test" field\nexec'


def test_deferred_dpu_port_selection_is_unchanged():
    text = (ROOT / "tests/gnmi/test_gnmi_smartswitch.py").read_text()
    assert text.count('redis-cli --raw -p %s -n 0 ') == 2


@pytest.mark.parametrize("mode", ["0", "1", "2"])
def test_scan_always_uses_native_cli_with_configured_endpoint(client, mode):
    client.st.mode = mode
    assert client.scan("dut", "CONFIG_DB", "PORT|*") == \
        "redis-cli -s /run/redis/primary.sock -n 4 --scan --pattern 'PORT|*'"


@pytest.mark.parametrize("mode", ["1", "2"])
def test_named_dump_uses_database_option(client, mode):
    client.st.mode = mode
    assert client.dump("dut", "CONFIG_DB", "PORT|*") == \
        "sonic-db-dump -t unix_socket -n CONFIG_DB -k 'PORT|*' -y"


@pytest.mark.parametrize('output,expected', [('OK', True), ('NOPERM denied', False),
    ('NOAUTH Authentication required', False), ('WRONGPASS invalid', False), ('Permission denied', False)])
def test_interactive_writer_reports_redis_errors(client, monkeypatch, output, expected):
    from types import SimpleNamespace
    monkeypatch.setattr(client.st, 'log', lambda message: None, raising=False)
    connection = SimpleNamespace(find_prompt=lambda: '#', send_command=lambda *a, **kw: output)
    assert client.config_redis_db(connection, 'SET key value') is expected


def test_copied_legacy_writer_is_rejected_with_tcp_disabled(client, monkeypatch):
    messages = []
    monkeypatch.setattr(client.st, 'error', lambda message, **kw: messages.append(message), raising=False)
    assert client.build_std_redis_cli('dut') == 1
    assert 'legacy Redis only' in messages[0]
    assert not hasattr(client.st, 'command')
