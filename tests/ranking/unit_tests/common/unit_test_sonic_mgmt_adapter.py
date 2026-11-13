import stat
from pathlib import Path

import yaml
import pytest


EXAMPLE = Path(__file__).resolve().parents[2] / 'environments' / 'sonic_sonic' / 'environment.yml'


def _environment(password=None):
    from tests.ranking.environments.sonic_sonic.environment import load_environment

    value = load_environment(EXAMPLE)
    if password is not None:
        value['hosts']['dut']['auth'] = {'password': password}
    return value


def test_adapter_materializes_private_standard_inventory_and_testbed(tmp_path):
    from tests.ranking.common.sonic_mgmt_adapter import create_controller_adapter
    from tests.ranking.environments.sonic_sonic.environment import controller_spec

    adapter = create_controller_adapter(
        controller_spec(_environment()), temp_parent=tmp_path)
    try:
        assert stat.S_IMODE(adapter.root.stat().st_mode) == 0o700
        assert stat.S_IMODE(adapter.inventory.stat().st_mode) == 0o600
        assert stat.S_IMODE(adapter.testbed_file.stat().st_mode) == 0o600
        topology = adapter.testbed_file.parent / 'vars' / 'topo_ptf32.yml'
        assert topology.is_file()
        assert stat.S_IMODE(topology.stat().st_mode) == 0o600
        inventory = yaml.safe_load(adapter.inventory.read_text(encoding='utf-8'))
        assert inventory['all']['children']['sonic']['hosts']['sonic-dut'] == {
            'ansible_host': '192.0.2.10', 'ansible_user': 'root',
            'ansible_connection': 'ssh'}
        assert 'ansible_password' not in adapter.inventory.read_text(encoding='utf-8')
        testbed = yaml.safe_load(adapter.testbed_file.read_text(encoding='utf-8'))
        assert testbed[0]['conf-name'] == 'ranking'
        assert testbed[0]['dut'] == ['sonic-dut']
        assert testbed[0]['ptf'] == 'sonic-ptf'
    finally:
        adapter.cleanup()
    assert not adapter.root.exists()


def test_password_exists_only_in_private_adapter_and_cleanup_removes_it(tmp_path):
    from tests.ranking.common.sonic_mgmt_adapter import create_controller_adapter
    from tests.ranking.environments.sonic_sonic.environment import controller_spec

    adapter = create_controller_adapter(
        controller_spec(_environment(password='sensitive-value')), temp_parent=tmp_path)
    assert 'sensitive-value' in adapter.inventory.read_text(encoding='utf-8')
    assert 'sensitive-value' not in adapter.testbed_file.read_text(encoding='utf-8')
    adapter.cleanup()
    assert not adapter.root.exists()


def test_relative_topology_source_is_resolved_from_sonic_mgmt_root(tmp_path, monkeypatch):
    from tests.ranking.common.sonic_mgmt_adapter import create_controller_adapter
    from tests.ranking.environments.sonic_sonic.environment import controller_spec

    spec = controller_spec(_environment())
    spec['topology_source'] = 'ansible/vars/topo_ptf32.yml'
    monkeypatch.chdir(tmp_path)
    adapter = create_controller_adapter(spec, temp_parent=tmp_path)
    try:
        topology = adapter.testbed_file.parent / 'vars' / 'topo_ptf32.yml'
        assert topology.read_bytes() == (
            EXAMPLE.parents[4] / spec['topology_source']).read_bytes()
    finally:
        adapter.cleanup()


def test_relative_topology_cannot_escape_repository(tmp_path, monkeypatch):
    from tests.ranking.common import sonic_mgmt_adapter
    from tests.ranking.environments.sonic_sonic.environment import controller_spec

    repository = tmp_path / 'repository'
    repository.mkdir()
    private = tmp_path / 'private'
    private.mkdir()
    (tmp_path / 'topo.yml').write_text('topology: {}\n')
    monkeypatch.setattr(sonic_mgmt_adapter, '__file__', str(
        repository / 'tests/ranking/common/sonic_mgmt_adapter.py'))
    monkeypatch.chdir(repository)
    spec = controller_spec(_environment())
    spec['topology_source'] = '../topo.yml'

    with pytest.raises(ValueError, match='escapes sonic-mgmt'):
        sonic_mgmt_adapter.create_controller_adapter(spec, temp_parent=private)

    assert not list(private.iterdir())
