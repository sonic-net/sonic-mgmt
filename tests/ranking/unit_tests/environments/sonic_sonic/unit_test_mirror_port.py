import importlib.util
from pathlib import Path
import subprocess

import pytest


EXAMPLE = Path(__file__).resolve().parents[3] / 'environments' / 'sonic_sonic'


def _module():
    path = EXAMPLE / 'ptf' / 'mirror_port.py'
    spec = importlib.util.spec_from_file_location('ranking_sonic_sonic_mirror_port', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_ptf_port_file_maps_ethernet1_to_32_to_cd0_to_31():
    module = _module()

    names = module.load_port_names(EXAMPLE / 'ptf' / 'port_config.ini')

    assert names == ['Ethernet{}'.format(number) for number in range(1, 33)]
    assert module.sdk_port_map(names) == {
        'Ethernet{}'.format(number): 'cd{}'.format(number - 1)
        for number in range(1, 33)
    }


def test_split_sonic_names_are_accepted_and_keep_file_order(tmp_path):
    module = _module()
    path = tmp_path / 'port_config.ini'
    path.write_text(
        '# name\nEthernet1_1\nEthernet1_2\nEthernet16_2\n',
        encoding='utf-8')

    names = module.load_port_names(path)

    assert module.sdk_port_map(names) == {
        'Ethernet1_1': 'cd0',
        'Ethernet1_2': 'cd1',
        'Ethernet16_2': 'cd2',
    }


def test_mirror_command_failure_is_propagated(tmp_path):
    module = _module()
    path = tmp_path / 'port_config.ini'
    path.write_text('# name\nEthernet1\n', encoding='utf-8')

    def fail(argv, check):
        raise subprocess.CalledProcessError(9, argv)

    with pytest.raises(subprocess.CalledProcessError) as error:
        module.apply_mirror('ingress', path, runner=fail)

    assert error.value.returncode == 9


def test_mirror_uses_one_argument_bcm_shell_command_without_a_host_shell(tmp_path):
    module = _module()
    path = tmp_path / 'port_config.ini'
    path.write_text('# name\nEthernet1\n', encoding='utf-8')
    calls = []

    def record(argv, check):
        calls.append((argv, check))

    module.apply_mirror('ingress', path, runner=record)

    assert calls == [([
        'docker', 'exec', 'syncd', 'bcmcmd', '-c',
        'mirror port cd0 mode=ingress dp=cpu0',
    ], True)]


def test_invalid_or_duplicate_port_names_are_rejected(tmp_path):
    module = _module()
    path = tmp_path / 'port_config.ini'
    path.write_text('# name\nEthernet1\nEthernet1\n', encoding='utf-8')

    with pytest.raises(ValueError, match='duplicate'):
        module.load_port_names(path)
