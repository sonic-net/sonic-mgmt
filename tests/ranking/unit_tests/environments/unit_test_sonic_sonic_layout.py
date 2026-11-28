from pathlib import Path


RANKING_ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENT_ROOT = RANKING_ROOT / 'environments' / 'sonic_sonic'


def test_sonic_sonic_environment_package_documents_its_topology():
    assert (ENVIRONMENT_ROOT / 'environment.py').is_file()
    assert (ENVIRONMENT_ROOT / 'prepare.py').is_file()
    topology = (ENVIRONMENT_ROOT / 'README.md').read_text(encoding='utf-8')
    assert 'SONiC DUT' in topology
    assert 'SONiC PTF' in topology
    assert '32' in topology
