import ast
import configparser
import fnmatch
import hashlib
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / 'cases'
PTF = CASES / 'ptf'
EXPECTED_SOURCE = {
    'repo': 'SONiC/SAI',
    'branch': 'v1.10-pdx-capability',
    'commit': '3e2e3631b57d8ce9f461ece2e14e451295cb520b',
}


def _load(name):
    return json.loads((CASES / name).read_text(encoding='utf-8'))


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cases_have_one_v110_source_identity():
    identity = _load('source_identity.json')
    manifest = _load('manifest.json')
    contract = _load('ranking-contract.json')

    assert identity == EXPECTED_SOURCE
    assert manifest['source_identity'] == EXPECTED_SOURCE
    assert contract['source_identity'] == EXPECTED_SOURCE
    assert not (ROOT / 'case_manifest.json').exists()
    assert not (ROOT / 'environments' / 'sonic_sonic' / 'case_manifest.json').exists()


def test_full_manifest_has_verified_v110_inventory():
    manifest = _load('manifest.json')

    assert manifest['schema_version'] == 2
    assert len(manifest['modules']) == 46
    assert sum(len(entry['cases']) for entry in manifest['modules'].values()) == 673
    assert 'multipleRoutesTest' in manifest['modules']['sairoute']['cases']
    assert 'dropRouteTest' in manifest['modules']['sairoute']['cases']
    priorities = Counter(
        metadata['priority']
        for entry in manifest['modules'].values()
        for metadata in entry['cases'].values())
    assert priorities == {'P0': 11, 'P2': 662}


def test_case_tree_is_a_nested_source_snapshot():
    assert PTF.is_dir()
    assert (PTF / 'sai_base_test.py').is_file()
    assert (PTF / 'sai_utils.py').is_file()
    assert (PTF / 'platform_helper').is_dir()
    assert (PTF / 'resources').is_dir()
    assert not (PTF / '.source_identity').exists()
    assert not (PTF / 'ranking-contract.json').exists()
    assert (PTF / 'attr_map.json').is_file()


def test_case_tree_does_not_vendor_generated_binding():
    assert not any(path.name == 'sai_thrift' for path in CASES.rglob('*'))
    assert not any(path.name == 'sai_rpc.py' for path in CASES.rglob('*'))
    assert not (PTF / 'resources' / 'Jenkinsfile.Saitest').exists()


def test_source_overlay_has_no_unrecorded_deviations():
    provenance = _load('patches.json')
    assert provenance['schema_version'] == 1
    assert provenance['base_source_identity'] == EXPECTED_SOURCE

    base_files = provenance['base_files']
    overlays = {entry['path']: entry for entry in provenance['patches']}
    excluded = {entry['path']: entry for entry in provenance['excluded_files']}
    assert len(base_files) == 118
    assert list(base_files) == sorted(base_files)
    assert list(overlays) == sorted(overlays)
    assert list(excluded) == sorted(excluded)
    assert set(overlays) == {
        'ext_sai_counter_stress_test.py', 'ext_sai_l3_scale_base.py', 'lpm.py',
        'resources/config_db_32d_ptf128.json',
        'resources/config_db_32d_ptf32.json',
        'resources/config_db_32d_ptf64.json',
        'sai_base_test.py', 'sai_test_result.py', 'saiport.py',
    }
    assert set(excluded) == {'resources/Jenkinsfile.Saitest'}
    assert not set(overlays).intersection(excluded)

    actual = {
        path.relative_to(PTF).as_posix(): _sha256(path)
        for path in PTF.rglob('*')
        if path.is_file() and '__pycache__' not in path.parts
    }
    assert set(actual) == set(base_files).difference(excluded)
    for path, digest in actual.items():
        expected = overlays.get(path, {}).get('patched_sha256', base_files[path])
        assert digest == expected, path
    for path, entry in overlays.items():
        assert entry['base_sha256'] == base_files[path]
        assert entry['base_sha256'] != entry['patched_sha256']
        assert entry['id']
        assert entry['reason']
    for path, entry in excluded.items():
        assert entry['base_sha256'] == base_files[path]
        assert entry['reason']
        assert not (PTF / path).exists()


def test_runtime_capability_map_is_owned_only_by_the_case_package():
    assert (PTF / 'attr_map.json').is_file()
    assert not (ROOT / 'report' / 'metadata' / 'attr_map.json').exists()


def test_sai_base_has_no_embedded_remote_lifecycle_or_credentials():
    source = (PTF / 'sai_base_test.py').read_text(encoding='utf-8')
    ast.parse(source)

    for forbidden in (
            'AutoAddPolicy', 'RUN_REG', 'start_saiserver', 'kill_saiserver',
            'SSHClient()', '.connect('):
        assert forbidden not in source
    assert not re.search(
        r'(?m)^\s*[A-Z_]*(?:USER|USERNAME|PASSWORD)\s*=\s*[\'\"]',
        source,
    )


def test_scale_timing_ssh_is_explicit_and_rejects_unknown_hosts():
    source = (PTF / 'ext_sai_l3_scale_base.py').read_text(encoding='utf-8')
    ast.parse(source)

    assert 'AutoAddPolicy' not in source
    assert 'RejectPolicy' in source
    assert 'load_system_host_keys' in source
    assert "os.environ.get('SAI_TIMING_SSH_HOST', '')" in source
    assert "os.environ.get('SAI_TIMING_SSH_USER', '')" in source
    assert "os.environ.get('SAI_TIMING_SSH_PASSWORD', '')" in source
    assert "os.environ.get('SAI_TIMING_CONTAINER', '')" in source
    assert not re.search(
        r'(?m)^\s*[A-Z_]*(?:USER|USERNAME|PASSWORD)\s*=\s*[\'\"]',
        source,
    )


def test_ptf_source_has_no_known_embedded_credentials_or_unsafe_host_policy():
    assignment = re.compile(
        r'(?m)^\s*[A-Z_]*(?:USER|USERNAME|PASSWORD)\s*=\s*[\'\"]')
    for path in PTF.rglob('*'):
        if path.is_file():
            source = path.read_bytes()
            assert b'AutoAddPolicy' not in source, path
    for path in PTF.rglob('*.py'):
        source = path.read_text(encoding='utf-8')
        assert assignment.search(source) is None, path
    assert not (PTF / 'resources' / 'Jenkinsfile.Saitest').exists()


def test_example_config_management_addresses_use_documentation_ranges():
    documentation_networks = (
        ipaddress.ip_network('192.0.2.0/24'),
        ipaddress.ip_network('198.51.100.0/24'),
        ipaddress.ip_network('203.0.113.0/24'),
        ipaddress.ip_network('2001:db8::/32'),
    )
    for path in sorted((PTF / 'resources').glob('config_db*.json')):
        config = json.loads(path.read_text(encoding='utf-8'))
        for key, attributes in config.get('MGMT_INTERFACE', {}).items():
            interface = ipaddress.ip_interface(key.split('|', 1)[1])
            gateway = ipaddress.ip_address(attributes['gwaddr'])
            assert any(interface.ip in network for network in documentation_networks), path
            assert any(gateway in network for network in documentation_networks), path


def test_imported_cases_do_not_own_saiserver_lifecycle():
    helper_names = {'start_saiserver', 'kill_saiserver'}
    for path in PTF.rglob('*.py'):
        source = path.read_text(encoding='utf-8')
        tree = ast.parse(source)
        definitions = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert not definitions.intersection(helper_names), path
        assert not calls.intersection(helper_names), path
        assert not re.search(
            r'docker\s+exec[^\n]*(?:/usr/sbin/)?saiserver', source, re.IGNORECASE,
        ), path
        assert 'start_saiserver(' not in source, path
        assert 'kill_saiserver(' not in source, path


def test_flake8_exception_is_scoped_to_imported_ptf_source():
    config = configparser.ConfigParser()
    config.read(ROOT.parents[1] / '.flake8')
    rules = config['flake8']['per-file-ignores'].splitlines()
    case_rules = [line.strip() for line in rules if 'tests/ranking/cases' in line]

    assert len(case_rules) == 1
    pattern, ignored = case_rules[0].split(':', 1)
    assert pattern.strip() == 'tests/ranking/cases/ptf/*'
    assert fnmatch.fnmatch(
        'tests/ranking/cases/ptf/config/port_configer.py', pattern.strip())
    assert not fnmatch.fnmatch(
        'tests/ranking/run/run_assets.py', pattern.strip())
    ignored_codes = {code.strip() for code in ignored.split(',')}
    assert {'F403', 'F405'}.issubset(ignored_codes)
    assert 'F821' not in ignored_codes
    assert not any(code.startswith('E9') for code in ignored_codes)


def test_each_selected_case_has_a_top_level_definition():
    manifest = _load('manifest.json')
    for module, configuration in manifest['modules'].items():
        tree = ast.parse((PTF / (module + '.py')).read_text(encoding='utf-8'))
        classes = Counter(node.name for node in tree.body if isinstance(node, ast.ClassDef))
        for case in configuration['cases']:
            assert classes[case] >= 1, '{}.{} has {} definitions'.format(
                module, case, classes[case],
            )
