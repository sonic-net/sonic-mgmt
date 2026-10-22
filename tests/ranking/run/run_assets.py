"""Load topology-independent assets consumed by Ranking case execution."""

from copy import deepcopy
from pathlib import Path
import re

from tests.ranking.common.case_selection import load_case_manifest, load_json


def _existing(path, description):
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError('{} must be an existing file: {}'.format(
            description, path))
    return str(path)


def load_run_assets(ranking_root=None):
    """Return topology-independent assets consumed by case execution."""
    ranking_root = (Path(ranking_root).resolve() if ranking_root is not None
                    else Path(__file__).resolve().parent.parent)
    cases_root = ranking_root / 'cases'
    config = {
        'manifest': _existing(cases_root / 'manifest.json', 'case manifest'),
        'source_identity_file': _existing(
            cases_root / 'source_identity.json', 'case source identity'),
        'runner_path': _existing(
            ranking_root / 'run' / 'ptf_runner.py', 'container runner'),
    }
    config['manifest_data'] = load_case_manifest(
        config['manifest'], config['source_identity_file'])
    source_identity = config['manifest_data']['source_identity']

    case_contract = load_json(
        cases_root / 'ranking-contract.json', 'case contract')
    if (not isinstance(case_contract, dict) or
            case_contract.get('source_identity') !=
            source_identity or
            case_contract.get('switch_owner') != 'case' or
            case_contract.get('rpc_port') != 9092):
        raise ValueError(
            'case contract does not match the canonical Run assets')
    binding_identity = case_contract.get('binding_identity')
    hash_fields = ('package_sha256', 'headers_sha256', 'adapter_sha256')
    semantic = binding_identity.get('semantic_identity') if isinstance(
        binding_identity, dict) else None
    if (not isinstance(binding_identity, dict) or
            set(binding_identity) !=
            set(hash_fields) | {'semantic_identity'} or
            any(not isinstance(binding_identity.get(field), str) or
                re.fullmatch(r'[0-9a-f]{64}', binding_identity[field]) is None
                for field in hash_fields) or
            not isinstance(semantic, dict) or
            set(semantic) != {'SAI_MAJOR', 'SAI_MINOR', 'SAI_REVISION',
                              'SAI_API_VERSION'} or
            any(type(item) is not int for item in semantic.values())):
        raise ValueError(
            'case contract binding identity is incomplete or invalid')
    config['binding_identity'] = deepcopy(binding_identity)
    return config
