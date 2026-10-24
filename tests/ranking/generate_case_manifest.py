from copy import deepcopy

from .case_selection import (
    PRIORITIES, _validate_case_name, _validate_identifier,
    _validate_manifest, _validate_source_identity,
)


def build_manifest(test_names, source_identity, priorities) -> dict:
    _validate_source_identity(source_identity)
    if not isinstance(priorities, dict):
        raise ValueError('priorities must be an object')
    for module, priority in priorities.items():
        _validate_identifier(module)
        if priority not in PRIORITIES:
            raise ValueError('invalid priority for module: {}'.format(module))
    if not isinstance(test_names, (list, tuple)) or not test_names:
        raise ValueError('test_names must be a non-empty sequence')
    for name in test_names:
        _validate_case_name(name)
    if len(test_names) != len(set(test_names)):
        raise ValueError('duplicate test case')
    modules = {}
    for name in sorted(test_names):
        module, case = name.split('.')
        entry = modules.setdefault(
            module, {'priority': priorities.get(module, 'P2'), 'cases': []},
        )
        entry['cases'].append(case)
    manifest = {
        'schema_version': 1,
        'source_identity': deepcopy(source_identity),
        'modules': modules,
    }
    _validate_manifest(manifest)
    return manifest
