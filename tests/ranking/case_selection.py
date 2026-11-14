import json
import keyword
import re


PRIORITIES = ('P0', 'P1', 'P2')
IDENTIFIER_PATTERN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def _validate_identifier(value):
    if (not isinstance(value, str)
            or not IDENTIFIER_PATTERN.fullmatch(value)
            or keyword.iskeyword(value)):
        raise ValueError('invalid identifier: {!r}'.format(value))


def _validate_case_name(value):
    if not isinstance(value, str) or value.count('.') != 1:
        raise ValueError('invalid case name: {!r}'.format(value))
    module, case = value.split('.')
    _validate_identifier(module)
    _validate_identifier(case)


def _validate_source_identity(value):
    if not isinstance(value, dict) or not value:
        raise ValueError('source identity must be a non-empty object')
    if any(not isinstance(key, str) or not key for key in value):
        raise ValueError('source identity keys must be non-empty strings')
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError('source identity must contain JSON values') from error


def _validate_manifest(manifest):
    if (not isinstance(manifest, dict)
            or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != 1):
        raise ValueError('manifest schema_version must be 1')
    _validate_source_identity(manifest.get('source_identity'))
    modules = manifest.get('modules')
    if not isinstance(modules, dict) or not modules:
        raise ValueError('manifest modules must be a non-empty object')
    names = set()
    for module, entry in modules.items():
        _validate_identifier(module)
        if not isinstance(entry, dict):
            raise ValueError('module entry must be an object: {}'.format(module))
        if entry.get('priority') not in PRIORITIES:
            raise ValueError('invalid priority for module: {}'.format(module))
        cases = entry.get('cases')
        if not isinstance(cases, list) or not cases:
            raise ValueError('module cases must be a non-empty list: {}'.format(module))
        for case in cases:
            _validate_identifier(case)
            name = '{}.{}'.format(module, case)
            if name in names:
                raise ValueError('duplicate case in manifest: {}'.format(name))
            names.add(name)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: {}'.format(key))
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('invalid JSON constant: {}'.format(value))


def _load_json(path, description):
    try:
        with open(path, encoding='utf-8') as source:
            return json.load(source, object_pairs_hook=_unique_object,
                             parse_constant=_reject_constant)
    except (OSError, ValueError, TypeError) as error:
        raise ValueError('cannot load {}: {}'.format(description, error)) from error


def load_case_manifest(manifest_path, source_identity_path) -> dict:
    manifest = _load_json(manifest_path, 'case manifest')
    source_identity = _load_json(source_identity_path, 'source identity')
    _validate_manifest(manifest)
    _validate_source_identity(source_identity)
    manifest_identity = json.dumps(manifest['source_identity'], sort_keys=True)
    expected_identity = json.dumps(source_identity, sort_keys=True)
    if manifest_identity != expected_identity:
        raise ValueError('manifest source identity mismatch')
    return manifest


def _parse_selector(value):
    if (not isinstance(value, str)
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError('selector must be a string without control characters')
    values = [item.strip() for item in value.split(',')]
    if not all(values):
        raise ValueError('empty selector value')
    if len(values) != len(set(values)):
        raise ValueError('duplicate selector value')
    return values


def select_ranking_cases(manifest, *, single=None, explicit=None,
                         modules=None, priority=None) -> list[str]:
    _validate_manifest(manifest)
    selectors = [single, explicit, modules, priority]
    if sum(value is not None for value in selectors) != 1:
        raise ValueError('exactly one non-empty selector is required')
    selector = next(value for value in selectors if value is not None)
    requested = _parse_selector(selector)
    entries = manifest['modules']
    all_cases = [
        '{}.{}'.format(module, case)
        for module, entry in entries.items()
        for case in entry['cases']
    ]
    if single is not None or explicit is not None:
        if single is not None and len(requested) != 1:
            raise ValueError('single selector requires exactly one case')
        for name in requested:
            _validate_case_name(name)
            if name not in all_cases:
                raise ValueError('unknown case: {}'.format(name))
        wanted = set(requested)
        return [name for name in all_cases if name in wanted]
    if modules is not None:
        for module in requested:
            _validate_identifier(module)
            if module not in entries:
                raise ValueError('unknown module: {}'.format(module))
        wanted = set(requested)
    else:
        if len(requested) != 1 or requested[0] not in PRIORITIES:
            raise ValueError('invalid priority selector')
        wanted = {module for module, entry in entries.items()
                  if entry['priority'] == requested[0]}
    return [
        '{}.{}'.format(module, case)
        for module, entry in entries.items() if module in wanted
        for case in entry['cases']
    ]
