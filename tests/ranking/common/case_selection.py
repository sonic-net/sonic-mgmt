import json
import keyword
import re


PRIORITIES = ('P0', 'P1', 'P2')
SELECTOR_KINDS = ('case', 'module', 'priority')
IDENTIFIER_PATTERN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def validate_identifier(value):
    if (not isinstance(value, str)
            or not IDENTIFIER_PATTERN.fullmatch(value)
            or keyword.iskeyword(value)):
        raise ValueError('invalid identifier: {!r}'.format(value))


def validate_case_name(value):
    if not isinstance(value, str) or value.count('.') != 1:
        raise ValueError('invalid case name: {!r}'.format(value))
    module, case = value.split('.')
    validate_identifier(module)
    validate_identifier(case)


def validate_source_identity(value):
    if not isinstance(value, dict) or not value:
        raise ValueError('source identity must be a non-empty object')
    if any(not isinstance(key, str) or not key for key in value):
        raise ValueError('source identity keys must be non-empty strings')
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError('source identity must contain JSON values') from error


def validate_manifest(manifest):
    if (not isinstance(manifest, dict)
            or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != 2):
        raise ValueError('manifest schema_version must be 2')
    validate_source_identity(manifest.get('source_identity'))
    modules = manifest.get('modules')
    if not isinstance(modules, dict) or not modules:
        raise ValueError('manifest modules must be a non-empty object')
    names = set()
    for module, entry in modules.items():
        validate_identifier(module)
        if not isinstance(entry, dict):
            raise ValueError('module entry must be an object: {}'.format(module))
        cases = entry.get('cases')
        if not isinstance(cases, dict) or not cases:
            raise ValueError(
                'module cases must be a non-empty object: {}'.format(module))
        for case, metadata in cases.items():
            validate_identifier(case)
            if not isinstance(metadata, dict):
                raise ValueError(
                    'case metadata must be an object: {}.{}'.format(
                        module, case))
            if metadata.get('priority') not in PRIORITIES:
                raise ValueError(
                    'invalid priority for case: {}.{}'.format(module, case))
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


def load_json(path, description):
    try:
        with open(path, encoding='utf-8') as source:
            return json.load(source, object_pairs_hook=_unique_object,
                             parse_constant=_reject_constant)
    except (OSError, ValueError, TypeError) as error:
        raise ValueError('cannot load {}: {}'.format(description, error)) from error


def load_case_manifest(manifest_path, source_identity_path) -> dict:
    manifest = load_json(manifest_path, 'case manifest')
    source_identity = load_json(source_identity_path, 'source identity')
    validate_manifest(manifest)
    validate_source_identity(source_identity)
    manifest_identity = json.dumps(manifest['source_identity'], sort_keys=True)
    expected_identity = json.dumps(source_identity, sort_keys=True)
    if manifest_identity != expected_identity:
        raise ValueError('manifest source identity mismatch')
    return manifest


def _parse_selector(value):
    if (not isinstance(value, str)
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError('selector must be a string without control characters')
    if ':' not in value:
        raise ValueError('selector must use TYPE:VALUE')
    kind, payload = value.split(':', 1)
    if kind not in SELECTOR_KINDS:
        raise ValueError('invalid selector type: {}'.format(kind))
    values = [item.strip() for item in payload.split(',')]
    if not all(values):
        raise ValueError('empty selector value')
    if len(values) != len(set(values)):
        raise ValueError('duplicate selector value')
    return kind, values


def select_ranking_cases(manifest, selector) -> list[str]:
    validate_manifest(manifest)
    kind, requested = _parse_selector(selector)
    entries = manifest['modules']
    all_cases = [
        '{}.{}'.format(module, case)
        for module, entry in entries.items()
        for case in entry['cases']
    ]
    if kind == 'case':
        for name in requested:
            validate_case_name(name)
            if name not in all_cases:
                raise ValueError('unknown case: {}'.format(name))
        wanted = set(requested)
        return [name for name in all_cases if name in wanted]
    if kind == 'module':
        for module in requested:
            validate_identifier(module)
            if module not in entries:
                raise ValueError('unknown module: {}'.format(module))
        wanted = set(requested)
        return [
            '{}.{}'.format(module, case)
            for module, entry in entries.items() if module in wanted
            for case in entry['cases']
        ]
    if len(requested) != 1 or requested[0] not in PRIORITIES:
        raise ValueError('invalid priority selector')
    priority = requested[0]
    selected = [
        '{}.{}'.format(module, case)
        for module, entry in entries.items()
        for case, metadata in entry['cases'].items()
        if metadata['priority'] == priority
    ]
    if not selected:
        raise ValueError(
            'selector matched no cases: priority:{}'.format(priority))
    return selected
