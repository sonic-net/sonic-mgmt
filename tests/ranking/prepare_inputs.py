import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from copy import deepcopy

from tests.ranking.case_selection import _validate_source_identity, select_ranking_cases
from tests.ranking.port_mapping import (
    build_port_mapping, build_virtual_port_mapping, interface_args, ptf_config_view,
)
from tests.ranking.runtime_config import validate_runtime_config


SCHEMA_VERSION = 1
REQUEST_FIELDS = (
    'runtime', 'manifest', 'source_identity', 'selector', 'graph',
    'dut_ports', 'config_db', 'ptf_port_map',
)
SELECTOR_FIELDS = ('single', 'explicit', 'modules', 'priority')
OUTPUT_FILES = ('inputs.json', 'port-mapping.json', 'ptf-config-db.json')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: {}'.format(key))
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('invalid JSON constant: {}'.format(value))


def _load_request(path):
    with open(path, encoding='utf-8') as source:
        request = json.load(source, object_pairs_hook=_unique_object,
                            parse_constant=_reject_constant)
    if not isinstance(request, dict):
        raise ValueError('request must be a JSON object')
    return request


def _validated_selector(selector):
    if not isinstance(selector, dict):
        raise ValueError('selector must be an object')
    unknown = sorted(field for field in selector if field not in SELECTOR_FIELDS)
    if unknown:
        raise ValueError('unknown selector fields: {}'.format(', '.join(unknown)))
    provided = [field for field in SELECTOR_FIELDS if field in selector]
    if len(provided) != 1:
        raise ValueError('exactly one selector field is required')
    field = provided[0]
    if not isinstance(selector[field], str):
        raise ValueError('selector field {} must be a string'.format(field))
    return {field: selector[field]}


def _check_source_identity(request):
    _validate_source_identity(request['source_identity'])
    try:
        manifest_identity = json.dumps(
            request['manifest']['source_identity'], sort_keys=True)
        requested_identity = json.dumps(request['source_identity'], sort_keys=True)
    except (TypeError, ValueError) as error:
        raise ValueError('source identity must contain JSON values') from error
    if manifest_identity != requested_identity:
        raise ValueError('manifest source identity mismatch')


def _mapping_hash(mapping):
    canonical = json.dumps(mapping, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _write_json(path, value, sort_keys=True):
    text = json.dumps(value, sort_keys=sort_keys, indent=2,
                      ensure_ascii=True, allow_nan=False) + '\n'
    with open(path, 'w', encoding='utf-8') as sink:
        sink.write(text)


def _publish(bundle, mapping, view, output_dir):
    target = os.path.abspath(os.fspath(output_dir))
    parent = os.path.dirname(target)
    name = os.path.basename(target)
    if not name:
        raise ValueError('output path must name a directory: {}'.format(output_dir))
    if not os.path.isdir(parent):
        raise ValueError('output parent directory does not exist: {}'.format(parent))
    if os.path.lexists(target):
        raise ValueError('output path already exists: {}'.format(target))
    try:
        for value, sort_keys in ((bundle, False), (mapping, True), (view, False)):
            json.dumps(value, sort_keys=sort_keys, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError('compiled inputs must contain finite JSON values') from error
    staging = tempfile.mkdtemp(prefix='.{}.staging-'.format(name), dir=parent)
    try:
        # Preserve manifest module order for execution-time reselection.
        _write_json(os.path.join(staging, 'inputs.json'), bundle, sort_keys=False)
        _write_json(os.path.join(staging, 'port-mapping.json'), mapping)
        _write_json(os.path.join(staging, 'ptf-config-db.json'), view,
                    sort_keys=False)
        try:
            os.rename(staging, target)
        except OSError as error:
            raise ValueError('cannot publish to {}: {}'.format(target, error)) from error
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def compile_inputs(request, output_dir):
    if not isinstance(request, dict):
        raise ValueError('request must be an object')
    missing = [field for field in REQUEST_FIELDS
               if field != 'graph' and field not in request]
    unknown = sorted(field for field in request if field not in REQUEST_FIELDS)
    if missing:
        raise ValueError('missing request fields: {}'.format(', '.join(missing)))
    if unknown:
        raise ValueError('unknown request fields: {}'.format(', '.join(unknown)))
    runtime = validate_runtime_config(request['runtime'])
    selector = _validated_selector(request['selector'])
    selected = select_ranking_cases(request['manifest'], **selector)
    _check_source_identity(request)
    if runtime['backend'] == 'physical_fanout':
        if 'graph' not in request:
            raise ValueError('missing request fields: graph')
        mapping = build_port_mapping(
            request['graph'], runtime['dut_id'], request['dut_ports'],
            request['config_db'], request['ptf_port_map'])
    else:
        mapping = build_virtual_port_mapping(
            request['config_db'], request['dut_ports'], request['ptf_port_map'])
    if len(mapping) != runtime['expected_connected_ports']:
        raise ValueError(
            'expected_connected_ports is {} but the port mapping has '
            '{} port(s)'.format(runtime['expected_connected_ports'], len(mapping)))
    view = ptf_config_view(request['config_db'], mapping)
    bundle = {
        'schema_version': SCHEMA_VERSION,
        'runtime': runtime,
        'selector': selector,
        'selected_cases': selected,
        'interface_args': interface_args(mapping),
        'mapping_hash': _mapping_hash(mapping),
        'source_identity': deepcopy(request['source_identity']),
        'manifest': deepcopy(request['manifest']),
    }
    _publish(bundle, mapping, view, output_dir)
    return bundle


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Compile offline ranking test inputs from a request JSON.')
    parser.add_argument('--request', required=True,
                        help='path to the request JSON file')
    parser.add_argument('--output', required=True,
                        help='output directory to publish the compiled inputs')
    arguments = parser.parse_args(argv)
    try:
        compile_inputs(_load_request(arguments.request), arguments.output)
    except (ValueError, OSError) as error:
        print('error: {}'.format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
