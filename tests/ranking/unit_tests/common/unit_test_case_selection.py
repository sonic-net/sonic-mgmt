import copy
import io
import json

import pytest

from tests.ranking.cases.tools import generate_manifest as manifest_generator
from tests.ranking.common.case_selection import load_case_manifest, select_ranking_cases
from tests.ranking.cases.tools.generate_manifest import build_manifest


def test_manifest_sorting_and_default_priority(manifest):
    assert manifest == {
        'schema_version': 2,
        'source_identity': {'repo': 'SAI', 'commit': 'a' * 40},
        'modules': {
            'sairoute': {'cases': {
                'RouteA': {'priority': 'P2'},
                'RouteB': {'priority': 'P2'},
            }},
            'saivlan': {'cases': {
                'VlanA': {'priority': 'P2'},
            }},
        },
    }


@pytest.mark.parametrize('selector,expected', [
    ('case:sairoute.RouteB,sairoute.RouteA',
     ['sairoute.RouteA', 'sairoute.RouteB']),
    ('case:saivlan.VlanA', ['saivlan.VlanA']),
    ('module:sairoute', ['sairoute.RouteA', 'sairoute.RouteB']),
    ('module:saivlan,sairoute',
     ['sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA']),
    ('priority:P2', [
        'sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA',
    ]),
])
def test_selectors_follow_manifest_order(manifest, selector, expected):
    assert select_ranking_cases(manifest, selector) == expected


def test_empty_priority_selection_is_rejected(manifest):
    with pytest.raises(ValueError, match='selector matched no cases'):
        select_ranking_cases(manifest, 'priority:P1')


def test_loaded_manifest_order_is_preserved(manifest, tmp_path):
    cases = manifest['modules']['sairoute']['cases']
    manifest['modules']['sairoute']['cases'] = dict(
        reversed(list(cases.items())))
    manifest_path = tmp_path / 'manifest.json'
    identity_path = tmp_path / 'identity.json'
    manifest_path.write_text(json.dumps(manifest))
    identity_path.write_text(json.dumps(manifest['source_identity']))
    loaded = load_case_manifest(manifest_path, identity_path)
    assert loaded == manifest
    assert select_ranking_cases(loaded, 'module:sairoute') == [
        'sairoute.RouteB', 'sairoute.RouteA',
    ]


@pytest.mark.parametrize('selector', [
    None, '', 'case:', 'case:  ', 'unknown:sairoute.RouteA',
    'case:sairoute.RouteA,',
    'case:sairoute.RouteA,sairoute.RouteA',
    'case:sairoute.RouteA, sairoute.RouteA',
    'case:sairoute.Unknown', 'module:unknown',
    'module:sairoute,sairoute', 'module:sairoute,',
    'case:sairoute.RouteA;id', 'case:sairoute.RouteA\n',
    'priority:P3', 'priority:P0,P1', True, ['case:sairoute.RouteA'],
])
def test_invalid_selectors(manifest, selector):
    with pytest.raises(ValueError):
        select_ranking_cases(manifest, selector)


def test_invalid_manifest_is_rejected_by_selection():
    with pytest.raises(ValueError):
        select_ranking_cases({}, 'case:sairoute.RouteA')


@pytest.mark.parametrize('change', [
    lambda m: m.update(schema_version=1),
    lambda m: m.update(schema_version=True),
    lambda m: m.update(modules=[]),
    lambda m: m.update(source_identity={}),
    lambda m: m['modules']['sairoute']['cases']['RouteA'].update(priority='P9'),
    lambda m: m['modules']['sairoute'].update(cases=['RouteA']),
    lambda m: m['modules']['sairoute'].update(cases={'bad-name': {'priority': 'P2'}}),
    lambda m: m['modules']['sairoute'].update(cases={'RouteA;id': {'priority': 'P2'}}),
    lambda m: m['modules']['sairoute'].update(cases={'RouteA': None}),
    lambda m: m['modules']['sairoute'].update(cases={}),
    lambda m: m['modules'].update({'bad-module': {
        'cases': {'A': {'priority': 'P2'}},
    }}),
])
def test_invalid_manifest_files(manifest, tmp_path, change):
    identity = copy.deepcopy(manifest['source_identity'])
    change(manifest)
    manifest_path = tmp_path / 'manifest.json'
    identity_path = tmp_path / 'identity.json'
    manifest_path.write_text(json.dumps(manifest))
    identity_path.write_text(json.dumps(identity))
    with pytest.raises(ValueError):
        load_case_manifest(manifest_path, identity_path)


def test_source_mismatch(manifest, tmp_path):
    manifest_path = tmp_path / 'manifest.json'
    identity_path = tmp_path / 'identity.json'
    manifest_path.write_text(json.dumps(manifest))
    identity_path.write_text(json.dumps({'repo': 'SAI', 'commit': 'b' * 40}))
    with pytest.raises(ValueError, match='identity'):
        load_case_manifest(manifest_path, identity_path)


@pytest.mark.parametrize('manifest_value,source_value', [(True, 1), (1, 1.0)])
def test_source_identity_comparison_preserves_json_types(
        manifest, tmp_path, manifest_value, source_value):
    manifest['source_identity']['metadata'] = {'value': manifest_value}
    identity = copy.deepcopy(manifest['source_identity'])
    identity['metadata']['value'] = source_value
    manifest_path = tmp_path / 'manifest.json'
    identity_path = tmp_path / 'identity.json'
    manifest_path.write_text(json.dumps(manifest))
    identity_path.write_text(json.dumps(identity))
    with pytest.raises(ValueError, match='identity'):
        load_case_manifest(manifest_path, identity_path)


def test_source_identity_key_order_does_not_matter(manifest, tmp_path):
    manifest_path = tmp_path / 'manifest.json'
    identity_path = tmp_path / 'identity.json'
    manifest_path.write_text(json.dumps(manifest))
    identity_path.write_text(json.dumps(dict(
        reversed(list(manifest['source_identity'].items())),
    )))
    assert load_case_manifest(manifest_path, identity_path) == manifest


@pytest.mark.parametrize('text', ['{', '{}', '[]',
                                  '{"schema_version":1,"schema_version":1}'])
def test_invalid_json_and_duplicate_keys(tmp_path, text):
    path = tmp_path / 'manifest.json'
    path.write_text(text)
    identity = tmp_path / 'identity.json'
    identity.write_text('{"repo":"SAI"}')
    with pytest.raises(ValueError):
        load_case_manifest(path, identity)


def test_file_errors_are_value_errors(tmp_path):
    with pytest.raises(ValueError):
        load_case_manifest(tmp_path / 'missing', tmp_path / 'missing-source')


@pytest.mark.parametrize('names', [
    [], [''], ['sairoute.RouteA', 'sairoute.RouteA'],
    ['sairoute.Bad;id'], ['sairoute.RouteA.extra'], [None],
    'sairoute.RouteA', ['class.A'], ['sairoute.class'],
])
def test_invalid_generated_names(names):
    with pytest.raises(ValueError):
        build_manifest(names, {'repo': 'SAI'}, {})


@pytest.mark.parametrize('identity,priorities', [
    ({}, {}), ([], {}), ({'repo': 'SAI'}, []),
    ({'repo': 'SAI'}, {'sairoute': 'P3'}),
    ({'repo': 'SAI'}, {'bad-name': 'P0'}),
])
def test_invalid_generator_metadata(identity, priorities):
    with pytest.raises(ValueError):
        build_manifest(['sairoute.RouteA'], identity, priorities)


def test_generator_rejects_priority_for_unknown_case():
    with pytest.raises(ValueError, match='unknown priority case'):
        build_manifest(
            ['sairoute.RouteA'], {'repo': 'SAI'},
            {'sairoute.Missing': 'P0'},
        )


def test_generator_does_not_alias_identity():
    identity = {'repo': 'SAI', 'commit': 'a' * 40}
    result = build_manifest(['sairoute.RouteA'], identity, {})
    result['source_identity']['repo'] = 'changed'
    assert identity['repo'] == 'SAI'


def test_parse_test_names_filters_ptf_output():
    output = io.StringIO(
        'Using packet manipulation module: ptf.packet_scapy\n'
        'Platform not set. The common platform was selected\n'
        'sairoute.RouteB\n'
        '\n'
        'saivlan.VlanA\n'
    )

    assert manifest_generator.parse_test_names(output) == [
        'sairoute.RouteB', 'saivlan.VlanA',
    ]


@pytest.mark.parametrize('output,match', [
    ('informational output only\n', 'no test names'),
    ('sairoute.RouteA\nsairoute.RouteA\n', 'duplicate test case'),
    ('bad-module.RouteA\n', 'invalid identifier'),
    ('sairoute.RouteA.extra\n', 'invalid case name'),
])
def test_parse_test_names_rejects_invalid_output(output, match):
    with pytest.raises(ValueError, match=match):
        manifest_generator.parse_test_names(io.StringIO(output))


def test_parse_priorities():
    assert manifest_generator.parse_priority(
        'sairoute.RouteA=P0') == ('sairoute.RouteA', 'P0')
    assert manifest_generator.parse_priorities([
        'sairoute.RouteA=P0', 'saivlan.VlanA=P1',
    ]) == {
        'sairoute.RouteA': 'P0', 'saivlan.VlanA': 'P1',
    }


@pytest.mark.parametrize('value', [
    '', 'sairoute.RouteA', '=P0', 'sairoute.RouteA=',
    'sairoute.RouteA=P3', 'bad-module.RouteA=P0',
    'sairoute=P0', 'sairoute.RouteA=P0=extra',
])
def test_parse_priority_rejects_invalid_value(value):
    with pytest.raises(ValueError):
        manifest_generator.parse_priority(value)


def test_parse_priorities_rejects_duplicate_case():
    with pytest.raises(ValueError, match='duplicate priority'):
        manifest_generator.parse_priorities([
            'sairoute.RouteA=P0', 'sairoute.RouteA=P1',
        ])


def test_write_manifest_is_deterministic(tmp_path):
    identity = {'repo': 'SAI', 'commit': 'a' * 40}
    first = tmp_path / 'first.json'
    second = tmp_path / 'second.json'

    manifest_generator.write_manifest(
        ['saivlan.VlanA', 'sairoute.RouteB', 'sairoute.RouteA'],
        identity, {
            'sairoute.RouteA': 'P0', 'sairoute.RouteB': 'P0',
        }, first,
    )
    manifest_generator.write_manifest(
        ['sairoute.RouteA', 'saivlan.VlanA', 'sairoute.RouteB'],
        identity, {
            'sairoute.RouteA': 'P0', 'sairoute.RouteB': 'P0',
        }, second,
    )

    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text())['modules'] == {
        'sairoute': {'cases': {
            'RouteA': {'priority': 'P0'},
            'RouteB': {'priority': 'P0'},
        }},
        'saivlan': {'cases': {
            'VlanA': {'priority': 'P2'},
        }},
    }


def test_write_manifest_failure_preserves_existing_output(tmp_path, monkeypatch):
    output = tmp_path / 'manifest.json'
    output.write_text('existing\n')

    def fail_replace(source, destination):
        raise OSError('replace failed')

    monkeypatch.setattr(manifest_generator.os, 'replace', fail_replace)
    with pytest.raises(OSError, match='replace failed'):
        manifest_generator.write_manifest(
            ['sairoute.RouteA'], {'repo': 'SAI'}, {}, output,
        )

    assert output.read_text() == 'existing\n'
    assert list(tmp_path.iterdir()) == [output]


def test_main_reads_stdin_and_writes_manifest(tmp_path):
    identity = tmp_path / 'identity.json'
    identity.write_text(json.dumps({'repo': 'SAI', 'commit': 'a' * 40}))
    output = tmp_path / 'manifest.json'

    result = manifest_generator.main([
        '--source-identity', str(identity),
        '--priority', 'sairoute.RouteA=P0',
        '--output', str(output),
    ], stdin=io.StringIO('PTF startup\nsairoute.RouteA\n'))

    assert result == 0
    assert json.loads(output.read_text())['modules'] == {
        'sairoute': {'cases': {
            'RouteA': {'priority': 'P0'},
        }},
    }


def test_main_reads_input_file(tmp_path):
    identity = tmp_path / 'identity.json'
    identity.write_text(json.dumps({'repo': 'SAI'}))
    discovered = tmp_path / 'names.txt'
    discovered.write_text('sairoute.RouteA\n')
    output = tmp_path / 'manifest.json'

    assert manifest_generator.main([
        '--input', str(discovered),
        '--source-identity', str(identity),
        '--output', str(output),
    ]) == 0
    assert output.is_file()


def test_main_reports_invalid_discovery(tmp_path):
    identity = tmp_path / 'identity.json'
    identity.write_text(json.dumps({'repo': 'SAI'}))

    with pytest.raises(SystemExit) as error:
        manifest_generator.main([
            '--source-identity', str(identity),
            '--output', str(tmp_path / 'manifest.json'),
        ], stdin=io.StringIO('PTF startup only\n'))

    assert error.value.code == 2


@pytest.mark.parametrize('missing_argument', ['identity', 'input'])
def test_main_reports_unreadable_input(tmp_path, missing_argument):
    identity = tmp_path / 'identity.json'
    identity.write_text(json.dumps({'repo': 'SAI'}))
    discovered = tmp_path / 'names.txt'
    discovered.write_text('sairoute.RouteA\n')
    if missing_argument == 'identity':
        identity = tmp_path / 'missing-identity.json'
    else:
        discovered = tmp_path / 'missing-names.txt'

    with pytest.raises(SystemExit) as error:
        manifest_generator.main([
            '--input', str(discovered),
            '--source-identity', str(identity),
            '--output', str(tmp_path / 'manifest.json'),
        ])

    assert error.value.code == 2
