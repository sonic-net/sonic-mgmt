import io
import json

import pytest

from tests.ranking.cases import generate_manifest as manifest_generator
from tests.ranking.common.case_selection import load_case_manifest, select_ranking_cases
from tests.ranking.cases.generate_manifest import build_manifest


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
    ('case: sairoute.RouteA', ['sairoute.RouteA']),
    ('module:sairoute', ['sairoute.RouteA', 'sairoute.RouteB']),
    ('module: sairoute', ['sairoute.RouteA', 'sairoute.RouteB']),
    ('module:saivlan,sairoute',
     ['sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA']),
    ('priority:P2', [
        'sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA',
    ]),
    ('priority: P2', [
        'sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA',
    ]),
])
def test_selectors_follow_manifest_order(manifest, selector, expected):
    assert select_ranking_cases(manifest, selector) == expected


@pytest.mark.parametrize('selector,expected', [
    ('sairoute.RouteB,sairoute.RouteA',
     ['sairoute.RouteA', 'sairoute.RouteB']),
    ('sairoute', ['sairoute.RouteA', 'sairoute.RouteB']),
    ('P2', ['sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA']),
    ('sairoute.RouteA,saivlan,P2', [
        'sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA',
    ]),
    ('module:sairoute,saivlan.VlanA', [
        'sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA',
    ]),
    ('case:sairoute.RouteB,module:saivlan',
     ['sairoute.RouteB', 'saivlan.VlanA']),
    ('sairoute.RouteA,case:sairoute.RouteA', ['sairoute.RouteA']),
    ('case:sairoute.RouteA,sairoute.RouteA', ['sairoute.RouteA']),
    ('case:sairoute.RouteA, sairoute.RouteA', ['sairoute.RouteA']),
    ('module:sairoute,sairoute', ['sairoute.RouteA', 'sairoute.RouteB']),
])
def test_unprefixed_and_mixed_selectors_are_unioned(manifest, selector, expected):
    assert select_ranking_cases(manifest, selector) == expected


def test_empty_priority_selection_is_rejected(manifest):
    with pytest.raises(ValueError, match='selector matched no cases'):
        select_ranking_cases(manifest, 'priority:P1')


def test_loaded_manifest_order_is_preserved(manifest, tmp_path):
    cases = manifest['modules']['sairoute']['cases']
    manifest['modules']['sairoute']['cases'] = dict(
        reversed(list(cases.items())))
    manifest_path = tmp_path / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest))
    loaded = load_case_manifest(manifest_path)
    assert loaded == manifest
    assert select_ranking_cases(loaded, 'module:sairoute') == [
        'sairoute.RouteB', 'sairoute.RouteA',
    ]


@pytest.mark.parametrize('selector', [
    None, '', 'case:', 'case:  ', 'unknown:sairoute.RouteA',
    'case:sairoute.RouteA,',
    'case:sairoute.Unknown', 'module:unknown',
    'module:sairoute,',
    'sairoute.Unknown', 'unknown', 'sairoute,', 'sairoute.RouteA\n',
    'sairoute;id', 'sairoute,unknown:saivlan',
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
    change(manifest)
    manifest_path = tmp_path / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        load_case_manifest(manifest_path)


@pytest.mark.parametrize('text', ['{', '{}', '[]',
                                  '{"schema_version":1,"schema_version":1}'])
def test_invalid_json_and_duplicate_keys(tmp_path, text):
    path = tmp_path / 'manifest.json'
    path.write_text(text)
    with pytest.raises(ValueError):
        load_case_manifest(path)


def test_file_errors_are_value_errors(tmp_path):
    with pytest.raises(ValueError):
        load_case_manifest(tmp_path / 'missing')


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


def test_generator_lists_cases_with_explicit_ptf_inputs(tmp_path):
    runner = tmp_path / 'ptf'
    test_dir = tmp_path / 'cases'
    test_dir.mkdir()
    runner.write_text(
        '#!/usr/bin/env python3\n'
        'import sys\n'
        'expected = ["--test-dir", {!r}, "--list-test-names"]\n'
        'if sys.argv[1:] != expected:\n'
        '    print("unexpected arguments: " + repr(sys.argv[1:]), file=sys.stderr)\n'
        '    raise SystemExit(7)\n'
        'print("sairoute.RouteB")\n'
        'print("saivlan.VlanA")\n'.format(str(test_dir)),
        encoding='utf-8')
    runner.chmod(0o755)

    assert manifest_generator.discover_test_names(runner, test_dir) == [
        'sairoute.RouteB', 'saivlan.VlanA',
    ]


def test_generator_reports_ptf_listing_failure(tmp_path):
    runner = tmp_path / 'ptf'
    test_dir = tmp_path / 'cases'
    test_dir.mkdir()
    runner.write_text(
        '#!/usr/bin/env python3\n'
        'import sys\n'
        'print("missing dependency", file=sys.stderr)\n'
        'raise SystemExit(3)\n', encoding='utf-8')
    runner.chmod(0o755)

    with pytest.raises(ValueError, match='PTF test listing failed.*missing dependency'):
        manifest_generator.discover_test_names(runner, test_dir)


def test_generator_preserves_existing_priorities(tmp_path):
    destination = tmp_path / 'manifest.json'
    destination.write_text(json.dumps({
        'schema_version': 2,
        'source_identity': {'repo': 'vendor/SAI'},
        'modules': {
            'sairoute': {'cases': {
                'RouteA': {'priority': 'P0'},
                'Removed': {'priority': 'P1'},
            }},
        },
    }))

    generated = manifest_generator.generate_manifest(
        ['sairoute.RouteA', 'sairoute.RouteB'], destination)

    assert generated['source_identity'] == {'repo': 'vendor/SAI'}
    assert generated['modules']['sairoute']['cases'] == {
        'RouteA': {'priority': 'P0'},
        'RouteB': {'priority': 'P2'},
    }


def test_manifest_cli_exposes_only_concrete_inputs():
    parser = manifest_generator.build_parser()
    options = {action.dest for action in parser._actions}

    assert {'ptf_runner', 'test_dir', 'test_name_list'} <= options
    assert not {'sai_root', 'output', 'source_manifest', 'priority'} & options


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


def test_main_reads_optional_test_name_list(tmp_path, monkeypatch, manifest):
    discovered = tmp_path / 'names.txt'
    discovered.write_text('sairoute.RouteA\n')
    output = tmp_path / 'manifest.json'
    output.write_text(json.dumps(manifest))
    monkeypatch.setattr(manifest_generator, 'DEFAULT_MANIFEST', output)

    assert manifest_generator.main([
        '--test-name-list', str(discovered),
    ]) == 0
    assert load_case_manifest(output)['modules'] == {
        'sairoute': {'cases': {'RouteA': {'priority': 'P2'}}},
    }
