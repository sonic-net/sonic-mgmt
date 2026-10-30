import copy
import json

import pytest

from tests.ranking.case_selection import load_case_manifest, select_ranking_cases
from tests.ranking.generate_case_manifest import build_manifest


def test_manifest_sorting_and_default_priority(manifest):
    assert manifest == {
        'schema_version': 1,
        'source_identity': {'repo': 'SAI', 'commit': 'a' * 40},
        'modules': {
            'sairoute': {'priority': 'P0', 'cases': ['RouteA', 'RouteB']},
            'saivlan': {'priority': 'P2', 'cases': ['VlanA']},
        },
    }


@pytest.mark.parametrize('selector,expected', [
    ({'explicit': 'sairoute.RouteB,sairoute.RouteA'},
     ['sairoute.RouteA', 'sairoute.RouteB']),
    ({'single': 'saivlan.VlanA'}, ['saivlan.VlanA']),
    ({'modules': 'sairoute'}, ['sairoute.RouteA', 'sairoute.RouteB']),
    ({'modules': 'saivlan,sairoute'},
     ['sairoute.RouteA', 'sairoute.RouteB', 'saivlan.VlanA']),
    ({'priority': 'P2'}, ['saivlan.VlanA']),
    ({'priority': 'P1'}, []),
])
def test_selectors_follow_manifest_order(manifest, selector, expected):
    assert select_ranking_cases(manifest, **selector) == expected


def test_loaded_manifest_order_is_preserved(manifest, tmp_path):
    manifest['modules']['sairoute']['cases'].reverse()
    manifest_path = tmp_path / 'manifest.json'
    identity_path = tmp_path / 'identity.json'
    manifest_path.write_text(json.dumps(manifest))
    identity_path.write_text(json.dumps(manifest['source_identity']))
    loaded = load_case_manifest(manifest_path, identity_path)
    assert loaded == manifest
    assert select_ranking_cases(loaded, modules='sairoute') == [
        'sairoute.RouteB', 'sairoute.RouteA',
    ]


@pytest.mark.parametrize('selector', [
    {}, {'single': ''}, {'single': '  '},
    {'single': 'saivlan.VlanA', 'priority': 'P2'},
    {'single': 'saivlan.VlanA', 'explicit': ''},
    {'explicit': 'sairoute.RouteA,'},
    {'explicit': 'sairoute.RouteA,sairoute.RouteA'},
    {'explicit': 'sairoute.RouteA, sairoute.RouteA'},
    {'single': 'sairoute.Unknown'}, {'modules': 'unknown'},
    {'modules': 'sairoute,sairoute'}, {'modules': 'sairoute,'},
    {'single': 'sairoute.RouteA;id'}, {'single': 'sairoute.RouteA\n'},
    {'single': 'sairoute.RouteA,saivlan.VlanA'}, {'priority': 'P3'},
    {'priority': True}, {'explicit': ['sairoute.RouteA']},
])
def test_invalid_selectors(manifest, selector):
    with pytest.raises(ValueError):
        select_ranking_cases(manifest, **selector)


def test_invalid_manifest_is_rejected_by_selection():
    with pytest.raises(ValueError):
        select_ranking_cases({}, single='sairoute.RouteA')


@pytest.mark.parametrize('change', [
    lambda m: m.update(schema_version=2),
    lambda m: m.update(schema_version=True),
    lambda m: m.update(modules=[]),
    lambda m: m.update(source_identity={}),
    lambda m: m['modules']['sairoute'].update(priority='P9'),
    lambda m: m['modules']['sairoute'].update(cases=['RouteA', 'RouteA']),
    lambda m: m['modules']['sairoute'].update(cases=['bad-name']),
    lambda m: m['modules']['sairoute'].update(cases=['RouteA;id']),
    lambda m: m['modules']['sairoute'].update(cases=[None]),
    lambda m: m['modules']['sairoute'].update(cases=[]),
    lambda m: m['modules'].update({'bad-module': {'priority': 'P2', 'cases': ['A']}}),
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


def test_generator_does_not_alias_identity():
    identity = {'repo': 'SAI', 'commit': 'a' * 40}
    result = build_manifest(['sairoute.RouteA'], identity, {})
    result['source_identity']['repo'] = 'changed'
    assert identity['repo'] == 'SAI'
