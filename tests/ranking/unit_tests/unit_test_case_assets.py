import ast
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / 'case_manifest.json').read_text())


def test_each_selected_case_has_one_top_level_definition():
    for module, configuration in MANIFEST['modules'].items():
        tree = ast.parse((ROOT / 'cases' / (module + '.py')).read_text())
        classes = Counter(node.name for node in tree.body if isinstance(node, ast.ClassDef))
        for case in configuration['cases']:
            assert classes[case] == 1, '{}.{} has {} definitions'.format(module, case, classes[case])


def test_pfc_and_tc_mapping_cases_have_independent_selectors():
    tree = ast.parse((ROOT / 'cases' / 'saiqosmap.py').read_text())
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    expected = {'noPfcToPpgMappingPFC': 'QosTcToPriorityGroupTestPFC',
                'noPfcToPpgMapping': 'QosTcToPriorityGroupTestTC'}
    for name, base in expected.items():
        assert name in MANIFEST['modules']['saiqosmap']['cases']
        assert classes[name].bases[0].id == base


def test_restored_pfc_selector_is_a_candidate_only_for_attributes_it_sets():
    registry = json.loads((ROOT / 'cases' / 'ranking_test' / 'spec_registry.json').read_text())
    attrs = registry['_modules']['saiport']['attrs']
    candidates = {entry['attr'] for entry in attrs
                  if 'saiqosmap.noPfcToPpgMappingPFC' in
                  entry.get('operations', {}).get('set', {}).get('candidates', [])}
    assert candidates == {'SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP',
                          'SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP',
                          'SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP'}
