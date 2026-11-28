import json

import pytest

from tests.ranking.cases import generate_attr_map


ADAPTER = '''
def sai_thrift_create_vlan(client, vlan_id=None, learn_disable=None):
    if vlan_id is not None:
        value = sai_thrift_attribute_value_t(u16=vlan_id)
        attr = sai_thrift_attribute_t(id=SAI_VLAN_ATTR_VLAN_ID, value=value)
    if learn_disable is not None:
        value = sai_thrift_attribute_value_t(booldata=learn_disable)
        attr = sai_thrift_attribute_t(id=SAI_VLAN_ATTR_LEARN_DISABLE, value=value)

def sai_thrift_get_vlan_attribute(client, vlan_oid, vlan_id=None):
    if vlan_id is not None:
        attr = sai_thrift_attribute_t(id=SAI_VLAN_ATTR_VLAN_ID)
        value = sai_thrift_attribute_value_t(u16=vlan_id)

def sai_thrift_remove_vlan(client, vlan_oid):
    return client.sai_thrift_remove_vlan(vlan_oid)
'''


def test_generate_attr_map_uses_adapter_and_fixed_schema(tmp_path):
    adapter = tmp_path / 'sai_adapter.py'
    output = tmp_path / 'attr_map.json'
    adapter.write_text(ADAPTER)

    envelope = generate_attr_map.generate(adapter, output)

    assert json.loads(output.read_text()) == envelope
    assert envelope['entries']['sai_thrift_create_vlan|vlan_id'] == {
        'attr': 'SAI_VLAN_ATTR_VLAN_ID',
        'op': 'create',
        'order': 0,
        'union': 'u16',
    }
    assert envelope['entries'][
        'sai_thrift_get_vlan_attribute|vlan_id']['op'] == 'read'
    assert envelope['signatures']['sai_thrift_get_vlan_attribute'] == [
        'client', 'vlan_oid', 'vlan_id',
    ]


def test_generate_attr_map_rejects_adapter_without_mappings(tmp_path):
    adapter = tmp_path / 'sai_adapter.py'
    adapter.write_text('def sai_thrift_remove_vlan(client, oid):\n    return 0\n')

    with pytest.raises(ValueError, match='no attribute mappings'):
        generate_attr_map.generate(adapter, tmp_path / 'attr_map.json')


def test_attr_map_cli_exposes_only_adapter_input():
    options = {action.dest for action in generate_attr_map.build_parser()._actions}

    assert 'adapter' in options
    assert not {'sai_root', 'output', 'out'} & options
