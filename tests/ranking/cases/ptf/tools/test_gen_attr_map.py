#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for gen_attr_map.py.

The fixture reproduces every construction shape found in the real
sai_adapter.py: plain create, per-attr set, the two-branch get form, bulk
list form, the flush prefix (standard shape but non-CRUD name), and a
function that builds no attribute at all.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gen_attr_map.py')

ADAPTER = '''
def sai_thrift_create_vlan(client, vlan_id=None, learn_disable=None):
    attr_list = []
    if vlan_id is not None:
        attribute_value = sai_thrift_attribute_value_t(u16=vlan_id)
        attribute = sai_thrift_attribute_t(id=SAI_VLAN_ATTR_VLAN_ID,
                                           value=attribute_value)
        attr_list.append(attribute)

    if learn_disable is not None:
        attribute_value = sai_thrift_attribute_value_t(booldata=learn_disable)
        attribute = sai_thrift_attribute_t(id=SAI_VLAN_ATTR_LEARN_DISABLE,
                                           value=attribute_value)
        attr_list.append(attribute)
    return client.sai_thrift_create_vlan(attr_list)


def sai_thrift_set_vlan_attribute(client, vlan_oid, learn_disable=None):
    if learn_disable is not None:
        attr_value = sai_thrift_attribute_value_t(booldata=learn_disable)
        attr = sai_thrift_attribute_t(id=SAI_VLAN_ATTR_LEARN_DISABLE,
                                      value=attr_value)
        client.sai_thrift_set_vlan_attribute(vlan_oid, attr)
    return status


def sai_thrift_get_vlan_attribute(client, vlan_oid, vlan_id=None):
    attr_list = []
    if vlan_id is not None:
        if vlan_id == True:
            attribute = sai_thrift_attribute_t(id=SAI_VLAN_ATTR_VLAN_ID)
        else:
            attribute_value = sai_thrift_attribute_value_t(u16=vlan_id)
            attribute = sai_thrift_attribute_t(id=SAI_VLAN_ATTR_VLAN_ID,
                                               value=attribute_value)
        attr_list.append(attribute)
    return attrs


def sai_thrift_create_acl_entry(client, action_packet_action=None,
                                acl_action_type_list=None):
    attr_list = []
    if action_packet_action is not None:
        attribute_value = sai_thrift_attribute_value_t(aclaction=action_packet_action)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION,
                                           value=attribute_value)
        attr_list.append(attribute)

    if acl_action_type_list is not None:
        attribute_value = sai_thrift_attribute_value_t(s32list=acl_action_type_list)
        attribute = sai_thrift_attribute_t(id=SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST,
                                           value=attribute_value)
        attr_list.append(attribute)


def sai_thrift_bulk_create_next_hop_group_members(client, object_oid,
                                                  next_hop_group_id=None):
    attr_list = []
    for i in range(0, len(object_oid)):
        if next_hop_group_id is not None:
            attribute_value = sai_thrift_attribute_value_t(oid=next_hop_group_id[i])
            attribute = sai_thrift_attribute_t(
                id=SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID,
                value=attribute_value)
            attr_list.append(attribute)


def sai_thrift_flush_fdb_entries(client, bv_id=None, entry_type=None):
    attr_list = []
    if bv_id is not None:
        attribute_value = sai_thrift_attribute_value_t(oid=bv_id)
        attribute = sai_thrift_attribute_t(id=SAI_FDB_FLUSH_ATTR_BV_ID,
                                           value=attribute_value)
        attr_list.append(attribute)

    if entry_type is not None:
        attribute_value = sai_thrift_attribute_value_t(s32=entry_type)
        attribute = sai_thrift_attribute_t(id=SAI_FDB_FLUSH_ATTR_ENTRY_TYPE,
                                           value=attribute_value)
        attr_list.append(attribute)


def sai_thrift_remove_vlan(client, vlan_oid):
    return client.sai_thrift_remove_vlan(vlan_oid)


def sai_thrift_clear_port_stats(client, port_oid, counter_ids=None):
    return client.sai_thrift_clear_port_stats(port_oid, counter_ids)
'''


class GenAttrMapTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='gen_attr_map_')
        self.adapter = os.path.join(self.tmp, 'sai_adapter.py')
        with open(self.adapter, 'w') as f:
            f.write(ADAPTER)
        self.out = os.path.join(self.tmp, 'attr_map.json')

    def _run_envelope(self):
        r = subprocess.run(
            [sys.executable, TOOL, '--adapter', self.adapter, '--out', self.out],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.out) as f:
            return json.load(f)

    def _run(self):
        return self._run_envelope()['entries']

    def test_create_records_attr_union_order_op(self):
        m = self._run()
        e = m['sai_thrift_create_vlan|vlan_id']
        self.assertEqual(e['attr'], 'SAI_VLAN_ATTR_VLAN_ID')
        self.assertEqual(e['union'], 'u16')
        self.assertEqual(e['order'], 0)
        self.assertEqual(e['op'], 'create')
        self.assertEqual(m['sai_thrift_create_vlan|learn_disable']['order'], 1)

    def test_set_maps_to_set_op(self):
        m = self._run()
        e = m['sai_thrift_set_vlan_attribute|learn_disable']
        self.assertEqual(e['op'], 'set')
        self.assertEqual(e['union'], 'booldata')

    def test_get_two_branch_form_captures_union_and_read_op(self):
        m = self._run()
        e = m['sai_thrift_get_vlan_attribute|vlan_id']
        self.assertEqual(e['attr'], 'SAI_VLAN_ATTR_VLAN_ID')
        self.assertEqual(e['op'], 'read')
        self.assertEqual(e['union'], 'u16')

    def test_nested_and_list_unions_recorded(self):
        m = self._run()
        self.assertEqual(
            m['sai_thrift_create_acl_entry|action_packet_action']['union'],
            'aclaction')
        self.assertEqual(
            m['sai_thrift_create_acl_entry|acl_action_type_list']['union'],
            's32list')

    def test_bulk_form_nested_guard_captured(self):
        """Bulk builders wrap the standard guard block in a for loop."""
        m = self._run()
        e = m['sai_thrift_bulk_create_next_hop_group_members|next_hop_group_id']
        self.assertEqual(e['attr'],
                         'SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID')
        self.assertEqual(e['union'], 'oid')
        self.assertEqual(e['op'], 'create')

    def test_flush_prefix_is_not_dropped(self):
        """flush_fdb_entries uses the standard shape; only its prefix differs."""
        m = self._run()
        self.assertIn('sai_thrift_flush_fdb_entries|bv_id', m)
        self.assertEqual(
            m['sai_thrift_flush_fdb_entries|entry_type']['op'], 'create')

    def test_functions_without_attr_construction_absent(self):
        m = self._run()
        self.assertFalse([k for k in m if k.startswith('sai_thrift_remove_vlan|')])
        self.assertFalse([k for k in m if k.startswith('sai_thrift_clear_port_stats|')])


    def test_signatures_carry_the_real_positional_order(self):
        """The capture layer zips positional args against this, so the object id
        must sit where the adapter actually declares it."""
        env = self._run_envelope()
        sig = env['signatures']
        self.assertEqual(sig['sai_thrift_set_vlan_attribute'],
                         ['client', 'vlan_oid', 'learn_disable'])
        self.assertEqual(sig['sai_thrift_create_vlan'],
                         ['client', 'vlan_id', 'learn_disable'])
        # only functions that contribute entries are carried
        self.assertEqual(set(sig),
                         {k.split('|')[0] for k in env['entries']})


if __name__ == '__main__':
    unittest.main()
