#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for sai_capture value extraction and case attribution.

Pure logic: no sai_adapter import, no device. The thrift structs are replaced
by minimal stand-ins carrying the same field names verified against ttypes.py.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import sai_capture  # noqa: E402


class Struct(object):
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class ValueExtractionTest(unittest.TestCase):

    def test_scalar_enum(self):
        self.assertEqual(sai_capture.extract_values('s32', 4), [4])

    def test_bool(self):
        self.assertEqual(sai_capture.extract_values('booldata', True), [True])

    def test_enum_list_iterates_int32list(self):
        raw = Struct(count=3, int32list=[1, 2, 5])
        self.assertEqual(sai_capture.extract_values('s32list', raw), [1, 2, 5])

    def test_enum_list_empty_is_empty(self):
        self.assertEqual(
            sai_capture.extract_values('s32list', Struct(count=0, int32list=[])), [])

    def test_nested_aclaction_reads_parameter(self):
        raw = Struct(enable=True, parameter=Struct(s32=6, booldata=None))
        self.assertEqual(sai_capture.extract_values('aclaction', raw), [6])

    def test_nested_aclfield_reads_data_not_parameter(self):
        raw = Struct(enable=True, mask=Struct(s32=None), data=Struct(s32=2, booldata=None))
        self.assertEqual(sai_capture.extract_values('aclfield', raw), [2])

    def test_nested_disabled_records_no_value(self):
        raw = Struct(enable=False, parameter=Struct(s32=6))
        self.assertEqual(sai_capture.extract_values('aclaction', raw), [])

    def test_non_value_level_union_yields_single_none(self):
        """oid / ip6 / objlist stay attr-level: one cell, no value."""
        self.assertEqual(sai_capture.extract_values('oid', 12345), [None])


class RecordTest(unittest.TestCase):

    def setUp(self):
        sai_capture.reset()
        self.rows = []
        sai_capture.set_sink(self.rows.append)
        sai_capture.load_map_dict({'entries': {
            'sai_thrift_create_vlan|vlan_id': {
                'attr': 'SAI_VLAN_ATTR_VLAN_ID', 'union': 'u16',
                'order': 0, 'op': 'create'},
            'sai_thrift_create_vlan|learn_disable': {
                'attr': 'SAI_VLAN_ATTR_LEARN_DISABLE', 'union': 'booldata',
                'order': 1, 'op': 'create'},
        }})

    def test_records_carry_case_identity(self):
        sai_capture.set_case('saivlan', 'ForwardingTest')
        sai_capture.record_call('sai_thrift_create_vlan',
                                {'vlan_id': 100, 'learn_disable': True})
        self.assertEqual(len(self.rows), 2)
        self.assertTrue(all(r['case'] == 'saivlan.ForwardingTest' for r in self.rows))

    def test_unmapped_kwargs_ignored(self):
        sai_capture.set_case('saivlan', 'ForwardingTest')
        sai_capture.record_call('sai_thrift_create_vlan',
                                {'client': object(), 'unknown_kwarg': 1})
        self.assertEqual(self.rows, [])

    def test_none_kwargs_ignored(self):
        sai_capture.set_case('saivlan', 'ForwardingTest')
        sai_capture.record_call('sai_thrift_create_vlan',
                                {'vlan_id': None, 'learn_disable': False})
        self.assertEqual([r['attr'] for r in self.rows],
                         ['SAI_VLAN_ATTR_LEARN_DISABLE'])

    def test_no_sink_is_noop(self):
        sai_capture.reset()
        sai_capture.set_case('saivlan', 'ForwardingTest')
        sai_capture.record_call('sai_thrift_create_vlan', {'vlan_id': 100})
        # nothing raised, nothing recorded anywhere

    def test_unknown_function_ignored(self):
        sai_capture.set_case('saivlan', 'ForwardingTest')
        sai_capture.record_call('sai_thrift_create_widget', {'size': 1})
        self.assertEqual(self.rows, [])

    def test_row_shape_has_no_phase_and_no_status(self):
        sai_capture.set_case('saivlan', 'ForwardingTest')
        sai_capture.record_call('sai_thrift_create_vlan', {'vlan_id': 100})
        self.assertEqual(set(self.rows[0]), {'case', 'attr', 'op', 'value'})


class InstallTest(unittest.TestCase):

    def setUp(self):
        sai_capture.reset()
        self.rows = []
        sai_capture.set_sink(self.rows.append)
        sai_capture.load_map_dict({'entries': {
            'sai_thrift_create_vlan|learn_disable': {
                'attr': 'SAI_VLAN_ATTR_LEARN_DISABLE', 'union': 'booldata',
                'order': 1, 'op': 'create'},
        }})
        sai_capture.set_case('saivlan', 'ForwardingTest')

    def test_install_uses_explicit_name_not_func_name(self):
        """The community @invocation_logger has no functools.wraps, so an
        already-decorated adapter function reports __name__ == 'inner_logger'.
        """
        adapter = Struct()

        def inner_logger(client, vlan_id, learn_disable=None):
            return 'called'

        self.assertEqual(inner_logger.__name__, 'inner_logger')
        adapter.sai_thrift_create_vlan = inner_logger

        self.assertEqual(sai_capture.install(
            adapter,
            {'sai_thrift_create_vlan': ['client', 'vlan_id', 'learn_disable']}), 1)
        self.assertEqual(adapter.sai_thrift_create_vlan(None, 100, True), 'called')
        self.assertEqual(self.rows, [{'case': 'saivlan.ForwardingTest',
                                      'attr': 'SAI_VLAN_ATTR_LEARN_DISABLE',
                                      'op': 'create', 'value': True}])
        # already wrapped -> not wrapped twice
        self.assertEqual(sai_capture.install(
            adapter, {'sai_thrift_create_vlan': ['client', 'vlan_id']}), 0)


class SignatureZipTest(unittest.TestCase):
    """install() zips positional args against the adapter's real signature."""

    ENVELOPE = {
        'entries': {
            'sai_thrift_set_vlan_attribute|max_learned_addresses': {
                'attr': 'SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES', 'union': 'u32',
                'order': 0, 'op': 'set'},
            'sai_thrift_set_vlan_attribute|learn_disable': {
                'attr': 'SAI_VLAN_ATTR_LEARN_DISABLE', 'union': 'booldata',
                'order': 1, 'op': 'set'},
        },
        'signatures': {
            'sai_thrift_set_vlan_attribute': [
                'client', 'vlan_oid', 'max_learned_addresses',
                'learn_disable'],
        },
    }

    def setUp(self):
        sai_capture.reset()
        self.rows = []
        sai_capture.set_sink(self.rows.append)
        sai_capture.load_map_dict(self.ENVELOPE)
        sai_capture.set_case('saivlan', 'ForwardingTest')
        self.adapter = Struct()
        self.adapter.sai_thrift_set_vlan_attribute = (
            lambda client, vlan_oid, max_learned_addresses=None,
            learn_disable=None: 'ok')
        self.assertEqual(sai_capture.install(self.adapter), 1)

    def test_positional_object_id_is_not_recorded_as_an_attr(self):
        self.adapter.sai_thrift_set_vlan_attribute(
            None, 0xdeadbeef, learn_disable=True)
        self.assertEqual([r['attr'] for r in self.rows],
                         ['SAI_VLAN_ATTR_LEARN_DISABLE'])

    def test_positionally_passed_attr_is_still_recorded(self):
        """196 call sites in the suite pass attrs positionally."""
        self.adapter.sai_thrift_set_vlan_attribute(None, 0xdeadbeef, 4096)
        self.assertEqual(self.rows, [
            {'case': 'saivlan.ForwardingTest',
             'attr': 'SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES',
             'op': 'set', 'value': None}])


if __name__ == '__main__':
    unittest.main()
