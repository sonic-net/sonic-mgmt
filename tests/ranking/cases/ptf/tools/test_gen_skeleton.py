#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for gen_skeleton.py (value-level capability skeleton)."""
import collections
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
GEN_SKELETON = os.path.join(TOOLS_DIR, 'gen_skeleton.py')
GEN_ENUM_VALUES = os.path.join(TOOLS_DIR, 'gen_enum_values.py')


class ValueLevelExpansionTest(unittest.TestCase):
    """Q1 mixed granularity: enum/bool expand per value, everything else stays
    at attr level; read never expands."""

    HEADER = '''
/**
 * @brief Packet action
 *
 * @type sai_packet_action_t
 * @flags CREATE_AND_SET
 */
SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION = SAI_ROUTE_ENTRY_ATTR_START,

/**
 * @brief MTU
 *
 * @type sai_uint32_t
 * @flags CREATE_AND_SET
 */
SAI_PORT_ATTR_MTU = 0x10,

/**
 * @brief Member list
 *
 * @type sai_object_list_t
 * @flags READ_ONLY
 */
SAI_VLAN_ATTR_MEMBER_LIST = 0x20,
'''
    ENUM = '''
typedef enum _sai_packet_action_t
{
    SAI_PACKET_ACTION_DROP,
    SAI_PACKET_ACTION_FORWARD,
    SAI_PACKET_ACTION_TRAP,
    SAI_PACKET_ACTION_DENY = SAI_PACKET_ACTION_DROP,
    SAI_PACKET_ACTION_CUSTOM_RANGE_BASE = 0x1000,
    SAI_PACKET_ACTION_MAX = 0x2000,
} sai_packet_action_t;
'''

    # One documented enum member of the fixture above, e.g.
    # "/** @brief ... */ SAI_PORT_ATTR_MTU = 0x10,".
    MEMBER_BLOCK_RE = re.compile(
        r'/\*\*(?:(?!\*/).)*?\*/\s*(SAI_[A-Z0-9_]+)[^,]*,', re.DOTALL)

    def _wrap_members(self, text):
        """Wrap bare attr members into the sai_<obj>_attr_t enums they belong to.

        The parser only harvests members whose name matches the prefix derived
        from the enclosing enum, so SAI_PORT_ATTR_MTU and
        SAI_VLAN_ATTR_MEMBER_LIST cannot share one enum block.
        """
        groups = collections.OrderedDict()
        for m in self.MEMBER_BLOCK_RE.finditer(text):
            enum = m.group(1).split('_ATTR_')[0].lower() + '_attr_t'
            groups.setdefault(enum, []).append(m.group(0))
        return '\n'.join('typedef enum _%s\n{\n%s\n} %s;\n'
                         % (enum, '\n'.join(blocks), enum)
                         for enum, blocks in groups.items())

    def _build(self, extra_header=''):
        """Run the enum-table then skeleton tools over a throw-away header tree."""
        with tempfile.TemporaryDirectory() as tmp:
            inc = os.path.join(tmp, 'inc')
            os.makedirs(inc)
            with open(os.path.join(inc, 'saitest.h'), 'w') as f:
                f.write(self._wrap_members(self.HEADER + extra_header))
                f.write(self.ENUM)
            enum_values = os.path.join(tmp, 'enum_values.json')
            subprocess.check_call(
                [sys.executable, GEN_ENUM_VALUES, '--inc', inc,
                 '--out', enum_values],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            out = os.path.join(tmp, 'skeleton.json')
            subprocess.check_call(
                [sys.executable, GEN_SKELETON, '--inc', inc,
                 '--enum-values', enum_values, '--out', out],
                stdout=subprocess.DEVNULL)
            with open(out) as f:
                data = json.load(f)
        self.assertEqual(data['schema_version'], 2)
        self.assertEqual(data['denominator'], len(data['cells']))
        return data['cells']

    def test_enum_attr_expands_on_create_and_set_only(self):
        cells = self._build()
        pa = [c for c in cells if c['attr'] == 'SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION']
        create = [c for c in pa if c['op'] == 'create']
        read = [c for c in pa if c['op'] == 'read']
        self.assertEqual(len(create), 3)                 # 3 enum values
        self.assertEqual(sorted(c['value'] for c in create),
                         ['SAI_PACKET_ACTION_DROP', 'SAI_PACKET_ACTION_FORWARD',
                          'SAI_PACKET_ACTION_TRAP'])
        self.assertEqual(len(read), 1)                   # read never expands
        self.assertIsNone(read[0]['value'])

    def test_non_enum_attr_stays_attr_level(self):
        cells = self._build()
        mtu = [c for c in cells if c['attr'] == 'SAI_PORT_ATTR_MTU']
        self.assertEqual(len(mtu), 3)                    # create/set/read, no values
        self.assertTrue(all(c['value'] is None for c in mtu))

    def test_read_only_attr_has_read_cell_only(self):
        cells = self._build()
        ml = [c for c in cells if c['attr'] == 'SAI_VLAN_ATTR_MEMBER_LIST']
        self.assertEqual([c['op'] for c in ml], ['read'])

    def test_hostif_packet_attrs_excluded_from_denominator(self):
        cells = self._build(extra_header='''
/**
 * @brief Ingress port
 *
 * @type sai_object_id_t
 * @flags READ_ONLY
 */
SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT = 0x30,
''')
        self.assertFalse([c for c in cells
                          if c['attr'].startswith('SAI_HOSTIF_PACKET_ATTR_')])

    def test_every_declared_value_is_resolvable(self):
        """A value the enum table cannot name back is a cell nothing can ever mark
        supported, so the two tools must agree on what counts as a value."""
        with tempfile.TemporaryDirectory() as tmp:
            inc = os.path.join(tmp, 'inc')
            os.makedirs(inc)
            with open(os.path.join(inc, 'saitest.h'), 'w') as f:
                f.write(self._wrap_members(self.HEADER))
                f.write(self.ENUM)
            enum_values = os.path.join(tmp, 'enum_values.json')
            skeleton = os.path.join(tmp, 'skeleton.json')
            subprocess.check_call(
                [sys.executable, GEN_ENUM_VALUES, '--inc', inc,
                 '--out', enum_values],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call(
                [sys.executable, GEN_SKELETON, '--inc', inc,
                 '--enum-values', enum_values, '--out', skeleton],
                stdout=subprocess.DEVNULL)
            with open(enum_values) as f:
                enums = json.load(f)
            with open(skeleton) as f:
                cells = json.load(f)['cells']

        resolvable = {k: set(v.values()) for k, v in enums.items()}
        unreachable = [c for c in cells
                       if c['enum_type'] and c['value'] is not None
                       and c['value'] not in resolvable.get(c['enum_type'], ())]
        self.assertEqual(unreachable, [])
        sentinels = [c['value'] for c in cells if c['value']
                     and c['value'].endswith(('_START', '_END', '_RANGE_BASE',
                                              '_MAX', '_MIN'))]
        self.assertEqual(sentinels, [])


if __name__ == '__main__':
    unittest.main()
