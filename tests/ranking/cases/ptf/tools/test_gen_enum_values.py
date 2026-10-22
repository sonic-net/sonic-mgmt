#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for gen_enum_values.py.

The reverse map must be keyed by (enum type, value): the same numeric value is
reused across different SAI enums, so a value-only key would collide.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gen_enum_values.py')

HEADER = '''
typedef enum _sai_packet_action_t
{
    SAI_PACKET_ACTION_DROP,
    SAI_PACKET_ACTION_FORWARD,
    SAI_PACKET_ACTION_COPY,
} sai_packet_action_t;

typedef enum _sai_vlan_flood_control_type_t
{
    SAI_VLAN_FLOOD_CONTROL_TYPE_ALL,
    SAI_VLAN_FLOOD_CONTROL_TYPE_NONE,
} sai_vlan_flood_control_type_t;

typedef enum _sai_acl_stage_t
{
    SAI_ACL_STAGE_INGRESS = 0,
    SAI_ACL_STAGE_EGRESS,
    SAI_ACL_STAGE_START = SAI_ACL_STAGE_INGRESS,
    SAI_ACL_STAGE_END,
} sai_acl_stage_t;
'''


class GenEnumValuesTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='gen_enum_values_')
        self.inc = os.path.join(self.tmp, 'inc')
        os.makedirs(self.inc)
        with open(os.path.join(self.inc, 'saitypes.h'), 'w') as f:
            f.write(HEADER)
        self.out = os.path.join(self.tmp, 'enum_values.json')

    def _run(self):
        r = subprocess.run(
            [sys.executable, TOOL, '--inc', self.inc, '--out', self.out],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.out) as f:
            return json.load(f)

    def test_implicit_values_start_at_zero_and_increment(self):
        m = self._run()
        self.assertEqual(m['sai_packet_action_t']['0'], 'SAI_PACKET_ACTION_DROP')
        self.assertEqual(m['sai_packet_action_t']['1'], 'SAI_PACKET_ACTION_FORWARD')
        self.assertEqual(m['sai_packet_action_t']['2'], 'SAI_PACKET_ACTION_COPY')

    def test_same_value_in_two_enums_does_not_collide(self):
        m = self._run()
        self.assertEqual(m['sai_packet_action_t']['0'], 'SAI_PACKET_ACTION_DROP')
        self.assertEqual(m['sai_vlan_flood_control_type_t']['0'],
                         'SAI_VLAN_FLOOD_CONTROL_TYPE_ALL')

    def test_explicit_value_respected(self):
        m = self._run()
        self.assertEqual(m['sai_acl_stage_t']['0'], 'SAI_ACL_STAGE_INGRESS')
        self.assertEqual(m['sai_acl_stage_t']['1'], 'SAI_ACL_STAGE_EGRESS')

    def test_sentinels_excluded(self):
        """_START/_END aliases must not shadow real members."""
        m = self._run()
        names = set(m['sai_acl_stage_t'].values())
        self.assertNotIn('SAI_ACL_STAGE_START', names)
        self.assertNotIn('SAI_ACL_STAGE_END', names)


if __name__ == '__main__':
    unittest.main()
