#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for build_capability.py.

Verdict comes purely from the case outcome (Q4 final): no SAI status, no phase.
Aggregation is pessimistic -- one failing source sinks the cell.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'build_capability.py')

SKELETON = {
    "cells": [
        {"module": "sairoute", "attr": "SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION",
         "op": "create", "value": "SAI_PACKET_ACTION_DROP",
         "enum_type": "sai_packet_action_t"},
        {"module": "sairoute", "attr": "SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION",
         "op": "create", "value": "SAI_PACKET_ACTION_TRAP",
         "enum_type": "sai_packet_action_t"},
        {"module": "sairoute", "attr": "SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION",
         "op": "create", "value": "SAI_PACKET_ACTION_LOG",
         "enum_type": "sai_packet_action_t"},
        {"module": "saiport", "attr": "SAI_PORT_ATTR_MTU",
         "op": "set", "value": None, "enum_type": None},
    ]
}
ENUMS = {"sai_packet_action_t": {"0": "SAI_PACKET_ACTION_DROP",
                                 "4": "SAI_PACKET_ACTION_TRAP",
                                 "5": "SAI_PACKET_ACTION_LOG"}}


class BuildCapabilityTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='build_cap_')
        self.jsondir = os.path.join(self.tmp, 'json')
        os.makedirs(self.jsondir)
        self._w('skeleton.json', SKELETON)
        self._w('enum_values.json', ENUMS)
        self.out = os.path.join(self.tmp, 'capability.json')

    def _w(self, name, obj):
        with open(os.path.join(self.tmp, name), 'w') as f:
            json.dump(obj, f)

    def _case(self, name, records):
        with open(os.path.join(self.jsondir, name + '.json'), 'w') as f:
            json.dump({"attr_records": records}, f)

    def _run(self, ptf_results):
        p = os.path.join(self.tmp, 'ptf_results.json')
        with open(p, 'w') as f:
            json.dump(ptf_results, f)
        r = subprocess.run([sys.executable, TOOL,
                            '--json-dir', self.jsondir,
                            '--skeleton', os.path.join(self.tmp, 'skeleton.json'),
                            '--enum-values', os.path.join(self.tmp, 'enum_values.json'),
                            '--ptf-results', p,
                            '--out', self.out],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.out) as f:
            return {(c['attr'], c['op'], c['value']): c for c in json.load(f)['cells']}

    def test_ok_case_marks_supported(self):
        self._case('sairoute_dropRouteTest',
                   [{"case": "sairoute.dropRouteTest",
                     "attr": "SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION",
                     "op": "create", "value": 4}])
        c = self._run({"sairoute.dropRouteTest": "OK"})
        k = ('SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION', 'create', 'SAI_PACKET_ACTION_TRAP')
        self.assertEqual(c[k]['verdict'], 'supported')

    def test_failed_case_marks_not_supported(self):
        self._case('saiacl_AclLogTest',
                   [{"case": "saiacl.AclLogTest",
                     "attr": "SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION",
                     "op": "create", "value": 5}])
        c = self._run({"saiacl.AclLogTest": "FAILED (failures=1)"})
        k = ('SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION', 'create', 'SAI_PACKET_ACTION_LOG')
        self.assertEqual(c[k]['verdict'], 'not_supported')

    def test_timeout_and_error_are_not_supported(self):
        self._case('a_T', [{"case": "a.T",
                            "attr": "SAI_PORT_ATTR_MTU", "op": "set", "value": None}])
        c = self._run({"a.T": "TIMEOUT"})
        self.assertEqual(c[('SAI_PORT_ATTR_MTU', 'set', None)]['verdict'],
                         'not_supported')
        c = self._run({"a.T": "FAILED (errors=1)"})
        self.assertEqual(c[('SAI_PORT_ATTR_MTU', 'set', None)]['verdict'],
                         'not_supported')

    def test_skipped_is_not_supported(self):
        """The adapter raises SkipTest when the chip answers NOT_SUPPORTED, so a
        skip that reached the attributes is the chip refusing, not absent
        evidence -- seen on FdbFlushTest, where flush_fdb_entries returned -2."""
        self._case('a_T', [{"case": "a.T",
                            "attr": "SAI_PORT_ATTR_MTU", "op": "set", "value": None}])
        c = self._run({"a.T": "OK (skipped=1)"})
        self.assertEqual(c[('SAI_PORT_ATTR_MTU', 'set', None)]['verdict'],
                         'not_supported')

    def test_hand_written_platform_skip_is_not_supported_too(self):
        """The suite's own skips say the same thing in words, e.g. saischeduler
        skipTest("sai_create_scheduler_group not supported on brcm"). Shown on a
        value-level cell: the rule applies per value, not just per attribute."""
        self._case('b_T', [{"case": "b.T",
                            "attr": "SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION",
                            "op": "create", "value": 4}])
        c = self._run({"b.T": "OK (skipped=1)"})
        k = ('SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION', 'create', 'SAI_PACKET_ACTION_TRAP')
        self.assertEqual(c[k]['verdict'], 'not_supported')

    def test_no_record_is_not_tested(self):
        c = self._run({})
        k = ('SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION', 'create', 'SAI_PACKET_ACTION_DROP')
        self.assertEqual(c[k]['verdict'], 'not_tested')
        self.assertEqual(c[k]['sources'], [])

    def test_pessimistic_aggregation_one_failure_sinks_cell(self):
        self._case('ok_case', [{"case": "m.OkCase",
                                "attr": "SAI_PORT_ATTR_MTU", "op": "set", "value": None}])
        self._case('bad_case', [{"case": "m.BadCase",
                                 "attr": "SAI_PORT_ATTR_MTU", "op": "set", "value": None}])
        c = self._run({"m.OkCase": "OK", "m.BadCase": "FAILED (failures=1)"})
        cell = c[('SAI_PORT_ATTR_MTU', 'set', None)]
        self.assertEqual(cell['verdict'], 'not_supported')
        self.assertEqual(len(cell['sources']), 2)

    def test_sources_carry_case_and_outcome(self):
        self._case('sairoute_dropRouteTest',
                   [{"case": "sairoute.dropRouteTest",
                     "attr": "SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION",
                     "op": "create", "value": 4}])
        c = self._run({"sairoute.dropRouteTest": "OK"})
        k = ('SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION', 'create', 'SAI_PACKET_ACTION_TRAP')
        self.assertEqual(c[k]['sources'],
                         [{'case': 'sairoute.dropRouteTest', 'outcome': 'OK'}])

    def test_join_miss_is_reported_not_silent(self):
        """A record whose case is absent from ptf_results must be counted."""
        self._case('ghost', [{"case": "m.Ghost",
                              "attr": "SAI_PORT_ATTR_MTU", "op": "set", "value": None}])
        p = os.path.join(self.tmp, 'ptf_results.json')
        with open(p, 'w') as f:
            json.dump({}, f)
        r = subprocess.run([sys.executable, TOOL,
                            '--json-dir', self.jsondir,
                            '--skeleton', os.path.join(self.tmp, 'skeleton.json'),
                            '--enum-values', os.path.join(self.tmp, 'enum_values.json'),
                            '--ptf-results', p, '--out', self.out],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.out) as f:
            doc = json.load(f)
        self.assertEqual(doc['summary']['unjoined_records'], 1)

    def test_value_reverse_lookup_uses_enum_type(self):
        """Numeric 0 must resolve via the cell's enum_type, not globally."""
        self._case('a_T', [{"case": "a.T",
                            "attr": "SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION",
                            "op": "create", "value": 0}])
        c = self._run({"a.T": "OK"})
        k = ('SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION', 'create', 'SAI_PACKET_ACTION_DROP')
        self.assertEqual(c[k]['verdict'], 'supported')


if __name__ == '__main__':
    unittest.main()
