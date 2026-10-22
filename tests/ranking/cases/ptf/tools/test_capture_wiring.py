#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""End-to-end wiring: adapter call -> case JSON -> capability verdict.

The unit tests cover each stage in isolation, which cannot show that the stages
are actually connected. This exercises the path sai_base_test wires up: install
the wrappers, point the sink at a real TestResultCollector, call the adapter,
write the JSON, and let build_capability.py flip the cell.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PTF_DIR = os.path.dirname(TOOLS_DIR)
BUILD_CAPABILITY = os.path.join(TOOLS_DIR, 'build_capability.py')
sys.path.insert(0, PTF_DIR)

import sai_capture                                             # noqa: E402
from sai_test_result import TestResultCollector as ResultCollector  # noqa: E402

ATTR = 'SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION'
ENUM = 'sai_packet_action_t'
ATTR_MAP = {
    'entries': {
        'sai_thrift_create_route_entry|packet_action': {
            'attr': ATTR, 'op': 'create', 'order': 0, 'union': 's32'},
    },
    'signatures': {
        'sai_thrift_create_route_entry': ['client', 'route_entry',
                                          'packet_action'],
    },
}
ENUM_VALUES = {ENUM: {'0': 'SAI_PACKET_ACTION_DROP',
                      '4': 'SAI_PACKET_ACTION_TRAP'}}


def skeleton(values):
    return {'schema_version': 2, 'denominator': len(values),
            'cells': [{'module': 'sairoute', 'attr': ATTR, 'op': 'create',
                       'value': v, 'enum_type': ENUM, 'shape': 'enum_scalar',
                       'applicable': True} for v in values]}


class CaptureWiringTest(unittest.TestCase):

    def setUp(self):
        sai_capture.reset()
        sai_capture.load_map_dict(ATTR_MAP)

        class Adapter(object):
            calls = []

        self.adapter = Adapter()
        self.adapter.sai_thrift_create_route_entry = (
            lambda client, route_entry, packet_action=None: 'oid')
        sai_capture.install(self.adapter)

    def _run_case(self, tmp, case_class, outcome, packet_action):
        """Mimic one case: identity, sink, an adapter call, then write JSON."""
        collector = ResultCollector(test_class_name=case_class,
                                        test_module_name='sairoute',
                                        output_dir=tmp)
        sai_capture.set_case('sairoute', case_class)
        sai_capture.set_sink(collector.record_attr_row)
        self.adapter.sai_thrift_create_route_entry(
            None, object(), packet_action=packet_action)
        collector.overall_result = outcome
        collector.write_json()
        return collector

    def _capability(self, tmp, results, values=('SAI_PACKET_ACTION_DROP',
                                                'SAI_PACKET_ACTION_TRAP')):
        skel = os.path.join(tmp, 'skeleton.json')
        enums = os.path.join(tmp, 'enum_values.json')
        ptf_results = os.path.join(tmp, 'ptf_results.json')
        out = os.path.join(tmp, 'capability.json')
        for path, doc in ((skel, skeleton(values)), (enums, ENUM_VALUES),
                          (ptf_results, results)):
            with open(path, 'w') as f:
                json.dump(doc, f)
        subprocess.check_call(
            [sys.executable, BUILD_CAPABILITY, '--json-dir', tmp,
             '--skeleton', skel, '--enum-values', enums,
             '--ptf-results', ptf_results, '--out', out],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(out) as f:
            return json.load(f)

    def test_touched_value_becomes_supported_untouched_stays_not_tested(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._run_case(tmp, 'dropRouteTest', 'PASS', 4)
            cap = self._capability(
                tmp, {'sairoute.dropRouteTest': 'OK'})
        by_value = {c['value']: c for c in cap['cells']}
        self.assertEqual(by_value['SAI_PACKET_ACTION_TRAP']['verdict'],
                         'supported')
        self.assertEqual(by_value['SAI_PACKET_ACTION_DROP']['verdict'],
                         'not_tested')
        self.assertEqual(cap['summary']['unjoined_records'], 0)

    def test_case_identity_follows_the_running_case(self):
        """Identity is module-level state, so a second case must not inherit the
        first one's records."""
        with tempfile.TemporaryDirectory() as tmp:
            first = self._run_case(tmp, 'dropRouteTest', 'PASS', 4)
            second = self._run_case(tmp, 'forwardRouteTest', 'PASS', 0)
        self.assertEqual([r['case'] for r in first.attr_rows],
                         ['sairoute.dropRouteTest'])
        self.assertEqual([r['case'] for r in second.attr_rows],
                         ['sairoute.forwardRouteTest'])

    def test_failing_case_marks_the_value_not_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._run_case(tmp, 'dropRouteTest', 'FAIL', 4)
            cap = self._capability(
                tmp, {'sairoute.dropRouteTest': 'FAILED: assertion'})
        by_value = {c['value']: c for c in cap['cells']}
        self.assertEqual(by_value['SAI_PACKET_ACTION_TRAP']['verdict'],
                         'not_supported')

    def test_repeated_touches_collapse_to_one_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = ResultCollector(test_class_name='dropRouteTest',
                                            test_module_name='sairoute',
                                            output_dir=tmp)
            sai_capture.set_case('sairoute', 'dropRouteTest')
            sai_capture.set_sink(collector.record_attr_row)
            for _ in range(5):
                self.adapter.sai_thrift_create_route_entry(
                    None, object(), packet_action=4)
            self.assertEqual(len(collector.attr_rows), 5)
            self.assertEqual(len(collector.to_dict()['attr_records']), 1)

    def test_adapter_return_value_is_passed_through(self):
        """Capture sits in the call path, so it must not alter the result."""
        self.assertEqual(
            self.adapter.sai_thrift_create_route_entry(
                None, object(), packet_action=4), 'oid')


if __name__ == '__main__':
    unittest.main()
