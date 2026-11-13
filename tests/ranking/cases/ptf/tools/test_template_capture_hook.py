#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The capture hook lives in the codegen template, so guard it there.

sai_adapter.py is generated from meta/templates/sai_adapter_utils.tt, and the
invocation_logger block is pure literal text -- no template variables -- so the
block in the template is byte-for-byte what lands in the adapter. That lets this
test lift the block straight out of the template and exercise it.

Why the hook belongs there: inside invocation_logger, func is the undecorated
function, so func.__name__ and inspect.getargspec(func) are the real name and
the real parameter order. An outer wrapper sees neither -- the community
decorator has no functools.wraps, so the name reads 'inner_logger', and the
signature reads (*args, **kwargs).
"""
import os
import re
import sys
import unittest

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PTF_DIR = os.path.dirname(TOOLS_DIR)
SAI_DIR = os.path.dirname(PTF_DIR)
TEMPLATE = os.path.join(SAI_DIR, 'meta', 'templates', 'sai_adapter_utils.tt')
sys.path.insert(0, PTF_DIR)

import sai_capture                                             # noqa: E402

ATTR_MAP = {
    'entries': {
        'sai_thrift_set_vlan_attribute|max_learned_addresses': {
            'attr': 'SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES', 'union': 'u32',
            'order': 0, 'op': 'set'},
        'sai_thrift_set_vlan_attribute|learn_disable': {
            'attr': 'SAI_VLAN_ATTR_LEARN_DISABLE', 'union': 'booldata',
            'order': 1, 'op': 'set'},
    },
    # Deliberately absent: the hook derives the parameter order from the
    # function itself, so it needs no signature table.
}


def load_template_logger():
    """Exec the template's invocation_logger block and return it."""
    with open(TEMPLATE, encoding='utf-8') as f:
        text = f.read()
    start = text.index('[%- BLOCK invocation_logger_func -%]')
    end = text.index('[%- END -%]', start)
    body = text[start:end].split('-%]', 1)[1]
    if re.search(r'\[%.*?%\]', body):
        raise AssertionError('block gained a template variable; it is no longer '
                             'identical to the generated adapter')
    import inspect
    import logging
    namespace = {'inspect': inspect, 'logging': logging,
                 'sai_capture': sai_capture}
    exec(body, namespace)                       # noqa: S102 - template payload
    return namespace['invocation_logger']


class TemplateCaptureHookTest(unittest.TestCase):

    def setUp(self):
        self.invocation_logger = load_template_logger()
        self.rows = []
        sai_capture.reset()
        sai_capture.load_map_dict(ATTR_MAP)
        sai_capture.set_case('saivlan', 'ForwardingTest')
        sai_capture.set_sink(self.rows.append)

        def sai_thrift_set_vlan_attribute(client, vlan_oid,
                                          max_learned_addresses=None,
                                          learn_disable=None):
            return 'ok'

        self.wrapped = self.invocation_logger(sai_thrift_set_vlan_attribute)

    def test_records_the_attr_the_call_carries(self):
        self.wrapped(None, 0xdeadbeef, learn_disable=True)
        self.assertEqual(self.rows, [
            {'case': 'saivlan.ForwardingTest',
             'attr': 'SAI_VLAN_ATTR_LEARN_DISABLE', 'op': 'set',
             'value': True}])

    def test_positional_object_id_is_not_recorded_as_an_attr(self):
        """The hook reads the real signature, so vlan_oid stays vlan_oid."""
        self.wrapped(None, 0xdeadbeef, learn_disable=True)
        self.assertNotIn('SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES',
                         [r['attr'] for r in self.rows])

    def test_positionally_passed_attr_is_recorded(self):
        self.wrapped(None, 0xdeadbeef, 4096)
        self.assertEqual([r['attr'] for r in self.rows],
                         ['SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES'])

    def test_return_value_is_passed_through(self):
        self.assertEqual(self.wrapped(None, 0xdeadbeef, learn_disable=True),
                         'ok')

    def test_capture_failure_does_not_break_the_call(self):
        def boom(row):
            raise RuntimeError('sink down')

        sai_capture.set_sink(boom)
        self.assertEqual(self.wrapped(None, 0xdeadbeef, learn_disable=True),
                         'ok')

    def test_absent_capture_module_is_tolerated(self):
        """A plain SAI checkout has no sai_capture; the adapter must still run."""
        with open(TEMPLATE, encoding='utf-8') as f:
            text = f.read()
        self.assertIn('except ImportError:', text)
        self.assertIn('sai_capture = None', text)
        self.assertIn('if sai_capture is not None:', text)


if __name__ == '__main__':
    unittest.main()
