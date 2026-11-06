#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for record_spec, the single reporting entry point.

record_spec now hard-fails on an unregistered spec name, so these tests also
pin the registry itself: a name that is not there aborts the case instead of
quietly dropping the row from the report.
"""
import ast
import glob
import importlib
import importlib.abc
import importlib.machinery
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PTF_DIR = os.path.dirname(TOOLS_DIR)
SAI_DIR = os.path.dirname(PTF_DIR)
REGISTRY_PATH = os.path.join(PTF_DIR, 'spec_registry.json')
HEADER_PARSER = os.path.join(TOOLS_DIR, 'parse_sai_headers.py')
INC_DIRS = [os.path.join(SAI_DIR, 'inc'), os.path.join(SAI_DIR, 'experimental')]

EXPECTED_SPEC_COUNT = 1641
PERF_SPEC = 'ipv4_route_scale'
CAPABILITY_SPEC = 'SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID'

sys.path.insert(0, PTF_DIR)

# sai_base_test pulls in ptf / thrift / sai_thrift and the platform helpers,
# which only exist inside the PTF image; stub them so the import works here.
_STUB_ROOTS = ('ptf', 'thrift', 'sai_thrift', 'paramiko', 'sai_utils',
               'LogConfig', 'data_module', 'config', 'platform_helper')


class _StubModule(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
        # A class, so the stub also works as a base class or a decorator arg.
        attr = type(name, (object,), {})
        setattr(self, name, attr)
        return attr


class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        module = _StubModule(spec.name)
        module.__path__ = []
        return module

    def exec_module(self, module):
        pass


class _StubFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in _STUB_ROOTS:
            return None
        return importlib.machinery.ModuleSpec(fullname, _StubLoader())


def _import_sai_base_test():
    try:
        return importlib.import_module('sai_base_test')
    except Exception:
        sys.meta_path.insert(0, _StubFinder())
        for name in list(sys.modules):
            if name.split('.')[0] in _STUB_ROOTS:
                del sys.modules[name]
        return importlib.import_module('sai_base_test')


sai_base_test = _import_sai_base_test()
from sai_test_result import SpecRegistry, TestResultCollector  # noqa: E402


class Host(object):
    """Carries the real methods: SaiHelperBase.__init__ needs a live device."""

    record_spec = sai_base_test.SaiHelperBase.record_spec
    probe_get_capability = sai_base_test.SaiHelperBase.probe_get_capability
    _record_measurement = sai_base_test.SaiHelperBase._record_measurement

    def __init__(self, output_dir):
        self._spec_registry = SpecRegistry(REGISTRY_PATH)
        self._result_collector = TestResultCollector(
            test_class_name='recordSpecTest',
            test_module_name='test_record_spec',
            output_dir=output_dir)

    @property
    def results(self):
        return self._result_collector.spec_results


def _literal_spec_names():
    """Spec names written as literals at record_spec / probe call sites."""
    sources = (glob.glob(os.path.join(PTF_DIR, '*.py'))
               + glob.glob(os.path.join(PTF_DIR, 'platform_helper', '*.py')))
    found = []
    for path in sources:
        if os.path.basename(path) == 'sai_base_test.py':
            continue
        with open(path) as handle:
            tree = ast.parse(handle.read(), path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = getattr(node.func, 'attr', getattr(node.func, 'id', None))
            if name not in ('record_spec', 'probe_get_capability'):
                continue
            first = node.args[0]
            # Constant.value on py>=3.8, Str.s before that.
            literal = getattr(first, 'value', getattr(first, 's', None))
            if isinstance(literal, str):
                found.append((os.path.basename(path), node.lineno, literal))
    return found


class RecordSpecTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='record_spec_')
        self.host = Host(self.tmp)

    def test_unregistered_spec_name_aborts(self):
        with self.assertRaises(AssertionError):
            self.host.record_spec('no_such_spec', 'create', 1,
                                  actual_value=42)
        self.assertEqual(self.host.results, [])

    def test_registered_spec_takes_metadata_from_the_registry(self):
        self.host.record_spec(PERF_SPEC, 'create', 40000, actual_value=12345)
        entry, = self.host.results
        registry = self.host._spec_registry
        self.assertEqual(entry['actual_value'], 12345)
        self.assertEqual(entry['unit'], registry.get_unit(PERF_SPEC))
        self.assertNotEqual(entry['unit'], SpecRegistry.DEFAULT_UNIT)
        self.assertEqual(entry['result_type'],
                         registry.get_result_type(PERF_SPEC))
        self.assertEqual(entry['direction'], registry.get_direction(PERF_SPEC))

    def test_measure_context_manager_is_gone(self):
        self.assertFalse(hasattr(sai_base_test.SaiHelperBase, 'measure'))
        self.assertTrue(hasattr(sai_base_test.SaiHelperBase, 'record_spec'))

    def test_registry_file_is_loadable_and_complete(self):
        self.assertTrue(os.path.exists(REGISTRY_PATH), REGISTRY_PATH)
        with open(REGISTRY_PATH) as handle:
            data = json.load(handle)
        specs = [key for key in data if not key.startswith('_')]
        self.assertEqual(len(specs), EXPECTED_SPEC_COUNT)

    def test_probe_get_capability_spec_names_are_registered(self):
        self.host.probe_get_capability(CAPABILITY_SPEC, lambda: 7, 7)
        self.host.probe_get_capability(CAPABILITY_SPEC, lambda: 7, 8)
        supported, unsupported = self.host.results
        self.assertEqual((supported['actual_value'], supported['operation']),
                         (1, 'get'))
        self.assertEqual(unsupported['actual_value'], 0)
        self.assertEqual(supported['unit'],
                         self.host._spec_registry.get_unit(CAPABILITY_SPEC))

        for module, lineno, name in _literal_spec_names():
            self.assertTrue(self.host._spec_registry.is_known(name),
                            '%s:%d records unregistered spec %r'
                            % (module, lineno, name))

        # probe_get_capability is called with attr full names, so every attr the
        # headers declare must be registered or the hard check would explode.
        if all(os.path.isdir(path) for path in INC_DIRS):
            self._assert_every_header_attr_is_registered()

    def _assert_every_header_attr_is_registered(self):
        attr_db = os.path.join(self.tmp, 'attr_db.json')
        command = [sys.executable, HEADER_PARSER, '-o', attr_db]
        for path in INC_DIRS:
            command += ['--inc-dir', path]
        subprocess.check_call(command, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        with open(attr_db) as handle:
            attrs = json.load(handle)['attrs']
        missing = sorted(entry['attr'] for entry in attrs
                         if not self.host._spec_registry.is_known(
                             entry['attr']))
        self.assertEqual(missing, [])
        self.assertGreater(len(attrs), 1000)


if __name__ == '__main__':
    unittest.main()
