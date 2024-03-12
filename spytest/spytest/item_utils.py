
import os
import sys
import pytest
import tempfile

from collections import OrderedDict

from spytest import env
from spytest import tcmap

collected_items = dict()
nodeid_map = dict()
nodeid_test_names = dict()
selected_test_items = OrderedDict()
must_fail_items = OrderedDict()
community_unsupported = OrderedDict()
duplicate_test_names = dict()


def collect(item):
    nodeid = item.nodeid
    name = item.location[2]
    if name in collected_items:
        duplicate_test_names.setdefault(name, [collected_items[name].nodeid])
        duplicate_test_names[name].append(nodeid)
    collected_items[name] = item
    nodeid_test_names[nodeid] = name
    full_nodeid = env.get("SPYTEST_USE_FULL_NODEID", "0")
    if full_nodeid != "0":
        relpath = os.path.relpath(item.fspath)
        if nodeid.startswith("::"):
            nodeid = relpath + nodeid
            nodeid_test_names[nodeid] = name
            if full_nodeid == "1":
                item._nodeid = nodeid
        nodeid_map[name] = relpath + "::" + name
        nodeid_map[nodeid] = nodeid_map[name]
        nodeid_map[os.path.basename(relpath)] = relpath


def _append_repeat(item, dep_name):
    if not item.originalname or not item.name:
        return None, dep_name
    repeat = item.name.replace(item.originalname, "")
    return repeat, "{}{}".format(dep_name, repeat)


def _add_dependency(item, items, trace):
    marker = item.get_closest_marker("depends")
    if marker:
        for dep_name0 in marker.args:
            repeat, dep_name = _append_repeat(item, dep_name0)
            if dep_name in items:
                continue
            if dep_name in collected_items:
                add_item = collected_items[dep_name]
                _add_dependency(add_item, items, trace)
                if add_item not in items.values():
                    items[dep_name] = add_item
                continue
            # this is the case of using --count option
            trace("item {} dependency {} not found in collected".format(item, dep_name))
    if item not in items.values():
        items[item.location[2]] = item


def build_dependency(items, trace):
    selected_test_items.clear()
    for item in items:
        _add_dependency(item, selected_test_items, trace)
    items[:] = selected_test_items.values()
    if trace and duplicate_test_names:
        trace("DUPLICATE TEST NAMES")
        for duplicates in duplicate_test_names.values():
            trace(duplicates)
    return list(duplicate_test_names.values())


def find(func):
    return selected_test_items.get(func, None)


def map_nodeid(nodeid):
    return nodeid_map.get(nodeid, nodeid)


def get_func_name(nodeid):
    nodeid = nodeid_map.get(nodeid, nodeid)
    if nodeid in nodeid_test_names:
        func_name = nodeid_test_names[nodeid]
    else:
        func_name = None
    return func_name


def read_inventory_marker(item):
    def_release, def_feature, tcs = None, None, OrderedDict()
    for marker in item.iter_markers(name="inventory"):
        if marker.kwargs.get("testcases", []):
            continue
        def_release = def_release or marker.kwargs.get("release", None)
        def_feature = def_feature or marker.kwargs.get("feature", None)
    for marker in item.iter_markers(name="inventory"):
        for tc in marker.kwargs.get("testcases", []):
            ent = tcs.setdefault(tc, {})
            ent.setdefault("release", marker.kwargs.get("release", def_release))
            ent.setdefault("feature", marker.kwargs.get("feature", def_feature))
    if not tcs and def_release and def_feature:
        ent = tcs.setdefault(item.name, {})
        ent.setdefault("release", def_release)
        ent.setdefault("feature", def_feature)
    for tc, ent in tcs.items():
        tcmap.inventory(get_func_name(item.nodeid), tc, ent["release"], ent["feature"])


def read_known_markers(items, force_inv=False):
    must_fail_items.clear()
    for item in items:
        marker = item.get_closest_marker("must_fail")
        if marker:
            must_fail_items[item.nodeid] = None
    community_unsupported.clear()
    for item in items:
        marker = item.get_closest_marker("community_unsupported")
        if marker:
            community_unsupported[item.nodeid] = None
    if force_inv or env.match("SPYTEST_TCMAP_MARKERS", "1", "1"):
        for item in items:
            read_inventory_marker(item)


def has_marker(nodeid, marker="must_fail"):
    if marker == "must_fail":
        return bool(nodeid in must_fail_items)
    if marker == "community_unsupported":
        return bool(nodeid in community_unsupported)
    return False


class CollectPlugin:

    def __init__(self, tin, tex):
        self.collected_names = []
        self.collected_items = []
        self.tin = tin
        self.tex = tex

    def pytest_collection_modifyitems(self, items):
        for item in items:
            collect(item)
            if self.tin:
                if item.location[2] not in self.tin:
                    continue

            if self.tex:
                if item.location[2] in self.tex:
                    continue

            self.collected_names.append(item.location[2])
            self.collected_items.append(item)
        read_known_markers(items, True)


def _collect_items(fin, fex, tin, tex, *suffix, **kwargs):
    root_path = os.path.join(os.path.dirname(__file__), '..')
    root_path = os.path.abspath(root_path)
    test_path = os.path.join(root_path, "tests")
    hide = False
    hide = True
    plugin = CollectPlugin(tin, tex)
    args = []
    for f in fin:
        args.append(os.path.join(test_path, f))
    if not args:
        for f in fex:
            args.extend(["--ignore", os.path.join(test_path, f)])
    args.insert(0, "--collect-only")
    args.insert(0, "-s")
    args.insert(0, "--disable-pytest-warnings")
    args.extend(["--rootdir", test_path])
    for arg in suffix:
        args.append(arg)

    if hide:
        oldout, olderr = sys.stdout, sys.stderr
        filepath = tempfile.TemporaryFile(mode='w')
        sys.stdout = filepath
        sys.stderr = sys.stdout
    os.chdir(test_path)
    pytest.main(args, plugins=[plugin])
    if hide:
        sys.stdout.close()
        sys.stdout, sys.stderr = oldout, olderr

    return plugin.collected_items if kwargs.get("return_items", False) else plugin.collected_names


def collect_items(suite, tin, tex, *args, **kwargs):
    if suite:
        from spytest.framework import parse_suite_files
        _, fin, fex, tin, tex = parse_suite_files([suite], [])
    else:
        fin, fex = [], []
    tcmap.get()
    items = _collect_items(fin, fex, tin, tex, *args, **kwargs)
    return items
