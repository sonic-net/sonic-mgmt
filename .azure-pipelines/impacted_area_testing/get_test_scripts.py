#!/usr/bin/env python3

"""
    Scripts for getting test scripts in impacted area
    Example:
        python impacted_area_testing/get_test_scripts.py vrf,gnmi ../tests

    It will get all test scripts in specific impacted area.
"""
import os
import re
import logging
import json
import argparse
import functools
from natsort import natsorted
from constant import PR_TOPOLOGY_TYPE, EXCLUDE_TEST_SCRIPTS, CONTROL_PLANE_DEDUP_RULES

VPP_TOPOLOGY = "t1-lag-vpp"
VPP_CHECKER = "t1-lag-vpp_checker"


def topo_name_to_topo_checker(topo_name):
    pattern = re.compile(r'^(ciscovs-7nodes|ciscovs-5nodes|wan|wan-pub-isis|wan-com|wan-pub|wan-pub-cisco|wan-3link-tg|'
                         r't0|t0-52|t0-mclag|mgmttor|m0|mc0|mx|'
                         r't1|t1-lag|t1-56-lag|t1-64-lag|'
                         r'ptf|fullmesh|dualtor|t2|tgen|multidut-tgen|dpu|any|snappi|util|'
                         r't0-2vlans|t0-sonic|t1-multi-asic)$')
    match = pattern.match(topo_name)
    if match is None:
        logging.warning("Unsupported testbed type - {}".format(topo_name))
        return topo_name

    topo_type = match.group()
    if topo_type in ['mgmttor', 'm0', 'mc0', 'mx', 't0-52', 't0-mclag']:
        # certain testbed types are in 't0' category with different names.
        topo_type = 't0'
    elif topo_type in ['t1-lag', 't1-56-lag', 't1-64-lag']:
        topo_type = 't1'
    elif 't2' in topo_type:
        topo_type = 't2'

    topology_checker = topo_type + "_checker"

    return topology_checker


def distribute_scripts_to_PR_checkers(match, script_name, test_scripts_per_topology_checker):
    for topology in match.group(1).split(","):
        topology_mark = topology.strip().strip('"').strip("'")
        if topology_mark == "any":
            for key in ["t0_checker", "t1_checker", "t2_checker"]:
                if script_name not in test_scripts_per_topology_checker[key]:
                    test_scripts_per_topology_checker[key].append(script_name)
        else:
            topology_checker = topo_name_to_topo_checker(topology_mark)
            if topology_checker in test_scripts_per_topology_checker \
                    and script_name not in test_scripts_per_topology_checker[topology_checker]:
                test_scripts_per_topology_checker[topology_checker].append(script_name)


def load_vpp_test_scripts_allowlist():
    pr_test_scripts_path = os.path.abspath(os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "pr_test_scripts.yaml"
    ))
    try:
        import yaml
    except ImportError as e:
        raise Exception(
            "PyYAML is required to load {}".format(pr_test_scripts_path)
        ) from e

    try:
        with open(pr_test_scripts_path, "r") as f:
            pr_test_scripts = yaml.safe_load(f)
    except Exception as e:
        raise Exception(
            "Exception occurred while trying to load {}, error {}".format(
                pr_test_scripts_path, e
            )
        )

    if not isinstance(pr_test_scripts, dict) or VPP_TOPOLOGY not in pr_test_scripts:
        raise Exception(
            "Missing {} allowlist in {}".format(
                VPP_TOPOLOGY, pr_test_scripts_path
            )
        )

    vpp_scripts = pr_test_scripts[VPP_TOPOLOGY]
    if not isinstance(vpp_scripts, list):
        raise Exception(
            "{} allowlist in {} must be a list".format(
                VPP_TOPOLOGY, pr_test_scripts_path
            )
        )

    return vpp_scripts


def build_vpp_impacted_scripts(raw_impacted_scripts, vpp_allowlist):
    raw_impacted_scripts = set(raw_impacted_scripts)
    return [
        script
        for script in vpp_allowlist
        if script in raw_impacted_scripts
    ]


def collect_scripts_by_topology_type(features: str, location: str) -> dict:
    """
    This function collects all test scripts under the impacted area and category them by topology type.

    Args:
        Features: The impacted area defined by features
        Location: The location of test scripts

    Returns:
        Dict: A dict of test scripts categorized by topology type.
    """
    # Recursively find all files starting with "test_" and ending with ".py"
    # Note: The full path and name of files are stored in a list named "files"
    scripts = []

    for feature in features.split(","):
        feature_path = os.path.join(location, feature)
        for root, dirs, script in os.walk(feature_path):
            for s in script:
                if s.startswith("test_") and s.endswith(".py"):
                    scripts.append(os.path.join(root, s))
    scripts = natsorted(scripts)

    # Open each file and search for regex pattern
    pattern = re.compile(r"[^@]pytest\.mark\.topology\(([^\)]*)\)")

    # Init the dict to record the mapping of topology type and test scripts
    test_scripts_per_topology_checker = {}
    for topology_type in PR_TOPOLOGY_TYPE:
        test_scripts_per_topology_checker[topology_type] = []

    raw_impacted_scripts = []

    for s in scripts:
        # Remove prefix from file name:
        script_name = s[len(location) + 1:]
        if script_name in EXCLUDE_TEST_SCRIPTS:
            continue

        raw_impacted_scripts.append(script_name)

        try:
            with open(s, 'r') as script:
                for line in script:
                    # Get topology type of script from mark `pytest.mark.topology`
                    match = pattern.search(line)
                    if match:
                        distribute_scripts_to_PR_checkers(match, script_name, test_scripts_per_topology_checker)
                        break
        except Exception as e:
            raise Exception('Exception occurred while trying to get topology in {}, error {}'.format(s, e))

    vpp_scripts = build_vpp_impacted_scripts(
        raw_impacted_scripts,
        load_vpp_test_scripts_allowlist()
    )
    if vpp_scripts:
        test_scripts_per_topology_checker[VPP_CHECKER] = vpp_scripts

    return {k: v for k, v in test_scripts_per_topology_checker.items() if v}


def dedup_control_plane_tests(scripts_per_checker, location):
    """
    Remove control-plane tests from checkers based on CONTROL_PLANE_DEDUP_RULES.

    For each (keep_in, remove_from) rule, control-plane tests that appear in both
    checkers are removed from 'remove_from'. Data-plane tests (PTF/Scapy traffic)
    are always kept in both because forwarding behavior differs across topologies.

    Rules are evaluated against a snapshot of the original checker contents so that
    rule ordering does not affect the result.
    """
    valid_checkers = set(PR_TOPOLOGY_TYPE)
    validated_rules = []
    for keep_in, remove_from in CONTROL_PLANE_DEDUP_RULES:
        if keep_in not in valid_checkers:
            logging.warning("Dedup rule references unknown checker '%s', skipping", keep_in)
            continue
        if remove_from not in valid_checkers:
            logging.warning("Dedup rule references unknown checker '%s', skipping", remove_from)
            continue
        if keep_in == remove_from:
            logging.warning("Dedup rule has identical keep_in and remove_from '%s', skipping", keep_in)
            continue
        validated_rules.append((keep_in, remove_from))

    # Snapshot original checker contents so rules are order-independent
    original_contents = {k: set(v) for k, v in scripts_per_checker.items()}

    for keep_in, remove_from in validated_rules:
        keep_scripts = original_contents.get(keep_in, set())
        if not keep_scripts or remove_from not in scripts_per_checker:
            continue

        overlap = [s for s in scripts_per_checker[remove_from] if s in keep_scripts]
        if not overlap:
            continue

        data_plane_scripts = _detect_data_plane_tests(
            overlap, location
        )

        original_count = len(scripts_per_checker[remove_from])
        scripts_per_checker[remove_from] = [
            s for s in scripts_per_checker[remove_from]
            if s not in keep_scripts or s in data_plane_scripts
        ]
        deduped_count = original_count - len(scripts_per_checker[remove_from])
        if deduped_count > 0:
            dropped = [
                s for s in overlap if s not in data_plane_scripts
            ]
            logging.info(
                "Deduped %d control-plane tests from %s "
                "(already in %s)",
                deduped_count, remove_from, keep_in
            )
            logging.debug(
                "Dedup %s: dropping %s", remove_from, dropped
            )

    # Remove empty checkers to avoid spawning empty PR jobs
    return {k: v for k, v in scripts_per_checker.items() if v}


# Patterns that indicate a test sends traffic through the data plane.
_TRAFFIC_PATTERN = re.compile(r"|".join([
    r"\bptfadapter\b",          # Packet send/receive adapter fixture
    r"\bptf_runner\b",          # Runs a PTF test script
    r"\bptf\.testutils\b",      # PTF send/verify utilities
    r"from\s+ptf\s+import",     # Direct PTF framework import
    r"import\s+ptf\b",          # Direct PTF framework import
    r"\bsend_packet\b",         # Sends a crafted packet
    r"\brun_ptf_script\b",      # Runs a PTF script
    r"\bsnappi\b",              # Snappi traffic generator
    r"\btgen_utils\b",          # Traffic generator utilities
    r"\bcraft_packet\b",        # Packet crafting helper
    r"\bpktgen\b",              # Kernel packet generator
    r"from\s+scapy\b",          # Scapy packet library import
    r"import\s+scapy\b",        # Scapy packet library import
    r"\bixnetwork\w*\b",           # Ixia IxNetwork traffic generator
    r"\btcpreplay\b",           # TCP replay traffic tool
]))


def _read_file_safe(filepath):
    """Read file content, returning None on any error."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except (IOError, OSError, UnicodeDecodeError):
        logging.warning("Could not read %s, treating as data-plane test (safe default)", filepath)
        return None


def _resolve_local_imports(filepath, content, location=""):
    """Find Python modules imported from the same package or tests.*.

    Args:
        filepath: absolute path to the Python file being scanned
        content: file content as a string
        location: base directory of the test tree (repo root / tests dir);
                  used to resolve absolute ``tests.X.Y`` imports
    """
    resolved = []
    directory = os.path.dirname(filepath)
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # from .module import ... (single-dot relative)
        match = re.match(r"from\s+\.(\w+)\s+import", line)
        if match:
            mod = os.path.join(directory, match.group(1) + ".py")
            if os.path.isfile(mod):
                resolved.append(mod)
            pkg_init = os.path.join(
                directory, match.group(1), "__init__.py"
            )
            if os.path.isfile(pkg_init):
                resolved.append(pkg_init)

        # from ..module import ... (parent-relative imports)
        match = re.match(r"from\s+\.\.(\w+)\s+import", line)
        if match:
            parent = os.path.dirname(directory)
            if parent:
                mod = os.path.join(
                    parent, match.group(1) + ".py"
                )
                if os.path.isfile(mod):
                    resolved.append(mod)
                pkg_init = os.path.join(
                    parent, match.group(1), "__init__.py"
                )
                if os.path.isfile(pkg_init):
                    resolved.append(pkg_init)

        # §3: from . import name  OR  from .. import name
        # (bare relative imports without a module name after dots)
        match = re.match(r"from\s+(\.+)\s+import\s+(\w+)", line)
        if match:
            dots = match.group(1)
            name = match.group(2)
            base = directory
            for _ in range(len(dots) - 1):
                base = os.path.dirname(base)
            mod = os.path.join(base, name + ".py")
            if os.path.isfile(mod):
                resolved.append(mod)
            pkg_init = os.path.join(base, name, "__init__.py")
            if os.path.isfile(pkg_init):
                resolved.append(pkg_init)

        # from tests.feature.module import ... OR import tests.feature
        # Handles both:
        #   import tests.common.helpers → tests/common/helpers.py
        #   from tests.common import helpers → tests/common.py AND
        #       tests/common/helpers.py
        match = re.match(
            r"from\s+(tests\.\S+?)\s+import\s+(\w+)", line
        )
        if match:
            pkg_path = match.group(1).replace(".", os.sep)
            imp_name = match.group(2)
            if location:
                tests_root = os.path.dirname(location)
                base = os.path.join(tests_root, pkg_path)
            else:
                base = pkg_path
            # Try package file: tests/common.py
            mod = base + ".py"
            if os.path.isfile(mod):
                resolved.append(mod)
            # Try package __init__: tests/common/__init__.py
            pkg_init = os.path.join(base, "__init__.py")
            if os.path.isfile(pkg_init):
                resolved.append(pkg_init)
            # Try imported name: tests/common/helpers.py
            sub_mod = os.path.join(base, imp_name + ".py")
            if os.path.isfile(sub_mod):
                resolved.append(sub_mod)
            # Try imported name as package
            sub_init = os.path.join(
                base, imp_name, "__init__.py"
            )
            if os.path.isfile(sub_init):
                resolved.append(sub_init)
        else:
            # import tests.common.helpers (no 'from')
            match = re.match(
                r"import\s+(tests\.\S+)", line
            )
            if match:
                rel_mod = match.group(1).replace(
                    ".", os.sep
                ) + ".py"
                if location:
                    tests_root = os.path.dirname(location)
                    mod = os.path.join(tests_root, rel_mod)
                else:
                    mod = rel_mod
                if os.path.isfile(mod):
                    resolved.append(mod)
                pkg_dir = mod[:-3]
                pkg_init = os.path.join(
                    pkg_dir, "__init__.py"
                )
                if os.path.isfile(pkg_init):
                    resolved.append(pkg_init)

    return resolved


def _collect_conftest_files(filepath, location):
    """Collect conftest.py files from the test directory up to location.

    pytest discovers fixtures by walking up the directory tree; a test
    file implicitly imports fixtures from every conftest.py above it.
    """
    conftests = []
    directory = os.path.dirname(os.path.abspath(filepath))
    location_abs = os.path.abspath(location) if location else ""
    while location_abs and directory.startswith(location_abs):
        conftest = os.path.join(directory, "conftest.py")
        if os.path.isfile(conftest) and conftest != os.path.abspath(filepath):
            conftests.append(conftest)
        if directory == location_abs:
            break
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    return conftests


@functools.lru_cache(maxsize=None)
def _has_traffic_pattern(filepath, location="", depth=0):
    """Check if a file or its imports (up to 2 levels) contain traffic
    patterns.

    Returns True (data-plane) if the file is unreadable — safe default
    to avoid accidentally deduping tests we can't inspect.

    At depth 0 (the test file itself), also scans conftest.py files in
    the directory chain up to *location*, since pytest fixtures defined
    there are implicitly available to the test.
    """
    if depth > 2:
        return False
    content = _read_file_safe(filepath)
    if content is None:
        return True  # Unreadable → assume data-plane (keep in both)
    if _TRAFFIC_PATTERN.search(content):
        return True

    # §1: At depth 0, scan conftest.py chain for traffic patterns
    if depth == 0 and location:
        for conftest in _collect_conftest_files(filepath, location):
            if _has_traffic_pattern(conftest, location, depth + 1):
                return True

    for imported in _resolve_local_imports(filepath, content, location):
        if _has_traffic_pattern(imported, location, depth + 1):
            return True
    return False


def _detect_data_plane_tests(script_names, location):
    """
    Detect which scripts are data-plane tests by scanning for traffic
    patterns.

    Checks the test file itself, its conftest.py chain, and modules it
    imports (up to 2 levels deep) for patterns like ptfadapter,
    ptf_runner, send_packet, snappi, scapy, etc.

    Args:
        script_names: list of script paths relative to location
        location: base directory of test scripts

    Returns:
        set of script names that are data-plane tests
    """
    _has_traffic_pattern.cache_clear()
    data_plane = set()
    for script_name in script_names:
        filepath = os.path.join(location, script_name)
        if _has_traffic_pattern(filepath, location):
            data_plane.add(script_name)
            logging.debug(
                "Data-plane test detected: %s", script_name
            )
    if data_plane:
        logging.info(
            "Detected %d data-plane tests in overlap "
            "(kept on both checkers)", len(data_plane)
        )
    return data_plane


def main(features, location):
    scripts_list = collect_scripts_by_topology_type(features, location)
    scripts_list = dedup_control_plane_tests(scripts_list, location)
    print(json.dumps(scripts_list))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", help="Impacted area", nargs='?', const="", type=str, default="")
    parser.add_argument("--location", help="The location of folder `tests`", type=str, default="")
    args = parser.parse_args()

    features = args.features
    location = args.location
    main(features, location)
