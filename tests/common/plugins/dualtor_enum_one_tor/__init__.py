"""
Run the DUT-enumerated test cases of the tests listed in dualtor_enum_one_tor.yaml on one ToR of active-active
dualtor testbeds, like dualtor-aa and dualtor-aa-56, if --dualtor_enum_one_tor is passed to pytest.

Test cases parametrized with the enum DUT fixtures, like enum_dut_hostname, enum_frontend_dut_hostname or
enum_dut_lossless_prio, run once per ToR on dualtor testbeds. For the listed tests, a test case enumerated on
another ToR is deselected if the same test case is enumerated on the randomly selected ToR, which is the same
ToR as rand_selected_dut.
"""
import logging
import os

import pytest
import yaml

logger = logging.getLogger(__name__)

TESTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
ENABLED_TESTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dualtor_enum_one_tor.yaml")


def pytest_addoption(parser):
    parser.addoption("--dualtor_enum_one_tor", action="store_true", default=False,
                     help="On active-active dualtor testbeds, run the DUT-enumerated test cases of the tests listed in "
                          "tests/common/plugins/dualtor_enum_one_tor/dualtor_enum_one_tor.yaml on one ToR only")


def load_enabled_tests():
    with open(ENABLED_TESTS_FILE) as f:
        return [test for test in (yaml.safe_load(f) or []) if isinstance(test, str)]


def get_test_path(item):
    """Return the test path relative to tests/ without parameters, like bgp/test_bgp_fact.py::test_bgp_facts."""
    module_path = os.path.relpath(str(item.path), TESTS_DIR).replace(os.sep, "/")
    return module_path + "::" + item.nodeid.split("::", 1)[1].split("[", 1)[0]


def is_enabled(test_path, enabled_tests):
    return any(test_path == test or test_path.startswith(test + "::") for test in enabled_tests)


def get_enumerated_tor(item, test_path, duts):
    """
    Return the ToR the test case is enumerated on, and the test case key without the ToR.

    The enum DUT fixtures use the DUT hostname or "<DUT hostname>|<port, priority, etc>" as the parameter.
    """
    params = getattr(getattr(item, "callspec", None), "params", {})
    tors = set(value.split("|")[0] for name, value in params.items()
               if name.startswith("enum_") and isinstance(value, str) and value.split("|")[0] in duts)
    if len(tors) != 1:
        return None, None

    tor = tors.pop()
    case_params = []
    for name, value in params.items():
        if name.startswith("enum_") and isinstance(value, str) and value.split("|")[0] == tor:
            case_params.append((name, value[len(tor):]))
        else:
            case_params.append((name, repr(value)))
    return tor, (test_path, tuple(sorted(case_params)))


def select_test_cases(items, selected_tor, duts, enabled_tests, explicit_ids=()):
    """Split items into the test cases to run and the test cases on the other ToRs to deselect."""
    cases = []
    cases_on_selected_tor = set()
    for item in items:
        tor, case_key = None, None
        test_path = get_test_path(item)
        if is_enabled(test_path, enabled_tests):
            tor, case_key = get_enumerated_tor(item, test_path, duts)
        if tor == selected_tor:
            cases_on_selected_tor.add(case_key)
        cases.append((item, tor, case_key))

    kept, deselected = [], []
    for item, tor, case_key in cases:
        if (tor not in (None, selected_tor) and case_key in cases_on_selected_tor and
                item.nodeid.split("::", 1)[1] not in explicit_ids):
            deselected.append(item)
        else:
            kept.append(item)
    return kept, deselected


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(session, config, items):
    # trylast, so only the test cases left after the deselection by -k, -m, --deselect, etc are checked.
    if not config.getoption("--dualtor_enum_one_tor"):
        return

    enabled_tests = load_enabled_tests()
    if not any(is_enabled(get_test_path(item), enabled_tests) for item in items):
        return

    # Imported here as tests/conftest.py registers this plugin.
    from tests.conftest import get_tbinfo, set_rand_one_dut_hostname

    _, tbinfo = get_tbinfo(session)
    duts = tbinfo.get("duts", [])
    if "dualtor-aa" not in tbinfo.get("topo", {}).get("name", "") or len(duts) < 2:
        return

    selected_tor = set_rand_one_dut_hostname(session)
    # Keep the test cases explicitly selected with parameters, like test_bgp_fact.py::test_bgp_facts[dut-None].
    explicit_ids = set(arg.split("::", 1)[1] for arg in config.args if "::" in arg and "[" in arg)
    kept, deselected = select_test_cases(items, selected_tor, duts, enabled_tests, explicit_ids)
    if deselected:
        logger.info("Run the DUT-enumerated test cases on ToR %s only, deselect %s",
                    selected_tor, [item.nodeid for item in deselected])
        config.hook.pytest_deselected(items=deselected)
        items[:] = kept
