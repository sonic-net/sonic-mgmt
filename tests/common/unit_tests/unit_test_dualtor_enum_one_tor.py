import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

PLUGIN_PATH = Path(__file__).resolve().parents[1] / "plugins" / "dualtor_enum_one_tor" / "__init__.py"
DUTS = ["upper-tor", "lower-tor"]


def _load_plugin():
    spec = importlib.util.spec_from_file_location("dualtor_enum_one_tor", PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = _load_plugin()


def _item(test, **params):
    module = test.split("::", 1)[0]
    return SimpleNamespace(
        path=Path(plugin.TESTS_DIR) / module,
        nodeid="tests/{}[{}]".format(test, "-".join(str(value) for value in params.values())),
        callspec=SimpleNamespace(params=params),
    )


def _select(items, enabled_tests, explicit_ids=()):
    kept, deselected = plugin.select_test_cases(items, "upper-tor", DUTS, enabled_tests, explicit_ids)
    return [item.nodeid for item in kept], [item.nodeid for item in deselected]


def test_same_test_case_on_other_tor_deselected():
    items = [
        _item("bgp/test_bgp_fact.py::test_bgp_facts", enum_frontend_dut_hostname="upper-tor", enum_asic_index=None),
        _item("bgp/test_bgp_fact.py::test_bgp_facts", enum_frontend_dut_hostname="lower-tor", enum_asic_index=None),
        _item("qos/test_pfc_pause.py::test_no_pfc", enum_dut_lossless_prio="upper-tor|3"),
        _item("qos/test_pfc_pause.py::test_no_pfc", enum_dut_lossless_prio="lower-tor|3"),
        # No test case with priority 4 on the selected ToR
        _item("qos/test_pfc_pause.py::test_no_pfc", enum_dut_lossless_prio="lower-tor|4"),
    ]
    kept, deselected = _select(items, ["bgp/test_bgp_fact.py", "qos/test_pfc_pause.py::test_no_pfc"])
    assert kept == [
        "tests/bgp/test_bgp_fact.py::test_bgp_facts[upper-tor-None]",
        "tests/qos/test_pfc_pause.py::test_no_pfc[upper-tor|3]",
        "tests/qos/test_pfc_pause.py::test_no_pfc[lower-tor|4]",
    ]
    assert deselected == [
        "tests/bgp/test_bgp_fact.py::test_bgp_facts[lower-tor-None]",
        "tests/qos/test_pfc_pause.py::test_no_pfc[lower-tor|3]",
    ]


@pytest.mark.parametrize("enabled_tests, explicit_ids", [
    ([], ()),
    (["bgp/test_bgp_fact.py::test_other_test"], ()),
    (["bgp/test_bgp_fact.py"], ("test_bgp_facts[lower-tor-None]",)),
])
def test_test_case_on_other_tor_kept(enabled_tests, explicit_ids):
    items = [
        _item("bgp/test_bgp_fact.py::test_bgp_facts", enum_frontend_dut_hostname="upper-tor", enum_asic_index=None),
        _item("bgp/test_bgp_fact.py::test_bgp_facts", enum_frontend_dut_hostname="lower-tor", enum_asic_index=None),
    ]
    kept, deselected = _select(items, enabled_tests, explicit_ids)
    assert len(kept) == 2 and deselected == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
