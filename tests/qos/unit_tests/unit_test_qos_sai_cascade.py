"""Regressions for TestQosSai cascade suppression after a seed setup error."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.qos import conftest as qos_conftest

SEED = "qos/test_qos_sai.py::TestQosSai::testParameter[single_asic]"


def _fixturedef(scope, failed):
    error = (RuntimeError("setup broke"), None) if failed else None
    return SimpleNamespace(scope=scope, cached_result=(None, 0, error))


def _item(name, param_set="single_asic", seed=False, fixturedefs=()):
    item = Mock()
    item.cls = type("TestQosSai", (), {})
    item.nodeid = name
    item.keywords = {"fixture_seed": True} if seed else {}
    item.callspec.params = {"select_src_dst_dut_and_asic": param_set}
    item._fixtureinfo.name2fixturedefs = {
        "fixture{}".format(i): [fixturedef] for i, fixturedef in enumerate(fixturedefs)
    }
    return item


def _setup_call(exc):
    try:
        raise exc
    except type(exc):
        excinfo = pytest.ExceptionInfo.from_current()
    return SimpleNamespace(when="setup", excinfo=excinfo)


@pytest.fixture(autouse=True)
def clear_failures():
    qos_conftest.pytest_sessionstart(None)
    yield
    qos_conftest.pytest_sessionstart(None)


def _seed_setup_error(param_set="single_asic", fixturedefs=None, exc=None):
    if fixturedefs is None:
        fixturedefs = [_fixturedef("class", failed=True)]
    seed = _item(SEED, param_set, seed=True, fixturedefs=fixturedefs)
    qos_conftest.pytest_runtest_makereport(seed, _setup_call(exc or RuntimeError("setup broke")))


def test_shared_fixture_error_xfails_derivative():
    _seed_setup_error()
    with pytest.raises(pytest.xfail.Exception, match=r"testParameter\[single_asic\]"):
        qos_conftest.pytest_runtest_setup(_item("testQosSaiPfcXoffLimit"))


@pytest.mark.parametrize("exc", [pytest.skip.Exception("unsupported"), pytest.xfail.Exception("known")])
def test_intentional_seed_exclusion_is_not_recorded(exc):
    _seed_setup_error(fixturedefs=[_fixturedef("class", failed=True)], exc=exc)
    assert qos_conftest._qos_sai_fixture_failures == {}
    qos_conftest.pytest_runtest_setup(_item("testQosSaiPfcXoffLimit"))


def test_function_scoped_seed_error_is_not_recorded():
    _seed_setup_error(fixturedefs=[_fixturedef("class", failed=False), _fixturedef("function", failed=True)])
    assert qos_conftest._qos_sai_fixture_failures == {}
    qos_conftest.pytest_runtest_setup(_item("testQosSaiPfcXoffLimit"))


def test_failure_is_scoped_to_parameter_set():
    _seed_setup_error(param_set="single_asic")
    qos_conftest.pytest_runtest_setup(_item("testQosSaiPfcXoffLimit", param_set="multi_asic"))


def test_seed_is_never_suppressed():
    _seed_setup_error()
    qos_conftest.pytest_runtest_setup(_item(SEED, seed=True))


def test_sessionstart_clears_recorded_failures():
    _seed_setup_error()
    qos_conftest.pytest_sessionstart(None)
    qos_conftest.pytest_runtest_setup(_item("testQosSaiPfcXoffLimit"))
