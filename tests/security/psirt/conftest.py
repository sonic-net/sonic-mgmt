import importlib

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--psirt-adapter-module",
        action="store",
        default=None,
        help="Python module providing the optional platform PSIRT adapter",
    )


@pytest.fixture(scope="session")
def psirt_adapter(pytestconfig):
    module_name = pytestconfig.getoption("--psirt-adapter-module")
    if not module_name:
        pytest.skip("BLOCKED: no platform PSIRT adapter configured")

    module = importlib.import_module(module_name)
    factory = getattr(module, "get_psirt_adapter", None)
    if factory is None:
        pytest.fail("PSIRT adapter module must define get_psirt_adapter()")
    adapter = factory()
    if not callable(getattr(adapter, "capabilities", None)):
        pytest.fail("PSIRT adapter must implement capabilities(duthost)")
    return adapter


def require_capability(adapter, duthost, capability):
    available = adapter.capabilities(duthost)
    if not isinstance(available, dict):
        pytest.fail("PSIRT adapter capabilities must be a mapping")
    result = available.get(capability)
    if result is True:
        return
    reason = result if isinstance(result, str) else "capability not supported"
    pytest.skip("BLOCKED: {}: {}".format(capability, reason))
