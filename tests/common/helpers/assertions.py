import pytest

def pytest_assert(condition, message = None):
    __tracebackhide__ = True
    if not condition:
        pytest.fail(message)

def pytest_require(condition, skip_message="", allow_module_level=True):
    if not condition:
        # We can't use pytest.skip here because pytest after 3.0
        # doesn't allow to call skip outside a test case or fixture.
        raise pytest.skip.Exception(skip_message, allow_module_level=allow_module_level)
