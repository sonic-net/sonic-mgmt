import pytest

def pytest_assert(condition, message = None):
    __tracebackhide__ = True
    if not condition:
        pytest.fail(message)
