import pytest
import logging
import decorator

def disable_loganalyzer(func):
    """
    Decorator to disable loganalyzer analysis after test case execution
    """
    def wrapper(func, *args, **kwargs):
        logging.debug("Disabling loganalyzer...")
        try:
            func(*args, **kwargs)
        finally:
            pytest.disable_loganalyzer = True
    return decorator.decorator(wrapper, func)
