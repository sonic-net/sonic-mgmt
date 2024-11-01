import ptf.testutils as testutils
import inspect
import logging

logger = logging.getLogger(__name__)


def wrapped(*args, **kwargs):
    return True


class DummyTestUtils:
    def __init__(self, *args, **kwargs):
        func_dict = {}
        for name, func in inspect.getmembers(testutils, inspect.isfunction):
            if name.startswith("send") or name.startswith("verify"):
                func_dict[name] = func
        self.func_dict = func_dict

    def __enter__(self, *args, **kwargs):
        """ enter in 'with' block """
        for name, func in self.func_dict.items():
            setattr(testutils, name, wrapped)

    def __exit__(self, *args, **kwargs):
        """ exit from 'with' block """
        for name, func in self.func_dict.items():
            setattr(testutils, name, self.func_dict[name])
