"""Performs post import function after importing pytest."""
import importlib
import sys


IMPORT_HOOK = []


class _PytestPostImportFinder(object):

    @staticmethod
    def find_module(fullname, path=None):
        if path is None and fullname == "pytest":
            return _PytestPostImportLoader()


class _PytestPostImportLoader(object):

    @staticmethod
    def load_module(fullname):
        importlib.import_module(fullname)
        module = sys.modules[fullname]
        for func in IMPORT_HOOK:
            func(module)
        return module


sys.meta_path.insert(0, _PytestPostImportFinder())


def register_hook(hook_function):
    IMPORT_HOOK.append(hook_function)
