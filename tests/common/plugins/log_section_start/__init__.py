"""Add section separation line to pytest log

Pytest can output visually outstanding line at the start of test sections like setup, call and teardown. For example:

------------------------------------- live log setup -------------------------------
------------------------------------- live log call --------------------------------
------------------------------------- live log teardown ----------------------------

But in pytest log file, there is no such separation lines. It is really difficult to tell where a test case setup,
call or teardown section starts and ends while inspecting the log files.

This plugin uses pytest hook functions to insert a visually outstanding log message at the start of each section. The
log message also contains 'nodeid' of the current test case. Examples of such log messages:

09:40:50 INFO __init__.py:_log_sep_line:27: ==================== test_plugin.py::test_case2 setup  ====================
09:40:50 INFO __init__.py:_log_sep_line:27: ==================== test_plugin.py::test_case2 call ====================
09:40:52 INFO __init__.py:_log_sep_line:27: ==================== test_plugin.py::test_case2 teardown ====================
"""
import pytest
import logging
import inspect
import decorator
import traceback
import sys

from . import postimport


LOGGER_NAME = "SectionStartLogger"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    """Add exception log when test function exits with error."""
    yield
    last_type = getattr(sys, "last_type", None)
    last_value = getattr(sys, "last_value", None)
    last_traceback = getattr(sys, "last_traceback", None)
    if last_type is not None and last_value is not None and last_traceback is not None:
        logging.error("".join(traceback.format_exception(last_type, last_value, last_traceback)))


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    logging_plugin = config.pluginmanager.get_plugin("logging-plugin")
    config.pluginmanager.register(LogSectionStartPlugin(logging_plugin), "LogSectionStart")
    logging.LogRecord = _LogRecord

    postimport.register_hook(_pytest_import_callback)
    # simply replace the fixture decorator in the imported `pytest` with the mocked one
    _pytest_import_callback(pytest)


def _pytest_import_callback(module):
    """Hook function registered for the pytest module."""

    @decorator.decorator
    def _fixture_func_decorator(fixture_func, *args, **kargs):
        logging.info("-" * 20 + (" fixture %s setup starts " % fixture_func.__name__) + "-" * 20)
        try:
            return fixture_func(*args, **kargs)
        except Exception as detail:
            logging.exception("\n%r", detail)
            raise
        finally:
            logging.info("-" * 20 + (" fixture %s setup ends " % fixture_func.__name__) + "-" * 20)

    @decorator.decorator
    def _fixture_generator_decorator(fixture_generator, *args, **kargs):
        # setup, to the first yield in fixture
        logging.info("-" * 20 + (" fixture %s setup starts " % fixture_generator.__name__) + "-" * 20)
        it = fixture_generator(*args, **kargs)
        try:
            res = next(it)
            logging.info("-" * 20 + (" fixture %s setup ends " % fixture_generator.__name__) + "-" * 20)
            yield res
        except Exception as detail:
            logging.exception("\n%r", detail)
            logging.info("-" * 20 + (" fixture %s setup ends " % fixture_generator.__name__) + "-" * 20)
            raise

        # teardown, fixture will raise StopIteration
        logging.info("-" * 20 + (" fixture %s teardown starts " % fixture_generator.__name__) + "-" * 20)
        try:
            next(it)
        except StopIteration:
            raise
        except Exception as detail:
            logging.exception("\n%r", detail)
            raise
        finally:
            logging.info("-" * 20 + (" fixture %s teardown ends " % fixture_generator.__name__) + "-" * 20)

    def build_custom_fixture_decorator(original_fixture):

        def _fixture(*args, **kargs):
            """Decorator to replace the original pytest.fixture."""
            def _decorate(func):
                if inspect.isgeneratorfunction(func):
                    return original_fixture(*args, **kargs)(_fixture_generator_decorator(func))
                else:
                    return original_fixture(*args, **kargs)(_fixture_func_decorator(func))

            # check if the pytest.fixture is directly called
            func = None
            if len(args) == 1 and callable(args[0]) and not kargs:
                func = args[0]
            elif len(kargs) == 1 and callable(list(kargs.values())[0]) and not args:
                func = list(kargs.values())[0]
            if func is not None:
                args = ()
                kargs = {}
                return _decorate(func)

            return _decorate

        return _fixture

    original_fixture = getattr(module, "fixture")
    setattr(module, "fixture", build_custom_fixture_decorator(original_fixture))


class _LogRecord(logging.LogRecord):
    """
    Internally used log record class to represent the event being logged.
    This aims to add customized extra attributes to the log record to allow the
    formatter to use.

    Newly added attributes:

    %(funcNamewithModule)s          combination of module and funcName as
                                    `<module>.<funcName>`
    For other attributes, pls refer to:
    https://github.com/python/cpython/blob/d00a449d6d421391557393cce695795b4b66c212/Lib/logging/__init__.py#L522
    """

    def __init__(self, *args, **kargs):
        super(_LogRecord, self).__init__(*args, **kargs)
        self.funcNamewithModule = "%s.%s" % (self.module, self.funcName)


class _SepLineFilter(logging.Filter):
    def filter(self, record):
        if record.name == LOGGER_NAME:
            return 0
        return 1


class LogSectionStartPlugin(object):

    def __init__(self, logging_plugin):
        self.logger = logging.getLogger(LOGGER_NAME)

        # The pytest console log already has section separation lines. Filter out such separation lines to console log.
        # Otherwise, such separation lines only decrease log readability.
        if logging_plugin.log_cli_handler:
            logging_plugin.log_cli_handler.addFilter(_SepLineFilter())

    def _log_sep_line(self, text):
        self.logger.info("=" * 20 + " " + text + " " + "=" * 20)

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_setup(self, item):
        self._log_sep_line("{} setup ".format(item.nodeid))
        yield

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self, item):
        self._log_sep_line("{} call".format(item.nodeid))
        yield

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_teardown(self, item):
        self._log_sep_line("{} teardown".format(item.nodeid))
        yield
