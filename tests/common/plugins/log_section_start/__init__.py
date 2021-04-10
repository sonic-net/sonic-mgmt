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

LOGGER_NAME = "SectionStartLogger"


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    logging_plugin = config.pluginmanager.get_plugin("logging-plugin")
    config.pluginmanager.register(LogSectionStartPlugin(logging_plugin), "LogSectionStart")
    logging.LogRecord = _LogRecord


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
