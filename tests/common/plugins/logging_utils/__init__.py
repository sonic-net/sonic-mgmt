"""Plugin that contains logging utilities to facilitate a better log."""
import os
import pytest


def pytest_addoption(parser):

    parser.addoption(
        "--log-directory",
        action="store",
        dest="log_dir",
        help="Per-module logs save directory, each test module will be saved under separate subdirs within."
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_setup(item):
    config = item.config
    log_dir = config.getoption("log_dir")
    if log_dir:
        logging_pluggin = config.pluginmanager.get_plugin("logging-plugin")
        relpath = str(item.fspath)[len(str(config.rootdir)):].lstrip("/")
        logfile = os.path.join(log_dir, os.path.splitext(relpath)[0] + ".log")
        logging_pluggin.set_log_path(logfile)
    yield
