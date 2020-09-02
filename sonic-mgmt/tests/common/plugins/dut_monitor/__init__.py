import os
import pytest

from pytest_dut_monitor import DUTMonitorPlugin


def pytest_addoption(parser):
    """Describe plugin specified options"""
    parser.addoption("--dut_monitor", action="store_true", default=False,
                     help="Enable DUT hardware resources monitoring")
    parser.addoption("--thresholds_file", action="store", default=None, help="Path to the custom thresholds file")


def pytest_configure(config):
    if config.option.dut_monitor:
        thresholds = os.path.join(os.path.split(__file__)[0], "thresholds.yml")
        if config.option.thresholds_file:
            thresholds = config.option.thresholds_file
        config.pluginmanager.register(DUTMonitorPlugin(thresholds), "dut_monitor")


def pytest_unconfigure(config):
    dut_monitor = getattr(config, "dut_monitor", None)
    if dut_monitor:
        del config.dut_monitor
        config.pluginmanager.unregister(dut_monitor)
