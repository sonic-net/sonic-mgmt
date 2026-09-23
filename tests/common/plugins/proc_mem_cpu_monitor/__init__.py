# -*- coding: utf-8 -*-
import logging

import pytest

from tests.common.plugins.proc_mem_cpu_monitor.constants import MEM_LEAK_EVENT
from tests.common.plugins.proc_mem_cpu_monitor.controller import MemCpuMonitorResult, ProcMemCpuMonitor

logger = logging.getLogger(__name__)

__all__ = [
    "MEM_LEAK_EVENT",
    "MemCpuMonitorResult",
    "ProcMemCpuMonitor",
]


class _DisabledProcMemCpuMonitor(object):
    """No-op controller when monitoring is not enabled for this run/test."""

    def start(self, *args, **kwargs):
        logger.info("mem_cpu_monitor is not enabled; start() ignored")

    def snapshot(self, *args, **kwargs):
        logger.info("mem_cpu_monitor is not enabled; snapshot() ignored")

    def stop(self):
        return MemCpuMonitorResult()

    def plot(self, *args, **kwargs):
        return None

    def export_samples(self, *args, **kwargs):
        return {}

    def teardown(self):
        pass


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "enable_proc_mem_cpu_monitor: enable mem_cpu_monitor fixture for this test (opt-in; disabled by default)",
    )


def pytest_addoption(parser):
    parser.addoption(
        "--enable_proc_mem_cpu_monitor",
        action="store_true",
        default=False,
        help="Enable mem_cpu_monitor sampling for the entire pytest session (opt-in; default off)",
    )


def _is_enabled(request) -> bool:
    if request.config.getoption("--enable_proc_mem_cpu_monitor", default=False):
        return True
    if "enable_proc_mem_cpu_monitor" in request.keywords:
        return True
    return False


@pytest.fixture
def mem_cpu_monitor(request):
    """
    CPU/MEM process sampling via ``top`` on DUT(s). **Disabled by default.**

    Enable for a **whole run**::

        pytest --enable_proc_mem_cpu_monitor ...

    Enable for **specific tests**::

        @pytest.mark.enable_proc_mem_cpu_monitor
        def test_foo(duthosts, mem_cpu_monitor):
            ...
    """
    if not _is_enabled(request):
        yield _DisabledProcMemCpuMonitor()
        return
    mon = ProcMemCpuMonitor(request)
    try:
        yield mon
    finally:
        mon.teardown()
