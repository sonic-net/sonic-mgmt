import logging
from types import SimpleNamespace

from tests.common.plugins.memory_utilization.memory_utilization import MemoryMonitor


_old_record_factory = logging.getLogRecordFactory()


def _record_factory(*args, **kwargs):
    record = _old_record_factory(*args, **kwargs)
    record.funcNamewithModule = "%s.%s" % (record.module, record.funcName)
    return record


logging.setLogRecordFactory(_record_factory)


def _memory_monitor():
    ansible_host = SimpleNamespace(hostname="dut", facts={"asic_type": "mellanox"})
    monitor = MemoryMonitor(ansible_host)
    monitor.parse_and_register_commands(hwsku="Mellanox-SN2700")
    return monitor


def test_frr_zebra_stable_baseline_does_not_exceed_high_threshold():
    monitor = _memory_monitor()
    values = {"frr_zebra": {"used": 257}}

    monitor.check_memory_thresholds(values, values)

    assert monitor.get_memory_errors() == []


def test_frr_zebra_growth_still_exceeds_fail_threshold():
    monitor = _memory_monitor()

    monitor.check_memory_thresholds(
        {"frr_zebra": {"used": 229}},
        {"frr_zebra": {"used": 100}},
    )

    assert len(monitor.get_memory_errors()) == 1
    assert "memory usage increased by 129.0 MB" in monitor.get_memory_errors()[0]
