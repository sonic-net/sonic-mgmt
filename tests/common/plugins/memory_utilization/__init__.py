import logging
import pytest
from tests.common.plugins.memory_utilization.memory_utilization import MemoryMonitor


def pytest_addoption(parser):
    parser.addoption(
        "--disable_memory_utilization",
        action="store_true",
        default=False,
        help="Disable memory utilization analysis for the 'memory_utilization' fixture"
    )


@pytest.fixture(autouse=True)
def memory_utilization(duthosts, request):
    if request.config.getoption("--disable_memory_utilization") or "disable_memory_utilization" in request.keywords:
        logging.info("Memory utilization is disabled")
        yield
        return

    memory_monitors = {}
    initial_memory_values = {}

    logging.info("Memory utilization: collect memory information before test case")
    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue
        memory_monitor = MemoryMonitor(ansible_host=duthost)
        logging.info(
            "Hostname: {}, Hwsku: {}, Platform: {}".format(
                duthost.hostname, duthost.sonichost._facts["hwsku"], duthost.sonichost._facts["platform"]
            )
        )
        memory_monitor.parse_and_register_commands(hwsku=duthost.sonichost._facts["hwsku"])
        memory_monitors[duthost.hostname] = memory_monitor

        # Initial memory check for all registered commands
        initial_memory_values[duthost.hostname] = {}
        for name, cmd, memory_params, memory_check in memory_monitor.commands:
            output = memory_monitor.execute_command(cmd)
            initial_memory_values[duthost.hostname][name] = memory_check(output, memory_params)

        logging.debug("Initial memory values[{}]: {}".format(duthost.hostname, initial_memory_values[duthost.hostname]))

    yield memory_monitors

    logging.info("Memory utilization: collect memory information after test case")
    final_memory_values = {}

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue
        memory_monitor = memory_monitors[duthost.hostname]
        # Memory check after test case for all registered commands
        final_memory_values[duthost.hostname] = {}
        for name, cmd, memory_params, memory_check in memory_monitor.commands:
            output = memory_monitor.execute_command(cmd)
            final_memory_values[duthost.hostname][name] = memory_check(output, memory_params)

        logging.info("Final memory values[{}]: {}".format(duthost.hostname, final_memory_values[duthost.hostname]))
        memory_monitor.check_memory_thresholds(
            final_memory_values[duthost.hostname], initial_memory_values[duthost.hostname]
        )
