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


@pytest.fixture(scope="function", autouse=True)
def store_fixture_values(request, duthosts, memory_utilization):
    logging.info("store memory_utilization {}".format(request.node.name))
    request.config.store_duthosts = duthosts
    request.config.store_memory_utilization = memory_utilization


@pytest.hookimpl(trylast=True)
def pytest_runtest_setup(item):
    logging.info("collect memory before test {}".format(item.name))

    duthosts = getattr(item.config, 'store_duthosts', None)
    memory_utilization = getattr(item.config, 'store_memory_utilization', None)
    if duthosts is None and memory_utilization is None:
        return

    memory_monitors, memory_values = memory_utilization

    logging.debug("memory_values {} ".format(memory_values))

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue

        # Initial memory check for all registered commands
        for name, cmd, memory_params, memory_check in memory_monitors[duthost.hostname].commands:
            output = memory_monitors[duthost.hostname].execute_command(cmd)
            memory_values["before_test"][duthost.hostname][name] = memory_check(output, memory_params)

    logging.info("Before test: collected memory_values {}".format(memory_values))


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_teardown(item, nextitem):
    logging.info("collect memory after test {}".format(item.name))

    duthosts = getattr(item.config, 'store_duthosts', None)
    memory_utilization = getattr(item.config, 'store_memory_utilization', None)
    if duthosts is None and memory_utilization is None:
        return

    memory_monitors, memory_values = memory_utilization

    logging.debug("memory_values {} ".format(memory_values))

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue

        # memory check for all registered commands
        for name, cmd, memory_params, memory_check in memory_monitors[duthost.hostname].commands:
            output = memory_monitors[duthost.hostname].execute_command(cmd)
            memory_values["after_test"][duthost.hostname][name] = memory_check(output, memory_params)

        memory_monitors[duthost.hostname].check_memory_thresholds(
            memory_values["after_test"][duthost.hostname], memory_values["before_test"][duthost.hostname])

    logging.info("After test: collected memory_values {}".format(memory_values))


@pytest.fixture(autouse=True)
def memory_utilization(duthosts, request):
    if request.config.getoption("--disable_memory_utilization") or "disable_memory_utilization" in request.keywords:
        logging.info("Memory utilization is disabled")
        yield None, None
        return

    memory_monitors = {}
    memory_values = {"before_test": {}, "after_test": {}}

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue
        memory_monitor = MemoryMonitor(ansible_host=duthost)
        memory_values["before_test"][duthost.hostname] = {}
        memory_values["after_test"][duthost.hostname] = {}
        logging.info("Hostname: {}, Hwsku: {}, Platform: {}".format(
            duthost.hostname, duthost.sonichost._facts["hwsku"], duthost.sonichost._facts["platform"]))
        memory_monitor.parse_and_register_commands(hwsku=duthost.sonichost._facts["hwsku"])
        memory_monitors[duthost.hostname] = memory_monitor

    yield memory_monitors, memory_values
