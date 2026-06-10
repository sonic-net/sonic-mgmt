import logging
import pytest
from tests.common.plugins.memory_utilization.memory_utilization import MemoryMonitor

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add this to store memory errors per test
_memory_errors_by_test = {}


def pytest_addoption(parser):
    parser.addoption(
        "--disable_memory_utilization",
        action="store_true",
        default=False,
        help="Disable memory utilization analysis for the 'memory_utilization' fixture"
    )
    parser.addoption(
        "--enable_monit_refresh",
        action="store_true",
        default=False,
        help="Enable the monit cache refresh in the memory_utilization fixture. "
             "When NOT set (default), the fixture does NOT issue `sudo monit "
             "validate` before collection and does NOT retry the `sudo monit "
             "status` read for freshness; the first read is returned as-is "
             "(faster, may contain stale monit cache data). When set, the fixture "
             "issues `sudo monit validate` to refresh the cache and retries the "
             "`sudo monit status` read for freshness, costing up to "
             "~MONIT_STATUS_FRESHNESS_WAIT_SECONDS * "
             "MONIT_STATUS_FRESHNESS_MAX_RETRIES seconds per setup/teardown when "
             "the cache is stale. Refresh can also be enabled per-test via "
             "`@pytest.mark.enable_monit_refresh`."
    )


@pytest.fixture(scope="function", autouse=True)
def store_fixture_values(request, duthosts, memory_utilization):
    if request.config.getoption("--disable_memory_utilization") or "disable_memory_utilization" in request.keywords:
        return

    logger.debug("store memory_utilization {}".format(request.node.name))
    request.config.store_duthosts = duthosts
    request.config.store_memory_utilization = memory_utilization


@pytest.hookimpl(trylast=True)
def pytest_runtest_setup(item):
    if "request" in item.fixturenames:
        request = item.funcargs.get("request", None)
        if request:
            if request.config.getoption("--disable_memory_utilization") or \
                    "disable_memory_utilization" in request.keywords:
                return

    logger.debug("collect memory before test {}".format(item.name))

    duthosts = getattr(item.config, 'store_duthosts', None)
    memory_utilization = getattr(item.config, 'store_memory_utilization', None)
    if duthosts is None and memory_utilization is None:
        return

    memory_monitors, memory_values = memory_utilization
    logger.debug("Memory monitors ready: {}".format(list(memory_monitors.keys()) if memory_monitors else "None"))
    logger.debug("memory_values {} ".format(memory_values))

    enable_monit_refresh = item.config.getoption("--enable_monit_refresh") or \
        "enable_monit_refresh" in item.keywords

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue

        if enable_monit_refresh:
            # Trigger monit to refresh its cache so subsequent collection reads fresh data
            logger.info("Triggering monit refresh on {} before collecting memory data".format(duthost.hostname))
            validate_output = memory_monitors[duthost.hostname].execute_command("sudo monit validate")
            memory_monitors[duthost.hostname].record_monit_baseline_from_validate_output(validate_output)
        else:
            logger.info(
                "enable_monit_refresh=False; bypassing 'sudo monit validate' pre-trigger on {}".format(
                    duthost.hostname))

        # Initial memory check for all registered commands
        for name, cmd, memory_params, memory_check in memory_monitors[duthost.hostname].commands:
            try:
                if name == "monit":
                    output = memory_monitors[duthost.hostname].read_monit_status_with_freshness_retry(
                        cmd, enable_retry=enable_monit_refresh)
                else:
                    output = memory_monitors[duthost.hostname].execute_command(cmd)
                memory_values["before_test"][duthost.hostname][name] = memory_check(output, memory_params)
            except Exception as e:
                logger.warning("Error collecting initial memory data for {}: {}".format(name, str(e)))
                memory_values["before_test"][duthost.hostname][name] = {}

    logger.info("Before test: collected memory_values {}".format(memory_values))


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_teardown(item, nextitem):
    if not hasattr(item, "rep_setup") or item.rep_setup.skipped or \
            not hasattr(item, "rep_call") or item.rep_call.skipped:
        return
    logger.debug("pytest_runtest_teardown early for test {}".format(item.name))
    if "request" in item.fixturenames:
        request = item.funcargs.get("request", None)
        if request:
            if request.config.getoption("--disable_memory_utilization") or \
                    "disable_memory_utilization" in request.keywords:
                return

    logger.debug("collect memory after test {}".format(item.name))

    duthosts = getattr(item.config, 'store_duthosts', None)
    memory_utilization = getattr(item.config, 'store_memory_utilization', None)
    if duthosts is None and memory_utilization is None:
        return

    memory_monitors, memory_values = memory_utilization
    memory_errors = []

    enable_monit_refresh = item.config.getoption("--enable_monit_refresh") or \
        "enable_monit_refresh" in item.keywords

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue

        if enable_monit_refresh:
            # Trigger monit to refresh its cache so subsequent collection reads fresh data
            logger.info("Triggering monit refresh on {} before collecting memory data".format(duthost.hostname))
            validate_output = memory_monitors[duthost.hostname].execute_command("sudo monit validate")
            memory_monitors[duthost.hostname].record_monit_baseline_from_validate_output(validate_output)
        else:
            logger.info(
                "enable_monit_refresh=False; bypassing 'sudo monit validate' pre-trigger on {}".format(
                    duthost.hostname))

        # memory check for all registered commands
        for name, cmd, memory_params, memory_check in memory_monitors[duthost.hostname].commands:
            try:
                if name == "monit":
                    output = memory_monitors[duthost.hostname].read_monit_status_with_freshness_retry(
                        cmd, enable_retry=enable_monit_refresh)
                else:
                    output = memory_monitors[duthost.hostname].execute_command(cmd)
                memory_values["after_test"][duthost.hostname][name] = memory_check(output, memory_params)
            except Exception as e:
                logger.warning("Error collecting final memory data for {}: {}".format(name, str(e)))
                memory_values["after_test"][duthost.hostname][name] = {}

        # Only check thresholds if we have data to compare
        if any(memory_values["before_test"][duthost.hostname]) and any(memory_values["after_test"][duthost.hostname]):
            try:
                memory_monitors[duthost.hostname].check_memory_thresholds(
                    memory_values["after_test"][duthost.hostname], memory_values["before_test"][duthost.hostname])

                # Check if any memory errors were detected
                if memory_monitors[duthost.hostname].has_memory_errors():
                    memory_errors.extend(memory_monitors[duthost.hostname].get_memory_errors())
                    memory_monitors[duthost.hostname].clear_memory_errors()

            except Exception as e:
                logger.error("Error checking memory thresholds: {}".format(str(e)))
        else:
            logger.warning("Skipping memory threshold check for {} due to missing data".format(duthost.hostname))

        # Store any detected errors for this test
        if memory_errors:
            _memory_errors_by_test[item.nodeid] = memory_errors
            logger.error("Memory errors detected: {}".format("\n".join(memory_errors)))

    logger.info("After test: collected memory_values {}".format(memory_values))


@pytest.fixture(autouse=True)
def memory_utilization(duthosts, request):
    if request.config.getoption("--disable_memory_utilization") or "disable_memory_utilization" in request.keywords:
        logger.info("Memory utilization monitoring is disabled")
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
        logger.info("Hostname: {}, Hwsku: {}, Platform: {}".format(
            duthost.hostname, duthost.sonichost._facts["hwsku"], duthost.sonichost._facts["platform"]))
        memory_monitor.parse_and_register_commands(hwsku=duthost.sonichost._facts["hwsku"])
        memory_monitors[duthost.hostname] = memory_monitor

    yield memory_monitors, memory_values

    # Check if we stored any memory errors for this test
    if request.node.nodeid in _memory_errors_by_test:
        errors = _memory_errors_by_test.pop(request.node.nodeid)
        if errors:
            failure_message = "\n".join(errors)
            logger.error(f"Memory errors detected in fixture teardown: {failure_message}")
            pytest.fail(failure_message)

    logger.debug("Memory utilization fixture cleanup")
