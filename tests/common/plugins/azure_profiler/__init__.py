import logging
import pytest

logger = logging.getLogger(__name__)

PROFILER_CONTAINER = "profiler"
PROFILER_DIR = "/usr/bin/linux_deploy/azprof"
PROFILER_CMD = "/usr/bin/linux_deploy/azprof/AzureProfiler /GroupName:SonicTest /Role:TestRole /IntervalMinutes:0"


def pytest_addoption(parser):
    parser.addoption("--with_azure_profiler", action="store_true", default=False,
                     help="Enable AzureProfiler on DUT for every test case")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "azure_profiler: Mark a test to run AzureProfiler on the DUT during execution. "
    )


@pytest.fixture(scope="function", autouse=True)
def azure_profiler(request):
    """
    Starts AzureProfiler on the DUT for a testcase.

    Activated by either:
      - `--with_azure_profiler` CLI flag (enables for every test case)
      - `@pytest.mark.azure_profiler` decorator on a specific test

    Usage (global, all tests):
        ./run_tests.sh ... -e --with_azure_profiler

    Usage (per-test):
        @pytest.mark.azure_profiler
        def test_something(duthost):
            ...
    The profiler is a best-effort monitoring tool; if it fails to start,
    the test case proceeds normally with a warning logged.
    """
    if not request.config.getoption("--with_azure_profiler") \
            and not request.node.get_closest_marker("azure_profiler"):
        yield
        return

    # Lazily resolve duthost and creds — not all tests have them
    try:
        duthost = request.getfixturevalue("duthost")
        creds = request.getfixturevalue("creds")
    except pytest.FixtureLookupError:
        logger.warning("azure_profiler: 'duthost' or 'creds' not available, skipping")
        yield
        return

    profiler_pid = None

    # Setup: verify container exists before attempting to start profiler
    container_check = duthost.shell(
        "docker inspect {} > /dev/null 2>&1 && echo exists || echo missing".format(PROFILER_CONTAINER),
        module_ignore_errors=True)
    if container_check["stdout"].strip() != "exists":
        logger.warning(
            "Profiler container '{}' not found on {}, skipping AzureProfiler".format(
                PROFILER_CONTAINER, duthost.hostname))
        yield
        return

    # Setup: start profiler inside the profiler container in background for sampling during test
    try:
        http_proxy = creds.get("proxy_env", {}).get("http_proxy", "")
        https_proxy = creds.get("proxy_env", {}).get("https_proxy", "")
        result = duthost.shell(
            "docker exec -e http_proxy={} -e https_proxy={} {} bash -c 'cd {} && chmod +x {} && nohup {} "
            "> /tmp/azureprofiler.log 2>&1 & echo $!'".format(
                http_proxy, https_proxy, PROFILER_CONTAINER, PROFILER_DIR, PROFILER_CMD.split()[0], PROFILER_CMD),
            module_ignore_errors=True)
        if result["rc"] != 0:
            logger.warning("AzureProfiler failed to launch in container '{}' on {}, rc={}, stderr={}".format(
                PROFILER_CONTAINER, duthost.hostname, result["rc"], result.get("stderr", "")))
        else:
            pid_str = result["stdout"].strip()
            if pid_str.isdigit():
                profiler_pid = pid_str
                logger.info("AzureProfiler started in container '{}' on {} with PID {}".format(
                    PROFILER_CONTAINER, duthost.hostname, profiler_pid))
            else:
                logger.warning("AzureProfiler PID invalid on {}: '{}'".format(duthost.hostname, pid_str))
    except Exception as e:
        logger.warning("Failed to start AzureProfiler on {}: {}".format(duthost.hostname, e))

    yield

    # Teardown: wait for AzureProfiler to finish uploading (up to 100s), do NOT kill it
    if profiler_pid:
        try:
            logger.info("Waiting for AzureProfiler (PID {}) to finish uploading on {}...".format(
                profiler_pid, duthost.hostname))
            duthost.shell(
                "docker exec {} bash -c 'timeout 100 sh -c \"while kill -0 {} 2>/dev/null; do sleep 5; done\"'".format(
                    PROFILER_CONTAINER, profiler_pid),
                module_ignore_errors=True)
            logger.info("AzureProfiler (PID {}) completed on {}".format(profiler_pid, duthost.hostname))
        except Exception as e:
            logger.warning("Error waiting for AzureProfiler PID {} on {}: {}".format(
                profiler_pid, duthost.hostname, e))
