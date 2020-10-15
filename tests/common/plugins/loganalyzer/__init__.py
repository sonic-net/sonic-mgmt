import logging
import pytest

from loganalyzer import LogAnalyzer
from tests.common.errors import RunAnsibleModuleFail


def pytest_addoption(parser):
    parser.addoption("--disable_loganalyzer", action="store_true", default=False,
                     help="disable loganalyzer analysis for 'loganalyzer' fixture")


@pytest.fixture(autouse=True)
def loganalyzer(duthost, request):
    if request.config.getoption("--disable_loganalyzer") or "disable_loganalyzer" in request.keywords:
        logging.info("Log analyzer is disabled")
        yield
        return

    # Force rotate logs
    try:
        duthost.shell(
            "/usr/sbin/logrotate -f /etc/logrotate.conf > /dev/null 2>&1"
            )
    except RunAnsibleModuleFail as e:
        logging.warning("logrotate is failed. Command returned:\n"
                        "Stdout: {}\n"
                        "Stderr: {}\n"
                        "Return code: {}".format(e.results["stdout"], e.results["stderr"], e.results["rc"]))

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=request.node.name)
    logging.info("Add start marker into DUT syslog")
    marker = loganalyzer.init()
    logging.info("Load config and analyze log")
    # Read existed common regular expressions located with legacy loganalyzer module
    loganalyzer.load_common_config()

    yield loganalyzer
    # Skip LogAnalyzer if case is skipped
    if request.node.rep_call.skipped:
        return
    loganalyzer.analyze(marker)
