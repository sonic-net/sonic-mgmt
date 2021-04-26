import logging
import pytest

from loganalyzer import LogAnalyzer
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.parallel import parallel_run, reset_ansible_local_tmp


def pytest_addoption(parser):
    parser.addoption("--disable_loganalyzer", action="store_true", default=False,
                     help="disable loganalyzer analysis for 'loganalyzer' fixture")


@reset_ansible_local_tmp
def analyzer_logrotate(node=None, results=None):
    logging.info("logrotate called on {}".format(node.hostname))
    try:
        node.shell("/usr/sbin/logrotate -f /etc/logrotate.conf > /dev/null 2>&1")
    except RunAnsibleModuleFail as e:
        logging.warning("logrotate is failed. Command returned:\n"
                        "Stdout: {}\n"
                        "Stderr: {}\n"
                        "Return code: {}".format(e.results["stdout"], e.results["stderr"], e.results["rc"]))


@reset_ansible_local_tmp
def analyzer_add_marker(analyzers, node=None, results=None):
    logging.info("add marker called on {}".format(node.hostname))
    loganalyzer = analyzers[node.hostname]
    logging.info("Add start marker into DUT syslog for host {}".format(node.hostname))
    marker = loganalyzer.init()
    logging.info("Load config and analyze log for host {}".format(node.hostname))
    # Read existed common regular expressions located with legacy loganalyzer module
    loganalyzer.load_common_config()
    results[node.hostname] = marker


@reset_ansible_local_tmp
def analyze_logs(analyzers, markers, node=None, results=None):
    dut_analyzer = analyzers[node.hostname]
    dut_analyzer.analyze(markers[node.hostname])


@pytest.fixture(autouse=True)
def loganalyzer(duthosts, request):
    if request.config.getoption("--disable_loganalyzer") or "disable_loganalyzer" in request.keywords:
        logging.info("Log analyzer is disabled")
        yield
        return

    # Analyze all the duts
    analyzers = {}
    parallel_run(analyzer_logrotate, [], {}, duthosts, timeout=120)
    for duthost in duthosts:
        analyzers[duthost.hostname] = LogAnalyzer(ansible_host=duthost, marker_prefix=request.node.name)
    markers = parallel_run(analyzer_add_marker, [analyzers], {}, duthosts, timeout=120)

    yield analyzers

    # Skip LogAnalyzer if case is skipped
    if "rep_call" in request.node.__dict__ and request.node.rep_call.skipped:
        return
    logging.info("Starting to analyse on all DUTs")
    parallel_run(analyze_logs, [analyzers, markers], {}, duthosts, timeout=120)

