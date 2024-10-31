import logging
import pytest

from .loganalyzer import LogAnalyzer, DisableLogrotateCronContext
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.parallel import parallel_run, reset_ansible_local_tmp


def pytest_addoption(parser):
    parser.addoption("--disable_loganalyzer", action="store_true", default=False,
                     help="disable loganalyzer analysis for 'loganalyzer' fixture")
    parser.addoption("--store_la_logs", action="store_true", default=False,
                     help="store loganalyzer errors")
    parser.addoption("--ignore_la_failure", action="store_true", default=False,
                     help="do not fail the test if new bugs were found")
    parser.addoption("--loganalyzer_rotate_logs", action="store_true", default=True,
                     help="rotate log on all the dut engines at the beginning of the log analyzer fixture")


@reset_ansible_local_tmp
def analyzer_logrotate(node=None, results=None):
    with DisableLogrotateCronContext(node):
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
    results[node.hostname] = marker


@reset_ansible_local_tmp
def analyze_logs(analyzers, markers, node=None, results=None, fail_test=True, store_la_logs=False):
    dut_analyzer = analyzers[node.hostname]
    dut_analyzer.analyze(markers[node.hostname], fail_test, store_la_logs=store_la_logs)


@pytest.fixture(scope="module")
def log_rotate_modular_chassis(duthosts, request):
    if request.config.getoption("--disable_loganalyzer") or "disable_loganalyzer" in request.keywords:
        return

    is_modular_chassis = duthosts[0].get_facts().get("modular_chassis")

    if not is_modular_chassis:
        return

    parallel_run(analyzer_logrotate, [], {}, duthosts, timeout=120)


@pytest.fixture(autouse=True)
def loganalyzer(duthosts, request, log_rotate_modular_chassis):
    if request.config.getoption("--disable_loganalyzer") or "disable_loganalyzer" in request.keywords:
        logging.info("Log analyzer is disabled")
        yield
        return

    # Analyze all the duts
    fail_test = not (request.config.getoption("--ignore_la_failure"))
    store_la_logs = request.config.getoption("--store_la_logs")
    analyzers = {}
    should_rotate_log = request.config.getoption("--loganalyzer_rotate_logs")

    is_modular_chassis = duthosts[0].get_facts().get("modular_chassis")
    if should_rotate_log and not is_modular_chassis:
        parallel_run(analyzer_logrotate, [], {}, duthosts, timeout=120)
    for duthost in duthosts:
        analyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=request.node.name)
        analyzer.load_common_config()
        analyzers[duthost.hostname] = analyzer
    markers = parallel_run(analyzer_add_marker, [analyzers], {}, duthosts, timeout=120)

    yield analyzers

    # Skip LogAnalyzer if case is skipped
    if "rep_call" in request.node.__dict__ and request.node.rep_call.skipped or \
            "rep_setup" in request.node.__dict__ and request.node.rep_setup.skipped:
        return
    logging.info("Starting to analyse on all DUTs")
    parallel_run(analyze_logs, [analyzers, markers], {'fail_test': fail_test, 'store_la_logs': store_la_logs},
                 duthosts, timeout=120)
