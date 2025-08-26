import logging
import pytest

from .loganalyzer import LogAnalyzer, DisableLogrotateCronContext
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.parallel import parallel_run, reset_ansible_local_tmp
from .bug_handler_helper import get_bughandler_instance


def pytest_addoption(parser):
    parser.addoption("--disable_loganalyzer", action="store_true", default=False,
                     help="disable loganalyzer analysis for 'loganalyzer' fixture")
    parser.addoption("--store_la_logs", action="store_true", default=False,
                     help="store loganalyzer errors")
    parser.addoption("--ignore_la_failure", action="store_true", default=False,
                     help="do not fail the test if new bugs were found")
    parser.addoption("--loganalyzer_rotate_logs", action="store_true", default=True,
                     help="rotate log on all the dut engines at the beginning of the log analyzer fixture")
    parser.addoption("--bug_handler_params", action="store", default=None,
                     help="params that may needed in log_analyzer_bug_handler when err detected, "
                          "log_analyzer_bug_handler is called in _post_err_msg_handler, "
                          "vendor can implement their own logic in log_analyzer_bug_handler.")
    parser.addoption("--force_load_err_list", action="store_true", default=False,
                     help="Load the user defined err msgs which is not included in the common ignore file,"
                          "even when disable_loganalyzer is true")


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
    analyzer_summary = dut_analyzer.analyze(markers[node.hostname], fail_test, store_la_logs=store_la_logs)
    # results is a ProxyDict passed from parallel_run
    results[node.hostname] = analyzer_summary


@pytest.fixture(scope="module")
def log_rotate_modular_chassis(duthosts, request):
    # The process of logrotate will take up to 2 minutes each test for modular chassis.
    # This will add-up as the number of tests we have. As a result for modular chassis we want to run logrotate
    # as "module" scope instead of "function" scope.
    if request.config.getoption("--disable_loganalyzer") or "disable_loganalyzer" in request.keywords:
        return

    is_modular_chassis = duthosts[0].get_facts().get("modular_chassis") if duthosts else False

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
    is_modular_chassis = duthosts[0].get_facts().get("modular_chassis") if duthosts else False

    # We make sure only run logrotate as "function" scope for non-modular chassis for optimisation purpose.
    # For modular chassis please refer to "log_rotate_modular_chassis" fixture
    if should_rotate_log and not is_modular_chassis:
        parallel_run(analyzer_logrotate, [], {}, duthosts, timeout=120)
    for duthost in duthosts:
        analyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=request.node.name, request=request)
        analyzer.load_common_config()
        analyzers[duthost.hostname] = analyzer
    markers = parallel_run(analyzer_add_marker, [analyzers], {}, duthosts, timeout=120)

    yield analyzers

    # Skip LogAnalyzer if case is skipped
    if "rep_call" in request.node.__dict__ and request.node.rep_call.skipped or \
            "rep_setup" in request.node.__dict__ and request.node.rep_setup.skipped:
        return
    logging.info("Starting to analyse on all DUTs")
    la_results = parallel_run(
        analyze_logs,
        [analyzers, markers],
        {'fail_test': fail_test, 'store_la_logs': store_la_logs},
        duthosts,
        timeout=240
    )
    consolidated_bughandler = get_bughandler_instance({"type": "consolidated"})
    consolidated_bughandler.bug_handler_wrapper(analyzers, duthosts, la_results)


@pytest.fixture(autouse=True)
def ignore_pkt_trim_errors(duthosts, loganalyzer):
    ASIC_LIST = ["th5"]
    if loganalyzer:
        for duthost in duthosts:
            if duthost.facts["platform_asic"].lower() == "broadcom" and duthost.get_asic_name().lower() not in ASIC_LIST:
                # We should cleanup this code once CSP12420291 is fixed.
                loganalyzer[duthost.hostname].ignore_regex.extend(
                    [
                        r".*ERR syncd#syncd: .* SAI_API_SWITCH:_brcm_sai_xgs_pkt_trim_get_mapped_counter:[\d]+ Packet trim feature is not supported.*",
                        r".*ERR syncd#syncd: .* SAI_API_QUEUE:_brcm_sai_xgs_queue_pkt_trim_get_clear_ctr:[\d]+ Get Trim mapped counter failed with error -2.*",
                        r".*ERR syncd#syncd: .* SAI_API_QUEUE:_brcm_sai_cosq_stat_get:[\d]+ Get Trim stats packets failed with error -2.*",
                        r".*ERR syncd#syncd: .* SAI_API_SWITCH:sai_query_switch_attribute_enum_values_capability:[\d]+ packet trim Enum Capability values get for [\d]+ failed with error -2.*"
                    ]
                )
