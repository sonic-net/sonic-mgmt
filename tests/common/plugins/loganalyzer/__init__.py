import logging
import pytest

from loganalyzer import LogAnalyzer


def pytest_addoption(parser):
    parser.addoption("--disable_loganalyzer", action="store_true", default=False,
                     help="disable loganalyzer analysis for 'loganalyzer' fixture")


@pytest.fixture(autouse=True)
def loganalyzer(duthost, request):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=request.node.name)
    logging.info("Add start marker into DUT syslog")
    marker = loganalyzer.init()
    yield loganalyzer
    if not request.config.getoption("--disable_loganalyzer") and "disable_loganalyzer" not in request.keywords:
        logging.info("Load config and analyze log")
        # Read existed common regular expressions located with legacy loganalyzer module
        loganalyzer.load_common_config()
        # Parse syslog and process result. Raise "LogAnalyzerError" exception if: total match or expected missing
        # match is not equal to zero
        loganalyzer.analyze(marker)
    else:
        logging.info("Add end marker into DUT syslog")
        loganalyzer._add_end_marker(marker)
