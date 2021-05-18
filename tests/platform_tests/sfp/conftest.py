import pytest
import logging
import os
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

ans_host = None


def teardown_module():
    logging.info("remove script to retrieve port mapping")
    file_path = os.path.join('/usr/share/sonic/device', ans_host.facts['platform'], 'plugins/getportmap.py')
    ans_host.file(path=file_path, state='absent')


@pytest.fixture(autouse=True)
def disable_analyzer_for_mellanox(duthost):
    if duthost.facts["asic_type"] in ["mellanox"]:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='sfp_cfg')
        loganalyzer.load_common_config()

        loganalyzer.ignore_regex.append("kernel.*Eeprom query failed*")
        marker = loganalyzer.init()
    yield

    if duthost.facts["asic_type"] in ["mellanox"]:
        loganalyzer.analyze(marker)
