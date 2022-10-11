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
def update_la_ignore_errors_list_for_mlnx(duthost):
    if duthost.facts["asic_type"] in ["mellanox"]:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='sfp_cfg')
        loganalyzer.load_common_config()
        loganalyzer.ignore_regex.append("kernel.*Eeprom query failed*")
        # Ignore PMPE error https://github.com/sonic-net/sonic-buildimage/issues/7163
        loganalyzer.ignore_regex.append(r".*ERR pmon#xcvrd: Receive PMPE error event on module.*")
        marker = loganalyzer.init()

    yield

    if duthost.facts["asic_type"] in ["mellanox"]:
        loganalyzer.analyze(marker)
