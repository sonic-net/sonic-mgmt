import pytest
import logging
import os

ans_host = None


def teardown_module():
    logging.info("remove script to retrieve port mapping")
    file_path = os.path.join('/usr/share/sonic/device', ans_host.facts['platform'], 'plugins/getportmap.py')
    ans_host.file(path=file_path, state='absent')


@pytest.fixture(autouse=True)
def update_la_ignore_errors_list_for_mlnx(duthost, loganalyzer):
    if duthost.facts["asic_type"] in ["mellanox"]:
        for host in loganalyzer:
            loganalyzer[host].ignore_regex.append("kernel.*Eeprom query failed*")
            # Ignore PMPE error https://github.com/Azure/sonic-buildimage/issues/7163
            loganalyzer[host].ignore_regex.append(r".*ERR pmon#xcvrd: Receive PMPE error event on module.*")

    yield

    if duthost.facts["asic_type"] in ["mellanox"]:
        for host in loganalyzer:
            loganalyzer[host].ignore_regex.remove("kernel.*Eeprom query failed*")
            # Remove Ignore PMPE error https://github.com/Azure/sonic-buildimage/issues/7163
            loganalyzer[host].ignore_regex.remove(r".*ERR pmon#xcvrd: Receive PMPE error event on module.*")
