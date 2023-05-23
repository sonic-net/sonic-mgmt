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
    extended_ignore_list = []

    if loganalyzer:
        if duthost.facts["asic_type"] in ["mellanox"]:
            extended_ignore_list.append("kernel.*Eeprom query failed*")
            # Ignore PMPE error https://github.com/sonic-net/sonic-buildimage/issues/7163
            extended_ignore_list.append(r".*ERR pmon#xcvrd: Receive PMPE error event on module.*")

            for host in loganalyzer:
                loganalyzer[host].ignore_regex.extend(extended_ignore_list)

    yield

    if loganalyzer:
        if duthost.facts["asic_type"] in ["mellanox"]:
            for host in loganalyzer:
                for ignore_regexp in extended_ignore_list:
                    loganalyzer[host].ignore_regex.remove(ignore_regexp)
