import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

s1_cli_dict_general = {
        #s1-clis to be tested
        "switch": ["mac-table"], #FORMAT: s1-cli -c "show switch mac-table"
}


def get_asic_str(duthost, asic):
    if duthost.is_multi_asic:
        return f" --asic-num {asic}"
    else:
        return ""
    
def test_s1_clis(duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index):
    """
    @summary: Verify output of s1-cli's, ie. `show switch mac`, update the s1_cli_dict_general to add more s1-cli's to coverage.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    error_result_list = []
    s1_cli_dict = s1_cli_dict_general.copy()

    for cli in s1_cli_dict:
        if duthost.is_multi_asic:
            asic = enum_rand_one_asic_index
        else:
            asic = ''
        for opt in s1_cli_dict[cli]:
            if duthost.is_multi_asic:
                result = duthost.shell('/usr/bin/s1-cli {} -c "show {} {}"'.
                        format(get_asic_str(duthost, asic), cli, opt), module_ignore_errors=True)
                logging.info(result["stdout"])
            else: 
                result = duthost.shell("s1-cli -c 'show {} {}' {}".
                        format(cli, opt, get_asic_str(duthost, asic)), module_ignore_errors=True)
                logging.info(result["stdout"])

            if result["stderr"]:
                error_result_list.append("Error found for s1-cli show {} {}".format(cli, opt))
            elif result is None or not result["stdout"]:
                error_result_list.append("No output for this s1 CLI show {} {}".format(cli, opt))
            elif "Traceback" in result["stdout"]:
                error_result_list.append("Traceback found for s1 CLI show {} {}".format(cli, opt))    

    for result in error_result_list:
        logging.error(result)

    assert not error_result_list, "One or more s1-cli's have failed {}".format(error_result_list)