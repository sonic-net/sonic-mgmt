import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from util import get_field_range, get_fields, get_skip_mod_list

logger = logging.getLogger('__name__')

pytestmark = [
    pytest.mark.topology('t2')
]

CMD_SHOW_CHASSIS_MODULE = "show chassis modules"


def parse_chassis_module(output, expected_headers):
    assert len(output) > 2
    f_ranges = get_field_range(output[1])
    headers = get_fields(output[0], f_ranges)

    for header_v in expected_headers:
        pytest_assert(header_v in headers, "Missing header {}".format(header_v))

    result = {}
    for a_line in output[2:]:
        field_val = get_fields(a_line, f_ranges)
        mod_idx = field_val[0]
        result[mod_idx] = {}
        cur_field = 1
        for a_header in headers[1:]:
            result[mod_idx][a_header] = field_val[cur_field]
            cur_field += 1

    return result


def test_show_chassis_module_status(duthosts, enum_rand_one_per_hwsku_hostname):
    cmd = " ".join([CMD_SHOW_CHASSIS_MODULE, "status"])
    logger.info("verifying output of cli command {}".format(cmd))
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    exp_headers = ["Name", "Description", "Physical-Slot", "Oper-Status", "Admin-Status"]
    skip_mod_list = get_skip_mod_list(duthost)

    output = duthost.command(cmd)
    res = parse_chassis_module(output['stdout_lines'], exp_headers)

    # by default will assume all modules should be shown online except in skip_module_list
    for mod_idx in res.keys():
        if mod_idx in skip_mod_list:
            pytest_assert(res[mod_idx]['Oper-Status'] == 'Empty',
                          "Oper-status for slot {} should be Empty but it is {}".format(
                              mod_idx, res[mod_idx]['Oper-Status']))
        else:
            pytest_assert(res[mod_idx]['Oper-Status'] == 'Online',
                          "Oper-status for slot {} should be Online but it is {}".format(
                              mod_idx, res[mod_idx]['Oper-Status']))


def test_show_chassis_module_midplane_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """
       @summary: Verify output of `show chassis-module midplane-status`
    """
    cmd = " ".join([CMD_SHOW_CHASSIS_MODULE, "midplane-status"])
    logger.info("verifying output of cli command {}".format(cmd))
    expected_headers = ["Name", "IP-Address", "Reachability"]

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    output = duthost.command(cmd)
    res_mid_status = parse_chassis_module(output['stdout_lines'], expected_headers)
    mod_key= ['line-cards', 'supervisor']
    skip_mod_list = get_skip_mod_list(duthost, mod_key)

    for mod_idx in res_mid_status:
        mod_mid_status = res_mid_status[mod_idx]['Reachability']
        if mod_idx in skip_mod_list:
            pytest_assert(res_mid_status[mod_idx]['Reachability'] == "False",
                          "reachability of line card {} expected false but is {}".format(mod_idx, mod_mid_status))
        else:
            pytest_assert(mod_mid_status == "True",
                          "midplane reachability of line card {} expected true but is {}".format(mod_idx,
                                                                                                 mod_mid_status))



