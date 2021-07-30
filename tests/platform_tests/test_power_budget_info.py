import logging
import re
import json
import pytest
from tests.common.helpers.assertions import pytest_assert
from cli.util import get_skip_mod_list

logger = logging.getLogger('__name__')

pytestmark = [
    pytest.mark.topology('t2')
]


def test_power_redis_db(duthosts, enum_supervisor_dut_hostname, tbinfo):
    """
    @summary: verify the output for power budget policy using
    redis command for chassis
    checks for each psu the supplied power
    checks consumed power for each present module
    """
    logger.info("verifying redis dump for power budget")
    duthost = duthosts[enum_supervisor_dut_hostname]
    skip_mod_list = get_skip_mod_list(duthost)
    exp_total_supp_power = 0
    exp_total_cons_power = 0

    redis_out = duthost.command("redis-dump -d 6 -y -k \"*power*\"")
    out_dict = json.loads(redis_out['stdout'])
    power_budget = out_dict.keys()

    for pb_name in power_budget:
        for out_val in out_dict[pb_name]['value']:
            if re.match('Supplied Power', out_val):
                n_psu = (re.split('Supplied Power ', out_val))[1]
                if n_psu not in skip_mod_list:
                    sup_power = float(out_dict[pb_name]['value'][out_val])
                    pytest_assert(sup_power > 0,
                                  "expected supplied power value for psu {} greater than 0 but got {}".format(n_psu, sup_power))
                    exp_total_supp_power += sup_power
                else:
                    logger.debug("psu {} in skip list skipping check".format(n_psu))

            elif re.match('Consumed Power', out_val):
                mod_name = (re.split('Consumed Power', out_val))[1]
                cons_power = float(out_dict[pb_name]['value'][out_val])
                exp_total_cons_power += cons_power
                if mod_name not in skip_mod_list:
                    pytest_assert(cons_power > 0,
                                  "power consumed values is not expected to be 0 or less for {}".format(mod_name))

        logger.info("verfying total supplied power is expected")
        tot_supp_power = float(out_dict[pb_name]['value']['Total Supplied Power'])
        tot_cons_power = float(out_dict[pb_name]['value']['Total Consumed Power'])
        pytest_assert(exp_total_cons_power == tot_cons_power,
                      "total consumed power is incorrect expected is {} reported is {}".format(
                          exp_total_cons_power, tot_cons_power))
        pytest_assert(exp_total_supp_power == tot_supp_power,
                      "total supplied power is not correct expected is {} reported is {}".format(
                          exp_total_supp_power, tot_supp_power))
