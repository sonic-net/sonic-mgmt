import pytest
import logging
import json
import sys
import time
import os
from datetime import datetime

if sys.version_info.major > 2:
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

from .macsec_config_helper import disable_macsec_port, cleanup_macsec_configuration, setup_macsec_configuration, wait_all_complete

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t2")
]

profile_name = "256_XPN_SCI"
new_rekey_period = 10
# few rekeys + 5 seconds to ensure rekeys logged
few_rekey_period = new_rekey_period*3+5


def filter_rekey_matches(items, start_time, date_format="%Y-%m-%d.%H:%M:%S.%f"):
    rekey_matches = []
    for item in items:
        date_str = item.split(' ', 1)[0]
        logger.info(date_str)
        try:
            item_date = datetime.strptime(date_str, date_format)
            if item_date > start_time:
                rekey_matches.append(item)
        except ValueError:
            continue

    logger.info(rekey_matches)

    return rekey_matches


@pytest.mark.disable_loganalyzer
def test_rekeying(macsec_nbrhosts, ctrl_links, duthosts,
          enum_rand_one_per_hwsku_frontend_hostname,
          enum_rand_one_frontend_asic_index):

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    with open(os.path.dirname(__file__) + '/profile.json') as f:
        macsec_profiles = json.load(f)
        macsec_profile = macsec_profiles[profile_name]
        macsec_profile["name"] = profile_name
        macsec_profile["rekey_period"] = new_rekey_period

    nbrhosts = []
    for nbr in macsec_nbrhosts:
        nbrhosts.append(macsec_nbrhosts[nbr]["host"])

    dut_macsec_ports = []
    nbr_macsec_ports = dict([(nbr, []) for nbr in nbrhosts])
    for dutport, nbrport in ctrl_links.items():
        dut_macsec_ports.append(dutport)
        nbr_macsec_ports[nbrport['host']].append(nbrport['port'])

    logger.info("Remove macsec and reconfigure with rekey period set to {}".format(macsec_profile['rekey_period']))
    # for dut_port, nbr in list(ctrl_links.items()):
    #     disable_macsec_port, (duthost, dut_port)
    #     disable_macsec_port, (nbr["host"], nbr["port"])
    # wait_all_complete(timeout=300)

    cleanup_macsec_configuration(duthost, ctrl_links, macsec_profile['name'])

    setup_macsec_configuration(duthost, ctrl_links, macsec_profile['name'],
                               macsec_profile['priority'],
                               macsec_profile['cipher_suite'],
                               macsec_profile['primary_cak'],
                               macsec_profile['primary_ckn'],
                               macsec_profile['policy'],
                               macsec_profile['send_sci'],
                               macsec_profile['rekey_period'])

    now = datetime.now()
    date_format = "%Y-%m-%d.%H:%M:%S.%f"
    start_time = datetime.strptime(str(now), date_format)
    logger.info('start:{}'.format(start_time))

    logger.info("Wait for rekey to occur")
    time.sleep(few_rekey_period)

    # Check logs to ensure rekey occurs
    output = duthost.shell("grep -a encoding_an /var/log/swss/swss.rec", module_ignore_errors=True)["stdout_lines"]
    logger.info('{}:{}'.format(duthost, output))
    rekey_matches = filter_rekey_matches(output, start_time)
    logger.info('{}:{}'.format(duthost, rekey_matches))
    for port in dut_macsec_ports:
        status = any(port in x for x in rekey_matches)
        assert status

    for nbrhost, ports in nbr_macsec_ports.items():
        output = nbrhost.shell("grep -a encoding_an /var/log/swss/swss.rec", module_ignore_errors=True)["stdout_lines"]
        logger.info('{}:{}'.format(nbrhost, output))
        rekey_matches = filter_rekey_matches(output, start_time)
        logger.info('{}:{}'.format(nbrhost, rekey_matches))
        for port in ports:
            status = any(port in x for x in rekey_matches)
            assert status

    logger.info("Rekey successful")
