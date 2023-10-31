import pytest
import logging
import json
import sys
import time
import os

if sys.version_info.major > 2:
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

from tests.macsec.macsec_config_helper import setup_macsec_configuration

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("any")
]

profile_name = "256_XPN_SCI"
new_rekey_period = 180


@pytest.fixture(scope='module')
def setup(duthost, macsec_nbrhosts, ctrl_links):
    dut_num_asics = duthost.num_asics()

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

    setup_info = {
        'duthost': duthost,
        'dut_num_asics': dut_num_asics,
        'macsec_profile': macsec_profile,
        'dut_macsec_ports': dut_macsec_ports,
        'nbr_macsec_ports': nbr_macsec_ports
    }

    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info


# @pytest.mark.disable_loganalyzer
def test_rekeying(duthost, setup, ctrl_links):
    macsec_profile = setup['macsec_profile']

    logger.info("Remove macsec and reconfigure with rekey period set to {}".format(macsec_profile['rekey_period']))
    setup_macsec_configuration(duthost, ctrl_links, macsec_profile['name'],
                               macsec_profile['priority'],
                               macsec_profile['cipher_suite'],
                               macsec_profile['primary_cak'],
                               macsec_profile['primary_ckn'],
                               macsec_profile['policy'],
                               macsec_profile['send_sci'],
                               macsec_profile['rekey_period'])

    logger.info("Wait for rekey to occur")
    # Wait for few rekeys to occur
    time.sleep(macsec_profile['rekey_period'])

    # Check logs to ensure rekey occurs
    output = duthost.shell("grep -a encoding_an /var/log/swss/swss.rec", module_ignore_errors=True)["stdout_lines"]
    for port in setup['dut_macsec_ports']:
        status = any(port in x for x in output)
        assert status

    for nbrhost, ports in setup['nbr_macsec_ports'].items():
        output = nbrhost.shell("grep -a encoding_an /var/log/swss/swss.rec", module_ignore_errors=True)["stdout_lines"]
        for port in ports:
            status = any(port in x for x in output)
            assert status

    logger.info("Rekey successful")

