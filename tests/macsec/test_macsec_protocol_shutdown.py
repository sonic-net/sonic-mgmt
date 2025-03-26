import pytest
import logging
import json
import time
import sys
import os

from .macsec_config_helper import enable_macsec_feature, disable_macsec_feature
from .macsec_helper import get_mka_session, get_sci, check_mka_session
from .macsec_platform_helper import get_macsec_ifname

if sys.version_info.major > 2:
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("any")
]

profile_name = "256_XPN_SCI"


@pytest.fixture(scope='module')
def setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
          enum_rand_one_frontend_asic_index, macsec_nbrhosts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dut_num_asics = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    with open(os.path.dirname(__file__) + '/profile.json') as f:
        macsec_profiles = json.load(f)
        macsec_profile = macsec_profiles[profile_name]
        macsec_profile["name"] = profile_name

    nbrhosts = []
    for nbr in macsec_nbrhosts:
        nbrhosts.append(macsec_nbrhosts[nbr]["host"])

    setup_info = {
        'duthost': duthost,
        'dut_num_asics': dut_num_asics,
        'nbrhosts': nbrhosts,
        'macsec_profile': macsec_profile
    }

    logger.info('Setup_info: {}'.format(setup_info))

    yield setup_info


def test_macsec_protocol_shutdown(duthost, macsec_nbrhosts, setup, ctrl_links):
    macsec_profile = setup['macsec_profile']

    dut_mka_session = get_mka_session(duthost)
    assert len(dut_mka_session) == len(ctrl_links)
    for port_name, nbr in list(ctrl_links.items()):
        nbr_mka_session = get_mka_session(nbr["host"])
        dut_macsec_port = get_macsec_ifname(duthost, port_name)
        nbr_macsec_port = get_macsec_ifname(
            nbr["host"], nbr["port"])
        dut_macaddress = duthost.get_dut_iface_mac(port_name)
        nbr_macaddress = nbr["host"].get_dut_iface_mac(nbr["port"])
        dut_sci = get_sci(dut_macaddress)
        nbr_sci = get_sci(nbr_macaddress)
        check_mka_session(dut_mka_session[dut_macsec_port], dut_sci,
                          nbr_mka_session[nbr_macsec_port], nbr_sci,
                          macsec_profile['policy'], macsec_profile['cipher_suite'],
                          macsec_profile['send_sci'])

    disable_macsec_feature(duthost, macsec_nbrhosts)
    time.sleep(5)
    output = duthost.shell("docker ps")["stdout_lines"]
    status = any("macsec" not in x for x in output)
    assert status
    logger.info("macsec disabled")

    enable_macsec_feature(duthost, macsec_nbrhosts)

    output = duthost.shell("docker ps")["stdout_lines"]
    if setup['dut_num_asics'] > 1:
        for i in range(setup['dut_num_asics']):
            y = "macsec{}".format(i)
            status = any(y in x for x in output)
            assert status
    else:
        status = any("macsec" in x for x in output)
        assert status
    logger.info("macsec enabled")

    time.sleep(300)

    dut_mka_session = get_mka_session(duthost)
    assert len(dut_mka_session) == len(ctrl_links)
    for port_name, nbr in list(ctrl_links.items()):
        nbr_mka_session = get_mka_session(nbr["host"])
        dut_macsec_port = get_macsec_ifname(duthost, port_name)
        nbr_macsec_port = get_macsec_ifname(
            nbr["host"], nbr["port"])
        dut_macaddress = duthost.get_dut_iface_mac(port_name)
        nbr_macaddress = nbr["host"].get_dut_iface_mac(nbr["port"])
        dut_sci = get_sci(dut_macaddress)
        nbr_sci = get_sci(nbr_macaddress)
        check_mka_session(dut_mka_session[dut_macsec_port], dut_sci,
                          nbr_mka_session[nbr_macsec_port], nbr_sci,
                          macsec_profile['policy'], macsec_profile['cipher_suite'],
                          macsec_profile['send_sci'])

    logger.info("macsec sessions restored")
