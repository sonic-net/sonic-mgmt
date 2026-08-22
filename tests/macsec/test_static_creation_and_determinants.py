import pytest
import logging
import json
import sys
import os

from .macsec_helper import get_mka_session
from .macsec_config_helper import setup_macsec_configuration


if sys.version_info.major > 2:
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("any")
]

profile_name = '256_XPN_SCI'

INVALID_CIPHER = 'GMC-AES-256'
INVALID_POLICY = 'secruity'
INVALID_CAK = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
INVALID_CKN = 'XYZ256'
INVALID_PRIORITY = 256


def configure_invalid_macsec_profile(duthost, setup, ctrl_links, type, value):
    macsec_profile = setup['macsec_profile']
    invalid_macsec_profile = setup['macsec_profile']
    invalid_macsec_profile[type] = value
    try:
        logger.info(
            duthost.shell(
                "sudo config macsec profile add --cipher_suite {} --policy {} \
                    --primary_cak {} --primary_ckn {} --priority {} \
                        --rekey_period {} --send_sci {}".
                format(invalid_macsec_profile['cipher_suite'],
                       invalid_macsec_profile['policy'],
                       invalid_macsec_profile['primary_cak'],
                       invalid_macsec_profile['primary_ckn'],
                       invalid_macsec_profile['priority'],
                       invalid_macsec_profile['rekey_period'],
                       invalid_macsec_profile['send_sci'])))
        output = duthost.shell("sonic-cfggen -d --var-json MACSEC_PROFILE")
        logger.info("macsec config")
        logger.info(output)
        dut_mka_session = get_mka_session(duthost)
        logger.info("dut_mka_session")
        logger.info(dut_mka_session)
    except BaseException as err:
        logger.info(
            'Macsec profile with {} "{}" produced the following error: {}\n\n'.format(type, value, err)
        )

    else:
        logger.error(
            'Macsec profile with {} "{}" did not produce an error.'.format(type, value)
        )

    finally:
        setup_macsec_configuration(duthost, ctrl_links, macsec_profile['name'],
                                   macsec_profile['priority'],
                                   macsec_profile['cipher_suite'],
                                   macsec_profile['primary_cak'],
                                   macsec_profile['primary_ckn'],
                                   macsec_profile['policy'],
                                   macsec_profile['send_sci'],
                                   macsec_profile['rekey_period'])


@pytest.fixture(scope='module')
def setup(duthost, macsec_nbrhosts):
    dut_num_asics = duthost.num_asics()

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


def test_macsec_profile_with_invalid_cipher_suite(duthost, setup, ctrl_links):
    configure_invalid_macsec_profile(duthost, setup, ctrl_links, type="cipher_suite", value=INVALID_CIPHER)


def test_macsec_profile_with_invalid_policy(duthost, setup, ctrl_links):
    configure_invalid_macsec_profile(duthost, setup, ctrl_links, type="policy", value=INVALID_POLICY)


def test_macsec_profile_with_invalid_CAK(duthost, setup, ctrl_links):
    configure_invalid_macsec_profile(duthost, setup, ctrl_links, type="primary_cak", value=INVALID_CAK)


def test_macsec_profile_with_invalid_CKN(duthost, setup, ctrl_links):
    configure_invalid_macsec_profile(duthost, setup, ctrl_links, type="primary_ckn", value=INVALID_CKN)


def test_macsec_profile_with_invalid_priority(duthost, setup, ctrl_links):
    configure_invalid_macsec_profile(duthost, setup, ctrl_links, type="priority", value=INVALID_PRIORITY)
