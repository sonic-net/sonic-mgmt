'''
The test case will verify that attempting to modify a macsec policy while in use behaves as intended.
Step 1: Attempt to modify in use profile and verify it errors
'''
import logging

import pytest
import time

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology('t2')
]


def test_modify_policy_in_use(macsec_duthost, startup_macsec, shutdown_macsec,
                              ctrl_links, profile_name, default_priority,
                              cipher_suite, primary_cak, primary_ckn, policy,
                              send_sci, capsys, rekey_period):
    port_name, nbr = list(ctrl_links.items())[0]
    if macsec_duthost.is_multi_asic:
        ns = " -n " + macsec_duthost.get_port_asic_instance(port_name).asic_index
    else:
        ns = ''

    with pytest.raises(Exception) as e_info:
        macsec_duthost.shell("sudo config macsec{} profile add --cipher_suite {} --policy {} \
                                       --primary_cak {} --primary_ckn {} --priority {} --rekey_period {} --send_sci {}"
                             .format(ns, cipher_suite, policy, primary_cak, primary_ckn,
                                     default_priority, rekey_period, profile_name))

    assert "Error: {} already exists".format(profile_name) in str(e_info.value)
    time.sleep(10)
    logger.info(macsec_duthost.shell("show macsec --profile")['stdout'])
