'''

The test case will verify that forcing a macsec policy delete and add behaves as intended.

Step 1: Attempt to delete in use profile and verify it errors
Step 2: Attempt to add an already configured profile and verify it errors

'''
import logging

import pytest
import time

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology('t2')
]


def test_delete_add_policy(macsec_duthost, ctrl_links, profile_name, default_priority,
                           cipher_suite, primary_cak, primary_ckn, policy, rekey_period):
    port_name, nbr = list(ctrl_links.items())[0]
    if macsec_duthost.is_multi_asic:
        ns = " -n " + macsec_duthost.get_port_asic_instance(port_name).namespace
    else:
        ns = ''

    with pytest.raises(Exception) as e_info:
        macsec_duthost.shell("sudo config macsec{} profile del {}".format(ns, profile_name))
    assert "Error: {} is being used by port".format(profile_name) in str(e_info.value)
    time.sleep(10)

    with pytest.raises(Exception) as e_info:
        macsec_duthost.shell("sudo config macsec{} profile add --cipher_suite {} --policy {} \
                                       --primary_cak {} --primary_ckn {} --priority {} --rekey_period {} --send_sci {}"
                             .format(ns, cipher_suite, policy, primary_cak, primary_ckn,
                                     default_priority, rekey_period, profile_name))

    assert "Error: {} already exists".format(profile_name) in str(e_info.value)
    time.sleep(10)
