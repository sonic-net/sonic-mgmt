'''
This script is to test the reboot behavior for SONiC when there
is a mismatched primary Macsec key.

Step 1: Configure Macsec between neighbor and DUT with a mismatched CAK
Step 2: Save config on DUT and reboot
Step 3: Verify macsec connection is not re-established after reboot
Step 4: Remove mismatched CAK

'''

import logging
import pytest
from tests.common import reboot
from tests.common.utilities import wait_until
from .macsec_helper import get_appl_db
from tests.common.helpers.assertions import pytest_assert
from .macsec_config_helper import disable_macsec_port, enable_macsec_port, delete_macsec_profile, set_macsec_profile

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


def test_corrupt_primary_key_reboot(enum_frontend_dut_hostname, localhost, ctrl_links, profile_name,
                                    default_priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci,
                                    duthosts):

    duthost = duthosts[enum_frontend_dut_hostname]
    if not duthost.is_macsec_capable_node():
        pytest.skip("DUT must be a MACSec enabled device.")
    pytest_assert(ctrl_links)
    port_name, nbr = list(ctrl_links.items())[0]

    disable_macsec_port(duthost, port_name)
    disable_macsec_port(nbr["host"], nbr["port"])
    delete_macsec_profile(nbr["host"], nbr["port"], profile_name)

    # Wait till macsec session has gone down.
    wait_until(20, 3, 0, lambda: not duthost.iface_macsec_ok(port_name) and
               not nbr["host"].iface_macsec_ok(nbr["port"]))

    # Set a wrong cak to the profile
    primary_cak = "0" * len(primary_cak)
    enable_macsec_port(duthost, port_name, profile_name)
    set_macsec_profile(nbr["host"], nbr["port"], profile_name, default_priority, cipher_suite, primary_cak,
                       primary_ckn, policy, send_sci)
    enable_macsec_port(nbr["host"], nbr["port"], profile_name)

    duthost.shell("config save -y")
    reboot(duthost, localhost, wait=200)

    def check_mka_establishment():
        _, _, dut_ingress_sc_table, dut_egress_sa_table, dut_ingress_sa_table = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        return dut_ingress_sc_table or dut_egress_sa_table or dut_ingress_sa_table
    # The mka should not be establishing or established
    # To check whether the MKA establishment did not happened within 90 seconds
    pytest_assert(not wait_until(90, 1, 12, check_mka_establishment))

    # Teardown of mismatch
    disable_macsec_port(duthost, port_name)
    disable_macsec_port(nbr["host"], nbr["port"])
    delete_macsec_profile(nbr["host"], nbr["port"], profile_name)
