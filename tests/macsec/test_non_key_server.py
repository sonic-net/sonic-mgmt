import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_helper import check_wpa_supplicant_process, check_appl_db
from tests.common.macsec.macsec_config_helper import (
    set_macsec_profile, enable_macsec_port, cleanup_macsec_configuration
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


class TestMacsecNonKeyServer:

    def test_non_key_server_macsec_establishment(self, duthost, ctrl_links,
                                                  profile_name, default_priority,
                                                  cipher_suite, primary_cak,
                                                  primary_ckn, policy, send_sci,
                                                  macsec_feature):
        if not ctrl_links:
            pytest.skip("No controlled MACsec links available")

        ctrl_link = dict([next(iter(ctrl_links.items()))])
        port_name, nbr = next(iter(ctrl_link.items()))
        non_key_server_profile = "{}_NON_KEY_SERVER".format(profile_name)

        try:
            # Set DUT as the non-key server by giving it a numerically higher
            # key-server priority than the neighbor.
            set_macsec_profile(duthost, port_name, non_key_server_profile,
                               default_priority + 1,
                               cipher_suite, primary_cak, primary_ckn,
                               policy, send_sci)
            set_macsec_profile(nbr["host"], nbr["port"], non_key_server_profile,
                               default_priority,
                               cipher_suite, primary_cak, primary_ckn,
                               policy, send_sci)

            enable_macsec_port(duthost, port_name, non_key_server_profile)
            enable_macsec_port(nbr["host"], nbr["port"], non_key_server_profile)

            assert wait_until(300, 3, 0,
                              lambda: duthost.iface_macsec_ok(port_name) and
                                      nbr["host"].iface_macsec_ok(nbr["port"]))

            assert wait_until(300, 6, 12,
                              check_appl_db, duthost, ctrl_link,
                              policy, cipher_suite, send_sci)

            check_wpa_supplicant_process(duthost, port_name)
            if not isinstance(nbr["host"], EosHost):
                check_wpa_supplicant_process(nbr["host"], nbr["port"])
        finally:
            cleanup_macsec_configuration(duthost, ctrl_link, non_key_server_profile)
