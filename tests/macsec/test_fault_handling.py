from time import sleep
import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common.macsec.macsec_helper import get_appl_db
from tests.common.macsec.macsec_config_helper import disable_macsec_port, \
    enable_macsec_port, delete_macsec_profile, set_macsec_profile
from tests.common.macsec.macsec_platform_helper import get_eth_ifname, find_portchannel_from_member, get_portchannel

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


class TestFaultHandling():
    MKA_TIMEOUT = 6
    LACP_TIMEOUT = 90

    @pytest.mark.disable_loganalyzer
    def test_link_flap(self, duthost, ctrl_links, wait_mka_establish):
        # Only pick one link for link flap test
        assert ctrl_links
        port_name, nbr = list(ctrl_links.items())[0]
        nbr_eth_port = get_eth_ifname(
            nbr["host"], nbr["port"])
        _, _, _, dut_egress_sa_table_orig, dut_ingress_sa_table_orig = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])

        # Flap < 6 seconds
        # Not working on eos neighbour
        if not isinstance(nbr["host"], EosHost):
            # Rekey may happen during the following assertions, so we need to get the SA tables again
            retry = 3
            while retry > 0:
                retry -= 1
                try:
                    nbr["host"].shell("config interface shutdown {}  && sleep 1 && config interface startup {}".format(
                        nbr["port"], nbr["port"]))
                    _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
                        duthost, port_name, nbr["host"], nbr["port"])
                    assert dut_egress_sa_table_orig == dut_egress_sa_table_new
                    assert dut_ingress_sa_table_orig == dut_ingress_sa_table_new
                    break
                except AssertionError as e:
                    if retry == 0:
                        raise e
                    # This test may fail due to the lag of DUT exceeding MKA_TIMEOUT that triggers a rekey.
                    # To mitigate this, retry the test after a while with a few seconds of idle time.
                    sleep(30)
                dut_egress_sa_table_orig, dut_ingress_sa_table_orig = dut_egress_sa_table_new, dut_ingress_sa_table_new

        # Flap > 6 seconds but < 90 seconds
        if isinstance(nbr["host"], EosHost):
            nbr["host"].shutdown(nbr_eth_port)
            sleep(TestFaultHandling.MKA_TIMEOUT)
            nbr["host"].no_shutdown(nbr_eth_port)
        else:
            nbr["host"].shell("config interface shutdown {}  && sleep {} && config interface startup {}".format(
                nbr["port"], TestFaultHandling.MKA_TIMEOUT, nbr["port"]))

        def check_new_mka_session():
            _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
                duthost, port_name, nbr["host"], nbr["port"])
            assert dut_egress_sa_table_new
            assert dut_ingress_sa_table_new
            assert dut_egress_sa_table_orig != dut_egress_sa_table_new
            assert dut_ingress_sa_table_orig != dut_ingress_sa_table_new
            return True
        assert wait_until(30, 5, 2, check_new_mka_session)

        # Flap > 90 seconds
        assert wait_until(12, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Up")
        if isinstance(nbr["host"], EosHost):
            nbr["host"].shutdown(nbr_eth_port)
            sleep(TestFaultHandling.LACP_TIMEOUT)
        else:
            nbr["host"].shell("ifconfig {} down && sleep {}".format(
                nbr_eth_port, TestFaultHandling.LACP_TIMEOUT))
        assert wait_until(6, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Dw")

        if isinstance(nbr["host"], EosHost):
            nbr["host"].no_shutdown(nbr_eth_port)
        else:
            nbr["host"].shell("ifconfig {} up".format(nbr_eth_port))
        assert wait_until(12, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Up")

    @pytest.mark.disable_loganalyzer
    def test_mismatch_macsec_configuration(self, duthost, unctrl_links,
                                           profile_name, default_priority, cipher_suite,
                                           primary_cak, primary_ckn, policy, send_sci, wait_mka_establish):
        # Only pick one uncontrolled link for mismatch macsec configuration test
        if not unctrl_links:
            pytest.skip('SKIP this test as there are no uncontrolled links in this dut')

        port_name, nbr = list(unctrl_links.items())[0]

        disable_macsec_port(duthost, port_name)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], nbr["port"], profile_name)

        # Wait till macsec session has gone down.
        wait_until(20, 3, 0,
                   lambda: not duthost.iface_macsec_ok(port_name) and
                   not nbr["host"].iface_macsec_ok(nbr["port"]))

        # Set a wrong cak to the profile
        primary_cak = "0" * len(primary_cak)
        enable_macsec_port(duthost, port_name, profile_name)
        set_macsec_profile(nbr["host"], nbr["port"], profile_name, default_priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci)
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)

        def check_mka_establishment():
            _, _, dut_ingress_sc_table, dut_egress_sa_table, dut_ingress_sa_table = get_appl_db(
                duthost, port_name, nbr["host"], nbr["port"])
            return dut_ingress_sc_table or dut_egress_sa_table or dut_ingress_sa_table
        # The mka should be establishing or established
        # To check whether the MKA establishment happened within 90 seconds
        assert not wait_until(90, 1, 12, check_mka_establishment)

        # Teardown
        disable_macsec_port(duthost, port_name)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], nbr["port"], profile_name)
        sleep(300)
