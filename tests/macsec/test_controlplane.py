from time import sleep
import pytest
import logging
import re

from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from .macsec_helper import check_wpa_supplicant_process, check_appl_db, check_mka_session,\
                           get_mka_session, get_sci, get_appl_db, get_ipnetns_prefix
from .macsec_platform_helper import get_platform, get_macsec_ifname

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2"),
]


class TestControlPlane():
    def test_wpa_supplicant_processes(self, duthost, ctrl_links):
        def _test_wpa_supplicant_processes():
            for port_name, nbr in list(ctrl_links.items()):
                check_wpa_supplicant_process(duthost, port_name)
                if isinstance(nbr["host"], EosHost):
                    continue
                check_wpa_supplicant_process(nbr["host"], nbr["port"])
            return True
        assert wait_until(300, 1, 1, _test_wpa_supplicant_processes)

    def test_appl_db(self, duthost, ctrl_links, policy, cipher_suite, send_sci, wait_mka_establish):
        assert wait_until(300, 6, 12, check_appl_db, duthost, ctrl_links, policy, cipher_suite, send_sci)

    def test_mka_session(self, duthost, ctrl_links, policy, cipher_suite, send_sci, wait_mka_establish):
        def _test_mka_session():
            # If the DUT isn't a virtual switch that cannot support "get mka session" by "ip macsec show"
            # So, skip this test for physical switch
            # TODO: Support "get mka session" in the physical switch
            if "x86_64-kvm_x86_64" not in get_platform(duthost):
                # TODO: add check mka session later, now wait some time for session ready
                sleep(30)
                logging.info(
                    "Skip to check mka session due to the DUT isn't a virtual switch")
                return True
            dut_mka_session = get_mka_session(duthost)
            assert len(dut_mka_session) == len(ctrl_links)
            for port_name, nbr in list(ctrl_links.items()):
                if isinstance(nbr["host"], EosHost):
                    assert nbr["host"].iface_macsec_ok(nbr["port"])
                    continue
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
                                  policy, cipher_suite, send_sci)
            return True
        assert wait_until(300, 5, 3, _test_mka_session)

    def test_rekey_by_period(self, duthost, ctrl_links, upstream_links, rekey_period, wait_mka_establish):
        if rekey_period == 0:
            pytest.skip("If the rekey period is 0 which means rekey by period isn't active.")
        assert len(ctrl_links) > 0
        # Only pick one link to test
        port_name, nbr = list(ctrl_links.items())[0]
        _, _, _, last_dut_egress_sa_table, last_dut_ingress_sa_table = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        up_link = upstream_links[port_name]
        tmp_file = "/tmp/rekey_ping.txt"
        # This ping commands may take a long time to confirm the packet loss during rekey rotation,
        # But this time may exceed the maximum timeout of SSH so that the Ansible comes to disconnection.
        duthost.shell(
            "bash -c 'sudo nohup {} ping {} -q -w {} -i 0.1 > {} &'".format(get_ipnetns_prefix(duthost, port_name),
                                                                            up_link["local_ipv4_addr"],
                                                                            rekey_period * 2, tmp_file))
        sleep(rekey_period * 2)
        output = duthost.command("cat {}".format(tmp_file))["stdout_lines"]
        _, _, _, new_dut_egress_sa_table, new_dut_ingress_sa_table = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        assert last_dut_egress_sa_table != new_dut_egress_sa_table
        assert last_dut_ingress_sa_table != new_dut_ingress_sa_table
        assert float(re.search(r"([\d\.]+)% packet loss", output[-2]).group(1)) < 1.0
        duthost.command("rm {}".format(tmp_file))
