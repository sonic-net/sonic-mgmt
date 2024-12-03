import pytest
import logging

from tests.common.utilities import wait_until
from tests.common import config_reload
from tests.common.macsec.macsec_helper import check_appl_db, get_appl_db
from time import sleep
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


class TestDeployment():
    MKA_TIMEOUT = 6

    @pytest.mark.disable_loganalyzer
    def test_config_reload(self, duthost, ctrl_links, policy, cipher_suite, send_sci, wait_mka_establish):
        # Save the original config file
        duthost.shell("cp /etc/sonic/config_db*.json /tmp")
        # Save the current config file
        duthost.shell("config save -y")
        config_reload(duthost)
        assert wait_until(300, 6, 12, check_appl_db, duthost, ctrl_links, policy, cipher_suite, send_sci)
        # Recover the original config file
        duthost.shell("sudo mv /tmp/config_db*.json /etc/sonic")

    @pytest.mark.disable_loganalyzer
    def test_scale_rekey(self, duthost, ctrl_links, rekey_period, wait_mka_establish):
        dut_egress_sa_table_orig = {}
        dut_ingress_sa_table_orig = {}
        dut_egress_sa_table_current = {}
        dut_ingress_sa_table_current = {}
        new_dut_egress_sa_table = {}
        new_dut_ingress_sa_table = {}

        # Shut the interface and wait for all macsec sessions to be down
        for dut_port, nbr in ctrl_links.items():
            _, _, _, dut_egress_sa_table_orig[dut_port], dut_ingress_sa_table_orig[dut_port] = get_appl_db(
                duthost, dut_port, nbr["host"], nbr["port"])
            intf_asic = duthost.get_port_asic_instance(dut_port)
            intf_asic.shutdown_interface(dut_port)

        sleep(TestDeployment.MKA_TIMEOUT)

        # Unshut the interfaces so that macsec sessions come back up
        for dut_port, nbr in ctrl_links.items():
            intf_asic = duthost.get_port_asic_instance(dut_port)
            intf_asic.startup_interface(dut_port)

        for dut_port, nbr in ctrl_links.items():
            def check_new_mka_session():
                _, _, _, dut_egress_sa_table_current[dut_port], dut_ingress_sa_table_current[dut_port] = get_appl_db(
                    duthost, dut_port, nbr["host"], nbr["port"])
                assert dut_egress_sa_table_orig[dut_port] != dut_egress_sa_table_current[dut_port]
                assert dut_ingress_sa_table_orig[dut_port] != dut_ingress_sa_table_current[dut_port]
                return True
            assert wait_until(30, 2, 2, check_new_mka_session)

        # if rekey_period for the profile is valid, Wait for rekey and make sure all sessions are present
        if rekey_period != 0:
            sleep(rekey_period * 2)

            for dut_port, nbr in ctrl_links.items():
                _, _, _, new_dut_egress_sa_table[dut_port], new_dut_ingress_sa_table[dut_port] = get_appl_db(
                    duthost, dut_port, nbr["host"], nbr["port"])
                assert dut_egress_sa_table_current[dut_port] != new_dut_egress_sa_table[dut_port]
                assert dut_ingress_sa_table_current[dut_port] != new_dut_ingress_sa_table[dut_port]
