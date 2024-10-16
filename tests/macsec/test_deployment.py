import pytest
import logging
import time

from tests.common.utilities import wait_until
from tests.common import config_reload
from .macsec_helper import check_appl_db
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2"),
]


class TestDeployment():
    @pytest.mark.disable_loganalyzer
    def test_config_reload(self, duthost, ctrl_links, policy, cipher_suite, send_sci, wait_mka_establish):
        # Save the original config file
        duthost.shell("cp /etc/sonic/config_db.json config_db.json")
        # Save the current config file
        duthost.shell("sonic-cfggen -d --print-data > /etc/sonic/config_db.json")
        config_reload(duthost)
        assert wait_until(300, 6, 12, check_appl_db, duthost, ctrl_links, policy, cipher_suite, send_sci)
        # Recover the original config file
        duthost.shell("sudo cp config_db.json /etc/sonic/config_db.json")

    # Test to try and delete and add an in use policy
    def test_delete_add_policy(self, macsec_duthost, ctrl_links, profile_name, default_priority,
                               cipher_suite, primary_cak, primary_ckn, policy, rekey_period):
        port_name, nbr = list(ctrl_links.items())[0]
        if macsec_duthost.is_multi_asic:
            ns = " -n " + macsec_duthost.get_port_asic_instance(port_name).namespace
        else:
            ns = ''

        # Ensure the expected error is thrown
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
