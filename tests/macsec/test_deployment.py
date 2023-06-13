import pytest
import logging

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
