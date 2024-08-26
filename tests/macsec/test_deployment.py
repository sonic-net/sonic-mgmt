import pytest
import logging

from tests.common.utilities import wait_until
from tests.common import config_reload
from tests.common.macsec.macsec_helper import check_appl_db
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


class TestDeployment():
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
