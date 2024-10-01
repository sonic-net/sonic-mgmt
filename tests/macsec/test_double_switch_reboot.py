import pytest
import logging
import time

from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.common.platform.interface_utils import \
    check_interface_status_of_up_ports
from tests.common.platform.processes_utils import wait_critical_processes
from tests.macsec.macsec_helper import check_appl_db

SONIC_SSH_PORT = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'

logger = logging.getLogger(__name__)
post_reboot_time = 240

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("any")
]

def reboot_nbr(nbrhost):
    # Save the original config file
    nbrhost.shell("cp /etc/sonic/config_db.json config_db.json")
    # Save the current config file
    nbrhost.shell("sonic-cfggen -d --print-data > /etc/sonic/config_db.json")
    nbrhost.command("sudo reboot")['stdout']
    time.sleep(10)


@pytest.mark.disable_loganalyzer
def test_double_switch_reboot(duthosts, enum_frontend_dut_hostname, nbrhosts,
                              localhost, ctrl_links, policy, cipher_suite, send_sci):
    """
     This test case reboots dut and neighbor, wait for critical porcesses then
     ensure all interfaces are up, Check appl_db and that route summary count
     are equal pre and post reboot.
    """

    duthost = duthosts[enum_frontend_dut_hostname]
    tor1 = duthost.shell("show lldp table")['stdout'].split("\n")[5].split()[1]
    nbrhost = nbrhosts[tor1]["host"]

    reboot_nbr(nbrhost)
    reboot(duthost, localhost, wait=post_reboot_time)

    wait_critical_processes(duthost)

    assert wait_until(300, 60, 0, check_interface_status_of_up_ports,
                      duthost), "Could not confirm interface status up \
                        on all any/all ports"

    assert wait_until(300, 6, 12, check_appl_db, duthost, ctrl_links, policy,
                      cipher_suite, send_sci)
