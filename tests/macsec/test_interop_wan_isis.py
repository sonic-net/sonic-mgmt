import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.macsec.macsec_platform_helper import get_portchannel
from tests.common.macsec.macsec_platform_helper import find_portchannel_from_member
from tests.common.macsec.macsec_config_helper import enable_macsec_port, disable_macsec_port


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("wan-pub-isis"),
]


'''
Macsec interop with is-is protocols
'''

ISIS_HOLDTIME = 30


def check_isis_established(duthost, nbr_name):
    isis_facts = duthost.isis_facts()["ansible_facts"]['isis_facts']

    if nbr_name not in isis_facts['neighbors']['1'].keys():
        return False
    logger.info("isis state {}".format(isis_facts['neighbors']['1'][nbr_name]['state']))
    return isis_facts['neighbors']['1'][nbr_name]['state'] == "Up"


def get_portchannel_state(duthost, ctrl_port):
    # Wait PortChannel up, which might flap if having one port member
    return wait_until(ISIS_HOLDTIME, 5, 5, lambda: find_portchannel_from_member(
                    ctrl_port, get_portchannel(duthost))["status"] == "Up")


def verify_isis_established_result(duthost, ctrl_port, nbr):
    # Check IS-IS neighbor when PortChannel is UP
    if get_portchannel_state(duthost, ctrl_port):
        pytest_assert(wait_until(ISIS_HOLDTIME, 6, 5, check_isis_established, duthost, nbr['name']),
                      "IS-IS neighbor is not UP.")


@pytest.mark.disable_loganalyzer
def test_isis_over_macsec(tbinfo, duthost, ctrl_links, upstream_links, profile_name, wait_mka_establish):
    if tbinfo['topo']['name'] != 'wan-pub-isis':
        pytest.skip("Skip as isis over macsec test only support on wan-pub-isis vtestbed")

    # Ensure the IS-IS sessions have been established
    for ctrl_port, nbr in ctrl_links.items():
        verify_isis_established_result(duthost, ctrl_port, nbr)

    # Check the IS-IS sessions are present after port macsec disabled
    for ctrl_port, nbr in ctrl_links.items():
        disable_macsec_port(duthost, ctrl_port)
        disable_macsec_port(nbr["host"], nbr["port"])
        wait_until(ISIS_HOLDTIME, 3, 0,
                   lambda: not duthost.iface_macsec_ok(ctrl_port) and
                   not nbr["host"].iface_macsec_ok(nbr["port"]))
        verify_isis_established_result(duthost, ctrl_port, nbr)

    # Check the IS-IS sessions are present after port macsec enabled
    for ctrl_port, nbr in ctrl_links.items():
        enable_macsec_port(duthost, ctrl_port, profile_name)
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)
        wait_until(ISIS_HOLDTIME, 3, 0,
                   lambda: duthost.iface_macsec_ok(ctrl_port) and
                   nbr["host"].iface_macsec_ok(nbr["port"]))
        verify_isis_established_result(duthost, ctrl_port, nbr)
