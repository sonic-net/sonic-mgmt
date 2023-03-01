import pytest
import logging
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import wait
from isis_helpers import DEFAULT_ISIS_INSTANCE as isis_instance
from conftest import get_dut_port_p2p
from isis_helpers import get_nbr_name

DOCUMENTATION = '''
short_description: Test SONiC authentication password protection
description:
    - Config area password or interface password before ISIS connection established.
    - Verify connectivity to neighbors by checking routing table.
'''

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan-com'),
]

ITF_AUTH_PASSWRD = 'itf_auth'
AREA_AUTH_PASSWRD = 'area_auth'


def test_isis_no_auth(isis_common_setup_teardown, nbrhosts, tbinfo):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name) = collect_dut_nbrs(
        selected_connections, nbrhosts, tbinfo
        )
    pytest_assert(wait_until(30, 2, 0, check_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "Routing to ISIS Neighbor {} is missing".format(nbr_name))


@pytest.mark.parametrize("auth_type", ["text", "md5"])
def test_isis_itf_auth(isis_common_setup_teardown, nbrhosts, tbinfo, auth_type):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name) = collect_dut_nbrs(
        selected_connections, nbrhosts, tbinfo
        )

    nbr_host.shutdown(nbr_port)
    wait(5, "Clear up existing ISIS hop from routing table.")
    logger.debug(dut_host.shell("show ip route")['stdout'])

    cmd = "isis password {} {}".format("md5" if "md5" == auth_type else "clear", ITF_AUTH_PASSWRD)
    dut_host.shell("vtysh -c \"conf t\" -c \"interface {}\" -c \"{}\"".format(dut_port, cmd))
    nbr_host.eos_config(
                              lines=['isis authentication mode {}'.format(auth_type),
                                     "isis authentication key {}".format(ITF_AUTH_PASSWRD)],
                              parents=['interface {}'.format(nbr_port)])

    # Reboot interface to make ISIS connection.
    nbr_host.no_shutdown(nbr_port)
    logger.info(dut_host.shell("vtysh -c 'show run'")['stdout'])

    logger.info(nbr_host.eos_command(commands=['show run'])['stdout_lines'][0])
    pytest_assert(wait_until(40, 2, 0, check_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "Routing to ISIS Neighbor {} is missing".format(nbr_name))


@pytest.mark.parametrize("auth_type", ["text", "md5"])
def test_isis_area_auth(isis_common_setup_teardown, nbrhosts, tbinfo, auth_type):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name) = collect_dut_nbrs(
        selected_connections, nbrhosts, tbinfo
        )
    nbr_host.shutdown(nbr_port)

    wait(5, "Clear up existing ISIS hop from routing table.")
    logger.debug(dut_host.shell("show ip route")['stdout'])

    cmd = "area-password {} {}".format("md5" if "md5" == auth_type else "clear", AREA_AUTH_PASSWRD)
    dut_host.shell("vtysh -c \"conf t\" \"-c router isis {}\" -c \"{}\"".format(isis_instance, cmd))
    nbr_host.eos_config(
                              lines=['authentication mode {}'.format(auth_type),
                                     "authentication key {}".format(AREA_AUTH_PASSWRD)],
                              parents=['router isis {}'.format(isis_instance)])

    # Reboot interface to make ISIS connection.
    nbr_host.no_shutdown(nbr_port)
    logger.info(dut_host.shell("vtysh -c 'show run'")['stdout'])
    logger.info(nbr_host.eos_command(commands=['show run'])['stdout_lines'][0])
    pytest_assert(wait_until(40, 2, 0, check_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "Routing to ISIS Neighbor {} is missing".format(nbr_name))


def collect_dut_nbrs(selected_connections, nbrhosts, tbinfo):
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]
    nbr_name = get_nbr_name(nbrhosts, nbr_host)
    mg_facts = dut_host.get_extended_minigraph_facts(tbinfo)
    (dut_p2p, nbr_p2p) = get_dut_port_p2p(mg_facts, dut_port)
    return (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name)


def check_isis_routing_to_nbr(dut_host, dut_port, dut_p2p, nbr_p2p):
    routing = dut_host.shell("show ip route")['stdout']
    logger.debug(routing)
    cond = re.search(r"I\s+{}.*?via\s+{},\s+{}.*".format(dut_p2p, nbr_p2p, dut_port), routing)
    return False if cond is None else True
