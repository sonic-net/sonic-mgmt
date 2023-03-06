import pytest
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import wait
from isis_helpers import DEFAULT_ISIS_INSTANCE as isis_instance
from isis_helpers import config_sonic_isis
from isis_helpers import config_nbr_isis
from isis_helpers import remove_nbr_isis_config
from isis_helpers import remove_sonic_isis_config
from conftest import get_dut_port_p2p
from isis_helpers import get_nbr_name

DOCUMENTATION = '''
short_description: Test SONiC authentication password protection
description:
    - Config area password or interface password before ISIS connection established.
    - Verify connectivity to neighbors by checking routing table.
'''

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
    reset_isis_config(dut_host, nbr_host)
    pytest_assert(wait_until(30, 2, 0, check_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "Routing to neighbor {} is missing".format(nbr_name))


@pytest.mark.parametrize("auth_type", ["text", "md5"])
def test_isis_itf_auth(isis_common_setup_teardown, nbrhosts, tbinfo, auth_type):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name) = collect_dut_nbrs(
        selected_connections, nbrhosts, tbinfo
        )

    reset_isis_config(dut_host, nbr_host)
    nbr_host.shutdown(nbr_port)
    wait(5, "Clear up existing ISIS hop from routing table.")

    config_dut_isis_auth(auth_type, ITF_AUTH_PASSWRD, dut_host, dut_port)
    config_nbr_isis_auth(auth_type, ITF_AUTH_PASSWRD, nbr_host, nbr_port)

    # Reboot interface to make ISIS connection.
    nbr_host.no_shutdown(nbr_port)

    pytest_assert(wait_until(40, 2, 0, check_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "ISIS routing to neighbor {} is missing".format(nbr_name))


@pytest.mark.parametrize("auth_type", ["text", "md5"])
def test_isis_area_auth(isis_common_setup_teardown, nbrhosts, tbinfo, auth_type):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name) = collect_dut_nbrs(
        selected_connections, nbrhosts, tbinfo
        )
    reset_isis_config(dut_host, nbr_host)
    nbr_host.shutdown(nbr_port)
    wait(5, "Clear up existing ISIS hop from routing table.")

    config_dut_isis_auth(auth_type, AREA_AUTH_PASSWRD, dut_host, None)
    config_nbr_isis_auth(auth_type, AREA_AUTH_PASSWRD, nbr_host, None)

    # Reboot interface to make ISIS connection.
    nbr_host.no_shutdown(nbr_port)

    pytest_assert(wait_until(40, 2, 0, check_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "ISIS routing to neighbor {} is missing".format(nbr_name))


@pytest.mark.parametrize("auth_type", ["text", "md5"])
def test_isis_itf_auth_wrong_password(isis_common_setup_teardown, nbrhosts, tbinfo, auth_type):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name) = collect_dut_nbrs(
        selected_connections, nbrhosts, tbinfo
        )
    reset_isis_config(dut_host, nbr_host)
    pytest_assert(wait_until(30, 2, 0, check_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "ISIS routing to neighbor {} is missing".format(nbr_name))

    config_dut_isis_auth(auth_type, ITF_AUTH_PASSWRD, dut_host, dut_port)
    config_nbr_isis_auth(auth_type, AREA_AUTH_PASSWRD, nbr_host, nbr_port)

    pytest_assert(wait_until(60, 2, 0, check_no_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "ISIS routing to neighbor {} should not be available".format(nbr_name))


@pytest.mark.parametrize("auth_type", ["text", "md5"])
def test_isis_area_itf_auth(isis_common_setup_teardown, nbrhosts, tbinfo, auth_type):
    selected_connections = isis_common_setup_teardown
    (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name) = collect_dut_nbrs(
        selected_connections, nbrhosts, tbinfo
        )
    reset_isis_config(dut_host, nbr_host)
    nbr_host.shutdown(nbr_port)
    wait(5, "Clear up existing ISIS hop from routing table.")

    config_dut_isis_auth(auth_type, ITF_AUTH_PASSWRD, dut_host, dut_port)
    config_nbr_isis_auth(auth_type, ITF_AUTH_PASSWRD, nbr_host, nbr_port)
    config_dut_isis_auth(auth_type, AREA_AUTH_PASSWRD, dut_host, None)
    config_nbr_isis_auth(auth_type, AREA_AUTH_PASSWRD, nbr_host, None)

    # Reboot interface to make ISIS connection.
    nbr_host.no_shutdown(nbr_port)

    pytest_assert(wait_until(40, 2, 0, check_isis_routing_to_nbr, dut_host, dut_port, dut_p2p, nbr_p2p),
                  "ISIS routing to neighbor {} is missing".format(nbr_name))


def config_dut_isis_auth(auth_type, auth_passwd, dut_host, dut_port):
    auth_type = "md5" if "md5" == auth_type else "clear"
    cmd = "vtysh -c \"conf t\""
    if dut_port is None:
        cmd += " -c \"router isis {}\"".format(isis_instance)
        cmd += " -c \"area-password {} {}\"".format(auth_type, auth_passwd)
    else:
        cmd += " -c \"interface {}\"".format(dut_port)
        cmd += " -c \"isis password {} {}\"".format(auth_type, auth_passwd)

    dut_host.shell(cmd)


def config_nbr_isis_auth(auth_type, auth_passwd, nbr_host, nbr_port):
    if nbr_port is None:
        nbr_host.eos_config(
                              lines=['authentication mode {}'.format(auth_type),
                                     "authentication key {}".format(auth_passwd)],
                              parents=['router isis {}'.format(isis_instance)])
    else:
        nbr_host.eos_config(
                                lines=['isis authentication mode {}'.format(auth_type),
                                       "isis authentication key {}".format(auth_passwd)],
                                parents=['interface {}'.format(nbr_port)])


def collect_dut_nbrs(selected_connections, nbrhosts, tbinfo):
    (dut_host, dut_port, nbr_host, nbr_port) = selected_connections[0]
    nbr_name = get_nbr_name(nbrhosts, nbr_host)
    mg_facts = dut_host.get_extended_minigraph_facts(tbinfo)
    (dut_p2p, nbr_p2p) = get_dut_port_p2p(mg_facts, dut_port)
    return (dut_host, dut_port, dut_p2p, nbr_host, nbr_port, nbr_p2p, mg_facts, nbr_name)


def check_isis_routing_to_nbr(dut_host, dut_port, dut_p2p, nbr_p2p):
    routing = dut_host.shell("show ip route")['stdout']
    cond = re.search(r"I\s+{}.*?via\s+{},\s+{}.*".format(dut_p2p, nbr_p2p, dut_port), routing)
    return False if cond is None else True


def check_no_isis_routing_to_nbr(dut_host, dut_port, dut_p2p, nbr_p2p):
    return not check_isis_routing_to_nbr(dut_host, dut_port, dut_p2p, nbr_p2p)


def reset_isis_config(dut_host, nbr_host):
    remove_sonic_isis_config(dut_host)
    remove_nbr_isis_config(nbr_host)
    config_sonic_isis(dut_host)
    config_nbr_isis(nbr_host)
