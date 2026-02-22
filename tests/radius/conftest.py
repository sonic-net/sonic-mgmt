import logging
import pytest
from tests.common.errors import RunAnsibleModuleFail
from .utils import load_radius_creds

logger = logging.getLogger(__name__)

SKIP_RADIUS_TESTS = False
FREE_RADIUS_CONF_DIR = "/etc/freeradius/3.0"


def radius_installed(ptfhost):
    """
    check is freeradius package is installed on ptf
    """
    out = ptfhost.command("freeradius -v")["stdout"]
    return "FreeRADIUS Version" in out


def stop_radius_server(ptfhost):
    """
    stop the FreeRADIUS server running on the ptfhost
    by killing the process ID.
    """
    # Find the PID of the FreeRADIUS process
    find_pid_command = (
        "ps aux | grep freeradius | grep -v grep | awk '{print $2}'"
    )
    pid_result = ptfhost.shell(find_pid_command)
    logger.debug("freeRADIUS PIDS: {}".format(pid_result))
    if pid_result["stdout_lines"]:
        for pid in pid_result["stdout_lines"]:
            kill_command = f"kill -9 {pid}"
            ptfhost.shell(kill_command)

    ptfhost.shell("rm -rf /tmp/freeradius.log")


def remove_radius_commands(duthost, ptf_mgmt_ip):
    """Remove AAA/RADIUS config"""
    cmds = [
        "config radius default nasip",
        "config radius default passkey",
        "config radius default authtype",
        "config radius statistics default",
        "config radius delete {}".format(ptf_mgmt_ip),
        "config aaa authentication login default",
        "config aaa authentication failthrough default",
    ]

    duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="module")
def radius_creds(creds_all_duts):
    """load radius creds into test fixures"""
    test_creds = load_radius_creds()
    creds_all_duts.update(test_creds)
    return creds_all_duts


@pytest.fixture(scope="module", autouse=True)
def run_radius_check(ptfhost):
    """Checking to see if freeRADIUS packages are installed in ptf"""
    SKIP_RADIUS_TESTS = not radius_installed(ptfhost)
    yield SKIP_RADIUS_TESTS


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """Skipping tests if no freeRADIUS is installed"""
    if SKIP_RADIUS_TESTS:
        pytest.skip(
            "Skipping RADIUS tests because RADIUS server not installed"
        )


@pytest.fixture(scope="module", autouse=True)
def setup_radius_server(
    ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, radius_creds
):
    """Settinng up freeRADIUS server on ptf host"""
    logger.debug("setting up freeRADIUS server")
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    extra_info = {}
    extra_info = radius_creds
    extra_info["duthost_mgmt_ip"] = duthost.mgmt_ip

    ptfhost.host.options["variable_manager"].extra_vars.update(extra_info)
    logging.debug(ptfhost.host.options["variable_manager"].extra_vars)
    ptfhost.template(
        src="radius/clients.conf.j2",
        dest="{}/clients.conf".format(FREE_RADIUS_CONF_DIR),
    )

    ptfhost.template(
        src="radius/users.j2",
        dest="{}/mods-config/files/authorize".format(FREE_RADIUS_CONF_DIR),
    )

    try:
        logging.debug("starting freeRADIUS server on ptfhost")
        ptfhost.shell("rm -rf /tmp/freeradius.log")
        # this starts in daemon mode by default
        ptfhost.shell("freeradius -xxl /tmp/freeradius.log")
    except RunAnsibleModuleFail:
        # most likely left over instance runninng
        stop_radius_server(ptfhost)
        ptfhost.shell("freeradius")

    yield

    stop_radius_server(ptfhost)


@pytest.fixture(scope="module", autouse=True)
def setup_radius_client(
    ptfhost, duthosts, radius_creds, enum_rand_one_per_hwsku_hostname
):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ping_result = duthost.shell(
        "ping {} -c 1 -W 3".format(ptfhost.mgmt_ip), module_ignore_errors=True
    )["stdout"]
    logger.info("RADIUS server ping result: {}".format(ping_result))
    if "100% packet loss" in ping_result:
        assert False, "RADIUS server not reachable"

    logger.debug("configuring RADIUS client")

    # configure NAS-IP
    duthost.shell("sudo config radius nasip {}".format(duthost.mgmt_ip))

    # configure RADIUS server
    duthost.shell(
        "sudo config radius add {} --key {}".format(
            ptfhost.mgmt_ip, radius_creds["radius_secret"]
        )
    )

    # configure radius statistics
    duthost.shell("sudo config radius statistics enable")

    # enable radius for login  allow failthrough for admin user
    duthost.shell("sudo config aaa authentication login radius local")
    duthost.shell("sudo config aaa authentication failthrough enable")

    yield

    remove_radius_commands(duthost, ptfhost.mgmt_ip)


@pytest.fixture(scope="module", autouse=True)
def routed_interfaces(
    duthosts, enum_rand_one_per_hwsku_hostname, enum_frontend_asic_index
):
    """
    Find routed interface to test

    Args:
        duthosts: DUT hosts fixture
        enum_rand_one_per_hwsku_frontend_hostname: DUT fixture
        enum_frontend_asic_index: asic index fixture

    Retruns:
        routedInterfaces (Tuple): Routed interface used for testing
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    test_routed_interfaces = []

    intf_status = duthost.show_ip_interface()["ansible_facts"]["ip_interfaces"]
    logger.debug(intf_status)
    for intf, status in list(intf_status.items()):
        if "up" in status["oper_state"]:
            test_routed_interfaces.append((intf, status["ipv4"]))
            if len(test_routed_interfaces) == 2:
                break

    yield test_routed_interfaces
