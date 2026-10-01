import os
import pytest

from tests.common.helpers.platform_api import psu
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

SERVER_FILE = 'platform_api_server.py'
SERVER_PORT = 8000

IPTABLES_DELETE_RULE_CMD = 'iptables -D INPUT -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)
IP6TABLES_DELETE_RULE_CMD = 'ip6tables -D INPUT -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)

# Upper bound on how many copies of the rule we try to remove. start_platform_api_service
# is function scoped and re-adds the rule every time the server is unreachable, so a server
# that dies part way through a module can leave more than one copy behind.
MAX_RULE_DELETE_ATTEMPTS = 10


def _remove_server_port_rules(duthost):
    """
    Remove every copy of the port 8000 ACCEPT rule this test run may have added.

    start_platform_api_service adds either the IPv4 or the IPv6 rule depending on the
    management address family, never both, so one of these deletes is expected to be a
    no-op. "iptables -D" removes a single matching rule, so keep deleting until there is
    nothing left to remove.

    Errors are ignored throughout: after a reboot test the DUT has power cycled and the
    rule is already gone, which is not a failure.
    """
    for delete_cmd in (IPTABLES_DELETE_RULE_CMD, IP6TABLES_DELETE_RULE_CMD):
        for _ in range(MAX_RULE_DELETE_ATTEMPTS):
            result = duthost.command(delete_cmd, module_ignore_errors=True)
            # Default to non-zero so anything that does not report an rc, such as an
            # unreachable host, stops the loop instead of raising KeyError.
            if result.get('rc', 1) != 0:
                break


def skip_absent_psu(psu_num, platform_api_conn, psu_skip_list, logger):    # noqa: F811
    name = psu.get_name(platform_api_conn, psu_num)
    if name in psu_skip_list:
        logger.info("Skipping PSU {} since it is part of psu_skip_list".format(name))
        return True
    return False


@pytest.fixture(scope='module', autouse=True)
def stop_platform_api_service(duthosts):
    try:
        yield
    finally:
        for duthost in duthosts:
            # Remove the port 8000 rules first. The checks below can raise, for example when
            # pmon is not running and the supervisorctl status output is empty, and the rules
            # have to come off regardless or they leak into the rest of the session and trip a
            # later cacl run. Nothing after this point needs the port: the remaining commands
            # all go over SSH via "docker exec".
            _remove_server_port_rules(duthost)

            # Stop the server and remove our supervisor config changes
            pmon_path_supervisor = os.path.join(os.sep, 'etc', 'supervisor', 'conf.d', 'platform_api_server.conf')
            pmon_path_script = os.path.join(os.sep, 'opt', SERVER_FILE)

            # Check if platform_api_server running in the pmon docker and only then stop it. Else we would fail,
            # and not stop on other DUT's
            out = duthost.shell('docker exec pmon supervisorctl status platform_api_server',
                                module_ignore_errors=True)

            # ensure pmon is still up
            if out.get('stderr_lines') and "Error response from daemon" in out['stderr_lines']:
                pytest.fail(f"pmon is not running after tests {out['stderr_lines']}")

            platform_api_service_state = [line.strip().split()[1] for line in out['stdout_lines']][0]
            if platform_api_service_state == 'RUNNING':
                duthost.command('docker exec -i pmon supervisorctl stop platform_api_server')
                duthost.command('docker exec -i pmon rm -f {}'.format(pmon_path_supervisor))
                duthost.command('docker exec -i pmon rm -f {}'.format(pmon_path_script))
                duthost.command('docker exec -i pmon supervisorctl reread')
                duthost.command('docker exec -i pmon supervisorctl update')


@pytest.fixture(autouse=True)
def check_not_implemented_warnings(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="platformapi_test")
    marker = loganalyzer.init()
    yield
    loganalyzer.match_regex.extend(['WARNING pmon#platform_api_server.py: API.+not implemented'])
    loganalyzer.analyze(marker)
