import os
import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

SERVER_FILE = 'platform_api_server.py'
SERVER_PORT = 8000

IPTABLES_DELETE_RULE_CMD = 'iptables -D INPUT -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)


@pytest.fixture(scope='module', autouse=True)
def stop_platform_api_service(duthosts):
    try:
        yield
    finally:
        for duthost in duthosts:
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

                # We ignore errors here because after a reboot test, the DUT will have power-cycled and will
                # no longer have the rule we added in the start_platform_api_service fixture, even if the
                # platform_api_server is running.
                duthost.command(IPTABLES_DELETE_RULE_CMD, module_ignore_errors=True)


@pytest.fixture(autouse=True)
def check_not_implemented_warnings(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="platformapi_test")
    marker = loganalyzer.init()
    yield
    loganalyzer.match_regex.extend(['WARNING pmon#platform_api_server.py: API.+not implemented'])
    loganalyzer.analyze(marker)
