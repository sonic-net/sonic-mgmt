import os
import time
import pytest
import httplib

SERVER_FILE = 'platform_api_server.py'
SERVER_PORT = 8000

IPTABLES_PREPEND_RULE_CMD = 'iptables -I INPUT 1 -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)
IPTABLES_DELETE_RULE_CMD = 'iptables -D INPUT -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)

@pytest.fixture(scope='function')
def start_platform_api_service(duthosts, enum_rand_one_per_hwsku_hostname, localhost, request):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_ip = duthost.mgmt_ip

    res = localhost.wait_for(host=dut_ip,
                             port=SERVER_PORT,
                             state='started',
                             delay=1,
                             timeout=5,
                             module_ignore_errors=True)
    if 'exception' in res:
        # TODO: Remove this check once we no longer need to support Python 2
        if request.cls.__name__ == "TestSfpApi" and duthost.facts.get("asic_type") == "mellanox":
            # On Mellanox platform, the SFP APIs are not migrated to python3 yet,
            # thus we have to make it as an exception here.
            py3_platform_api_available = False
        else:
            res = duthost.command('docker exec -i pmon python3 -c "import sonic_platform"', module_ignore_errors=True)
            py3_platform_api_available = not res['failed']

        supervisor_conf = [
            '[program:platform_api_server]',
            'command=/usr/bin/python{} /opt/platform_api_server.py --port {}'.format('3' if py3_platform_api_available else '2', SERVER_PORT),
            'autostart=True',
            'autorestart=True',
            'stdout_logfile=syslog',
            'stderr_logfile=syslog',
        ]
        dest_path = os.path.join(os.sep, 'tmp', 'platform_api_server.conf')
        pmon_path = os.path.join(os.sep, 'etc', 'supervisor', 'conf.d', 'platform_api_server.conf')
        duthost.copy(content='\n'.join(supervisor_conf), dest=dest_path)
        duthost.command('docker cp {} pmon:{}'.format(dest_path, pmon_path))

        src_path = os.path.join('common', 'helpers', 'platform_api', 'scripts', SERVER_FILE)
        dest_path = os.path.join(os.sep, 'tmp', SERVER_FILE)
        pmon_path = os.path.join(os.sep, 'opt', SERVER_FILE)
        duthost.copy(src=src_path, dest=dest_path)
        duthost.command('docker cp {} pmon:{}'.format(dest_path, pmon_path))

        # Prepend an iptables rule to allow incoming traffic to the HTTP server
        duthost.command(IPTABLES_PREPEND_RULE_CMD)

        # Reload the supervisor config and Start the HTTP server
        duthost.command('docker exec -i pmon supervisorctl reread')
        duthost.command('docker exec -i pmon supervisorctl update')

        res = localhost.wait_for(host=dut_ip, port=SERVER_PORT, state='started', delay=1, timeout=5)
        assert 'exception' not in res


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
                                module_ignore_errors=True)['stdout_lines']
            platform_api_service_state = [line.strip().split()[1] for line in out][0]
            if platform_api_service_state == 'RUNNING':
                duthost.command('docker exec -i pmon supervisorctl stop platform_api_server')
                duthost.command('docker exec -i pmon rm -f {}'.format(pmon_path_supervisor))
                duthost.command('docker exec -i pmon rm -f {}'.format(pmon_path_script))
                duthost.command('docker exec -i pmon supervisorctl reread')
                duthost.command('docker exec -i pmon supervisorctl update')

                # Delete the iptables rule we added
                duthost.command(IPTABLES_DELETE_RULE_CMD)


@pytest.fixture(scope='function')
def platform_api_conn(duthosts, enum_rand_one_per_hwsku_hostname, start_platform_api_service):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_ip = duthost.mgmt_ip

    conn = httplib.HTTPConnection(dut_ip, SERVER_PORT)
    try:
        yield conn
    finally:
        conn.close()
