import os
import time
import pytest
import httplib

SERVER_FILE = 'platform_api_server.py'
SERVER_PORT = 8000

IPTABLES_PREPEND_RULE_CMD = 'iptables -I INPUT 1 -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)
IPTABLES_DELETE_RULE_CMD = 'iptables -D INPUT -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)

@pytest.fixture(scope='function')
def start_platform_api_service(duthost, localhost):
    dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']

    res = localhost.wait_for(host=dut_ip,
                             port=SERVER_PORT,
                             state='started',
                             delay=1,
                             timeout=5,
                             module_ignore_errors=True)
    if 'exception' in res:
        supervisor_conf = [
            "[program:platform_api_server]",
            "command=/usr/bin/python /opt/platform_api_server.py --port {}".format(SERVER_PORT),
            "autostart=True",
            "autorestart=True",
            "stdout_logfile=syslog",
            "stderr_logfile=syslog",
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
def stop_platform_api_service(duthost):
    try:
        yield
    finally:
        # Stop the server and remove our supervisor config changes
        pmon_path_supervisor = os.path.join(os.sep, 'etc', 'supervisor', 'conf.d', 'platform_api_server.conf')
        pmon_path_script = os.path.join(os.sep, 'opt', SERVER_FILE)
        duthost.command('docker exec -i pmon supervisorctl stop platform_api_server')
        duthost.command('docker exec -i pmon rm -f {}'.format(pmon_path_supervisor))
        duthost.command('docker exec -i pmon rm -f {}'.format(pmon_path_script))
        duthost.command('docker exec -i pmon supervisorctl reread')
        duthost.command('docker exec -i pmon supervisorctl update')

        # Delete the iptables rule we added
        duthost.command(IPTABLES_DELETE_RULE_CMD)

@pytest.fixture(scope='function')
def platform_api_conn(duthost, start_platform_api_service):
    dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']

    conn = httplib.HTTPConnection(dut_ip, SERVER_PORT)
    try:
        yield conn
    finally:
        conn.close()
