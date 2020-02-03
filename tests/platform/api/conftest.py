import os
import time
import pytest
import httplib

SERVER_FILE = 'platform_api_server.py'
SERVER_PORT = 8000

@pytest.fixture(scope='function')
def start_platform_api_service(duthost, testbed_devices):
    localhost = testbed_devices['localhost']
    res = localhost.wait_for(host=duthost.hostname, port=SERVER_PORT, state='started', delay=1, timeout=5)
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

        duthost.command('docker exec -i pmon supervisorctl reread')
        duthost.command('docker exec -i pmon supervisorctl update')
        duthost.command('docker exec -i pmon supervisorctl start platform_api_server.conf')

        res = localhost.wait_for(host=duthost.hostname, port=SERVER_PORT, state='started', delay=1, timeout=5)
        assert 'exception' not in res


@pytest.fixture(scope='module', autouse=True)
def stop_platform_api_service(duthost):
    try:
        yield
    finally:
        pmon_path_supervisor = os.path.join(os.sep, 'etc', 'supervisor', 'conf.d', 'platform_api_server.conf')
        pmon_path_script = os.path.join(os.sep, 'opt', SERVER_FILE)
        duthost.command('docker exec -i pmon supervisorctl stop platform_api_server')
        duthost.command('docker exec -i pmon rm -f {}'.format(pmon_path_supervisor))
        duthost.command('docker exec -i pmon rm -f {}'.format(pmon_path_script))
        duthost.command('docker exec -i pmon supervisorctl reread')
        duthost.command('docker exec -i pmon supervisorctl update')

@pytest.fixture(scope='function')
def platform_api_conn(duthost, start_platform_api_service):
    conn = httplib.HTTPConnection(duthost.hostname, SERVER_PORT)
    try:
        yield conn
    finally:
        conn.close()
