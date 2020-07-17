import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

# Helper functions
def get_dict_stdout(gnmi_out, certs_out):
    """ Extracts dictionary from redis output.
    """
    gnmi_list = []
    gnmi_list = get_list_stdout(gnmi_out) + get_list_stdout(certs_out)
    # Elements in list alternate between key and value. Separate them and combine into a dict.
    key_list = gnmi_list[0::2]
    value_list = gnmi_list[1::2]
    params_dict = dict(zip(key_list, value_list))
    return params_dict

def get_list_stdout(cmd_out):
    out_list = []
    for x in cmd_out:
        result = x.encode('UTF-8')
        out_list.append(result)
    return out_list

def restart_telemetry(duthost):
    """ Restart telemetry process
    """
    duthost.shell('sudo config feature telemetry disabled', module_ignore_errors=False)['stdout_lines']
    status_out = duthost.shell('show features | grep telemetry', module_ignore_errors=False)['stdout_lines']
    status_value = get_list_stdout(status_out)
    status_value_list = status_value[0].split()
    status_value = status_value_list[1]
    if str(status_value) == "disabled":
        logger.info(' telemetry is disabled. enabling it back...')
        duthost.shell('sudo config feature telemetry enabled', module_ignore_errors=False)['stdout_lines']
        return True
    return False

# Test functions
def test_config_db_parameters(duthost):
    """Verifies required telemetry parameters from config_db.
    """
    gnmi = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "TELEMETRY|gnmi"', module_ignore_errors=False)['stdout_lines']
    pytest_assert(gnmi is not None, "TELEMETRY|gnmi does not exist in config_db")

    certs = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "TELEMETRY|certs"', module_ignore_errors=False)['stdout_lines']
    pytest_assert(certs is not None, "TELEMETRY|certs does not exist in config_db")

    d = get_dict_stdout(gnmi, certs)
    for key, value in d.items():
        if str(key) == "client_auth":
            client_auth_expected = "true"
            pytest_assert(str(value) == client_auth_expected, "'client_auth' value is not '{}'".format(client_auth_expected))
        if str(key) == "port":
            port_expected = "50051"
            pytest_assert(str(value) == port_expected, "'port' value is not '{}'".format(port_expected))
        if str(key) == "ca_crt":
            ca_crt_value_expected = "/etc/sonic/telemetry/dsmsroot.cer"
            pytest_assert(str(value) == ca_crt_value_expected, "'ca_crt' value is not '{}'".format(ca_crt_value_expected))
        if str(key) == "server_key":
            server_key_expected = "/etc/sonic/telemetry/streamingtelemetryserver.key"
            pytest_assert(str(value) == server_key_expected, "'server_key' value is not '{}'".format(server_key_expected))
        if str(key) == "server_crt":
            server_crt_expected = "/etc/sonic/telemetry/streamingtelemetryserver.cer"
            pytest_assert(str(value) == server_crt_expected, "'server_crt' value is not '{}'".format(server_crt_expected))

def test_telemetry_enabledbydefault(duthost):
    """Verify telemetry should be enabled by default
    """
    status = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "FEATURE|telemetry"', module_ignore_errors=False)['stdout_lines']
    status_list = get_list_stdout(status)
    # Elements in list alternate between key and value. Separate them and combine into a dict.
    status_key_list = status_list[0::2]
    status_value_list = status_list[1::2]
    status_dict = dict(zip(status_key_list, status_value_list))
    for k, v in status_dict.items():
        if str(k) == "status":
            status_expected = "enabled";
            pytest_assert(str(v) == status_expected, "Telemetry feature is not enabled")

def test_telemetry_ouput(duthost, ptfhost):
    """Run pyclient from ptfdocker and show gnmi server outputself.
       For pyclient to work client_auth need to be set to false.
    """
    set_client_auth = duthost.shell('/usr/bin/redis-cli -n 4 hset "TELEMETRY|gnmi" "client_auth" "false"', module_ignore_errors=False)
    logger.info('start telemetry testing')
    # For server to take effect of client_auth=false, server needs to be restarted
    restart_status = restart_telemetry(duthost)
    if restart_status:
        logger.info('telemetry process restarted. Now run pyclient on ptfdocker')
        dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']
        # pyclient should be available on ptfhost. If not fail pytest.
        file_exists = ptfhost.stat(path="~/gnxi/gnmi_cli_py/py_gnmicli.py")
        pytest_assert(file_exists["stat"]["exists"] is True)
        cmd = '~/gnxi/gnmi_cli_py/python py_gnmicli.py -g -t {0} -p 50051 -m get -x COUNTERS/Ethernet0 -xt COUNTERS_DB -o "ndastreamingservertest"'.format(dut_ip)
        show_gnmi_out = ptfhost.shell(cmd)[stdout]
        logger.info("gnmi server output \n {}".format(show_gnmi_out))
    else:
        logger.info('restart telemetry failed. Gnmi output is not verified')

    # Reset config back to original for telemetry process
    duthost.shell('/usr/bin/redis-cli -n 4 hset "TELEMETRY|gnmi" "client_auth" "true"', module_ignore_errors=False)
    restart_telemetry(duthost)
