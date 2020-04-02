import pytest
import logging

logger = logging.getLogger(__name__)

# Helper functions
def get_telemetry_keyvalues(gnmi_out, certs_out):
    gnmi_values = gnmi_out.split('\n')
    cert_values = certs_out.split('\n')
    gnmi_list = []
    gnmi_list = gnmi_values + cert_values
    params_dict= dict(itertools.izip_longest(*[iter(gnmi_list)] *2, fillvalue=""))
    return params_dict

# Test functions

def test_config_db_parameters(duthost):
    """Verifies required telemetry parameters from config_db.
       This is scoped as module as it need to be run once before first test run.
    """
    gnmi = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "TELEMETRY|gnmi"', module_ignore_errors=True)['stdout']
    certs = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "TELEMETRY|certs"', module_ignore_errors=True)['stdout']
    d = get_telemetry_keyvalues(gnmi, certs)
    for key, value in d.items():
        logger.info(' testing {}={}'.format(key,value))
        if str(key) == "client_auth" and str(value) == "true":
            assert True, "Client_auth set to true"
        if str(key) == "port" and str(value) == "50051":
            assert True, "port is set to 50051"
        if str(key) == "ca_crt" and str(value) == "/etc/sonic/telemetry/dsmsroot.cer":
            assert True, "ca_crt is set to {}".format(str(value))
        if str(key) == "server_key" and str(value) == "/etc/sonic/telemetry/streamingtelemetryserver.key":
            assert True, "server_key is set to {}".format(str(value))
        if str(key) == "server_crt" and str(value) == "/etc/sonic/telemetry/streamingtelemetry.cer":
            assert True, "server_crt is set to {}".format(str(value))

def test_telemetry_enabledbydefault(duthost):
    """Verify telemetry should be enabled by default
    """
    status = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "FEATURE|telemetry"', module_ignore_errors=True)['stdout']
    status_value = status.split('\n')
    if str(status_value[0]) == "status" and str(status_value[1]) == "enabled":
        assert True, "Telemetry status is enabled"
   
     

