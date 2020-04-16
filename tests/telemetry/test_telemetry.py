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

# Test functions
def test_config_db_parameters(duthost):
    """Verifies required telemetry parameters from config_db.
    """
    gnmi = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "TELEMETRY|gnmi"', module_ignore_errors=False)['stdout_lines']
    certs = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "TELEMETRY|certs"', module_ignore_errors=False)['stdout_lines']
    if gnmi is None or certs is None:
        assert False, "Either TELEMETRY|gnmi or TELEMETRY|certs does not exist in config_db"
    else:
        d = get_dict_stdout(gnmi, certs)
        for key, value in d.items():
            if str(key) == "client_auth":
                assert str(value) == "true", 'Client_auth should be set to true!'
            if str(key) == "port":
                assert str(value) == "50051", "Port should be set to 50051"
            if str(key) == "ca_crt":
                assert str(value) == "/etc/sonic/telemetry/dsmsroot.cer", "ca_crt  value should be set to /etc/sonic/telemetry/dsmsroot.cer"
            if str(key) == "server_key":
                assert str(value) == "/etc/sonic/telemetry/streamingtelemetryserver.key", "server_key  value should be set to  /etc/sonic/telemetry/streamingtelemetryserver.key"
            if str(key) == "server_crt":
                assert str(value) == "/etc/sonic/telemetry/streamingtelemetryserver.cer", "server_crt is set to /etc/sonic/telemetry/streamingtelemetryserver.cer"

def test_telemetry_enabledbydefault(duthost):
    """Verify telemetry should be enabled by default
    """
    status = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "FEATURE|telemetry"', module_ignore_errors=False)['stdout_lines']
    status_list = get_list_stdout(status)
    status_dict = dict(itertools.izip_longest(*[iter(status_list)] *2, fillvalue=""))
    for k,v in status_dict.items():
        if str(k) == "status":
            assert str(v) == "enabled", "Telemetry status should be enabled!"
