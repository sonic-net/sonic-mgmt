# Helper functions
def get_dict_stdout(gnmi_out, certs_out):
    result = ""
    gnmi_list = []
    gnmi_list = get_list_stdout(gnmi_out) + get_list_stdout(certs_out)
    params_dict= dict(itertools.izip_longest(*[iter(gnmi_list)] *2, fillvalue = ""))
    return params_dict

def get_list_stdout(cmd_out):
    result = ""
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
    d = get_dict_stdout(gnmi, certs)
    for key, value in d.items():
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
    status = duthost.shell('/usr/bin/redis-cli -n 4 hgetall "FEATURE|telemetry"', module_ignore_errors=False)['stdout_lines']
    status_list = get_list_stdout(status)
    status_dict = dict(itertools.izip_longest(*[iter(status_list)] *2, fillvalue=""))
    for k,v in status_dict.items():
        if str(k) == "status" and str(v) == "enabled":
            assert True, "Telemetry status is enabled"
