import logging
import pytest
import json


from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

TELEMETRY_PORT = 50051
METHOD_GET = "get"
METHOD_SUBSCRIBE = "subscribe"
SUBSCRIBE_MODE_STREAM = 0
SUBMODE_SAMPLE = 2
SUBMODE_ONCHANGE = 1


def assert_equal(actual, expected, message):
    """Helper method to compare an expected value vs the actual value.
    """
    pytest_assert(actual == expected, "{0}. Expected {1} vs actual {2}".format(message, expected, actual))


def get_dict_stdout(gnmi_out, certs_out):
    """ Extracts dictionary from redis output.
    """
    gnmi_list = []
    gnmi_list = get_list_stdout(gnmi_out) + get_list_stdout(certs_out)
    # Elements in list alternate between key and value. Separate them and combine into a dict.
    key_list = gnmi_list[0::2]
    value_list = gnmi_list[1::2]
    params_dict = dict(list(zip(key_list, value_list)))
    return params_dict


def get_list_stdout(cmd_out):
    out_list = []
    for x in cmd_out:
        result = x.encode('UTF-8')
        out_list.append(result)
    return out_list


def skip_201911_and_older(duthost):
    """ Skip the current test if the DUT version is 201911 or older.
    """
    if parse_version(duthost.kernel_version) <= parse_version('4.9.0'):
        pytest.skip("Test not supported for 201911 images. Skipping the test")


def setup_telemetry_forpyclient(duthost):
    """ Set client_auth=false. This is needed for pyclient to successfully set up channel with gnmi server.
        Restart telemetry process
    """
    client_auth_out = duthost.shell('sonic-db-cli CONFIG_DB HGET "TELEMETRY|gnmi" "client_auth"',
                                    module_ignore_errors=False)['stdout_lines']
    client_auth = str(client_auth_out[0])
    if client_auth == "true":
        duthost.shell('sonic-db-cli CONFIG_DB HSET "TELEMETRY|gnmi" "client_auth" "false"',
                      module_ignore_errors=False)
        duthost.service(name="telemetry", state="restarted")
    else:
        logger.info('client auth is false. No need to restart telemetry')
    return client_auth


def restore_telemetry_forpyclient(duthost, default_client_auth):
    client_auth_out = duthost.shell('sonic-db-cli CONFIG_DB HGET "TELEMETRY|gnmi" "client_auth"',
                                    module_ignore_errors=False)['stdout_lines']
    client_auth = str(client_auth_out[0])
    if client_auth != default_client_auth:
        duthost.shell('sonic-db-cli CONFIG_DB HSET "TELEMETRY|gnmi" "client_auth" {}'.format(default_client_auth),
                      module_ignore_errors=False)
        duthost.service(name="telemetry", state="restarted")


def listen_for_event(ptfhost, cmd, results):
    ret = ptfhost.shell(cmd)
    assert ret["rc"] == 0 , "PTF docker was not able to query EVENTS path"
    results[0]= ret["stdout"] 


def listen_for_events(duthost, gnxi_path, ptfhost, filter_event_regex, op_file):
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              submode=SUBMODE_ONCHANGE, update_count=1, xpath="all[heartbeat=2]",
                              target="EVENTS", filter_event_regex=filter_event_regex)
    results = [""]
    event_thread = threading.Thread(target=listen_for_event, args=(ptfhost, cmd, results,))
    event_thread.start()
    event_thread.join(30) # close thread after 30 sec, was not able to find event within reasonable time
    logger.info("".join(results))
    assert results[0] is not "", "No output from PTF docker"
    # regex logic and then to write to file
    result = results[0]
    match = re.findall('json_ietf_val: \"(.*)\"', result)
    assert len(match) > 0, "Not able to parse json from output"
    event_str = match[0]
    event_str = event_str.replace('\\', '')
    event_json = json.loads(event_str)
    with open(op_file, "w") as f:
        f.write("[\n")
        json.dump(event_json, f, indent=4)
        f.write("\n]")
        f.close()


def generate_client_cli(duthost, gnxi_path, method=METHOD_GET, xpath="COUNTERS/Ethernet0", target="COUNTERS_DB",
                        subscribe_mode=SUBSCRIBE_MODE_STREAM, submode=SUBMODE_SAMPLE,
                        intervalms=0, update_count=3, create_connections=1, filter_event_regex=""):
    """ Generate the py_gnmicli command line based on the given params.
    """
    cmdFormat = 'python ' + gnxi_path + 'gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m {2} -x {3} -xt {4} -o {5}'
    cmd = cmdFormat.format(duthost.mgmt_ip, TELEMETRY_PORT, method, xpath, target, "ndastreamingservertest")

    if method == METHOD_SUBSCRIBE:
        cmd += " --subscribe_mode {0} --submode {1} --interval {2} --update_count {3} --create_connections {4}".format(
                subscribe_mode,
                submode, intervalms,
                update_count, create_connections)
        if filter_event_regex is not "":
            cmd += " --filter_event_regex {}".format(filter_event_regex)
    return cmd
