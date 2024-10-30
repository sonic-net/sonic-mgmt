import logging
import pytest
import json
import re

from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_utils import GNMIEnvironment

logger = logging.getLogger(__name__)

METHOD_GET = "get"
METHOD_SUBSCRIBE = "subscribe"
SUBSCRIBE_MODE_STREAM = 0
SUBMODE_SAMPLE = 2
SUBMODE_ONCHANGE = 1

EVENT_REGEX = "json_ietf_val: \"(.*)\""
ON_CHANGE_REGEX = "json_ietf_val:\"({.*?})\""


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


def check_gnmi_cli_running(ptfhost):
    program_list = ptfhost.shell("pgrep -f 'python /root/gnxi/gnmi_cli_py/py_gnmicli.py'")["stdout"]
    return len(program_list) > 0


def parse_gnmi_output(gnmi_output, match_no, find_data):
    gnmi_str = str(gnmi_output)
    gnmi_str = gnmi_str.replace('\\', '')
    gnmi_str = gnmi_str.replace(' ', '')
    if find_data != "":
        result = fetch_json_ptf_output(ON_CHANGE_REGEX, gnmi_str, match_no)
        return find_data in result[match_no]


def fetch_json_ptf_output(regex, output, match_no):
    match = re.findall(regex, output)
    assert len(match) > match_no, "Not able to parse json from output"
    return match[:match_no+1]


def listen_for_events(duthost, gnxi_path, ptfhost, filter_event_regex, op_file, timeout, update_count=1,
                      match_number=0):
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              submode=SUBMODE_ONCHANGE, update_count=update_count, xpath="all[heartbeat=2]",
                              target="EVENTS", filter_event_regex=filter_event_regex, timeout=timeout)
    result = ptfhost.shell(cmd)
    assert result["rc"] == 0, "PTF command failed with non zero return code"
    output = result["stdout"]
    assert len(output) != 0, "No output from PTF docker, thread timed out after {} seconds".format(timeout)
    # regex logic and then to write to file
    event_strs = fetch_json_ptf_output(EVENT_REGEX, output, match_number)
    with open(op_file, "w") as f:
        f.write("[\n")
        for i in range(0, len(event_strs)):
            str = event_strs[i]
            event_str = str.replace('\\', '')
            event_json = json.loads(event_str)
            json.dump(event_json, f, indent=4)
            if i < match_number:
                f.write(",")
        f.write("\n]")
        f.close()


def trigger_logger(duthost, log, process, container="", priority="local0.notice", repeat=5):
    tag = process
    if container != "":
        tag = container + "#" + process
    for r in range(repeat):
        duthost.shell("logger -p {} -t {} {} {}".format(priority, tag, log, r))


def generate_client_cli(duthost, gnxi_path, method=METHOD_GET, xpath="COUNTERS/Ethernet0", target="COUNTERS_DB",
                        subscribe_mode=SUBSCRIBE_MODE_STREAM, submode=SUBMODE_SAMPLE,
                        intervalms=0, update_count=3, create_connections=1, filter_event_regex="", namespace=None,
                        timeout=-1):
    """ Generate the py_gnmicli command line based on the given params.
    t                      --target: gNMI target; required
    p                      --port: port of target; required
    m                      --mode: get/susbcribe; default get
    x                      --xpath: gnmi path, table name; required
    xt                     --xpath_target: gnmi path prefix, db name
    o                      --host_override, targets hostname for certificate CN
    subscribe_mode:        0=STREAM, 1=ONCE, 2=POLL; default 0
    submode:               0=TARGET_DEFINED, 1=ON_CHANGE, 2=SAMPLE; default 2
    interval:              sample interval in milliseconds, default 10000ms
    update_count:          Max number of streaming updates to receive. 0 means no limit. default 0
    create_connections:    Creates TCP connections with gNMI server; default 1; -1 for infinite connections
    filter_event_regex:    Regex to filter event when querying events path
    namespace:             namespace for multi-asic
    timeout:               Subscription duration in seconds; After X seconds, request terminates; default none
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    ns = ""
    if namespace is not None:
        ns = "/{}".format(namespace)
    cmdFormat = 'python ' + gnxi_path + 'gnmi_cli_py/py_gnmicli.py -g -t {0} -p {1} -m {2} -x {3} -xt {4}{5} -o {6}'
    cmd = cmdFormat.format(duthost.mgmt_ip, env.gnmi_port, method, xpath, target, ns, "ndastreamingservertest")

    if method == METHOD_SUBSCRIBE:
        cmd += " --subscribe_mode {0} --submode {1} --interval {2} --update_count {3} --create_connections {4}".format(
                subscribe_mode,
                submode, intervalms,
                update_count, create_connections)
        if filter_event_regex != "":
            cmd += " --filter_event_regex {}".format(filter_event_regex)
        if timeout > 0:
            cmd += " --timeout {}".format(timeout)
    return cmd


def unarchive_telemetry_certs(duthost):
    # Move all files within old_certs directory to parent certs directory
    path = "/etc/sonic/telemetry/"
    archive_dir = path + "old_certs"
    cmd = "ls {}".format(archive_dir)
    filenames = duthost.shell(cmd)['stdout_lines']
    for filename in filenames:
        cmd = "mv {}/{} {}".format(archive_dir, filename, path)
        duthost.shell(cmd)
    cmd = "rm -rf {}".format(archive_dir)


def archive_telemetry_certs(duthost):
    # Move all files within certs directory to old_certs directory
    path = "/etc/sonic/telemetry/"
    archive_dir = path + "old_certs"
    cmd = "mkdir -p {}".format(archive_dir)
    duthost.shell(cmd)
    cmd = "ls {}".format(path)
    filenames = duthost.shell(cmd)['stdout_lines']
    for filename in filenames:
        if filename.endswith(".cer") or filename.endswith(".key"):
            cmd = "mv {} {}".format(path + filename, archive_dir)
            duthost.shell(cmd)


def rotate_telemetry_certs(duthost, localhost):
    path = "/etc/sonic/telemetry/"
    # Create new certs to rotate
    cmd = "openssl req \
              -x509 \
              -sha256 \
              -nodes \
              -newkey rsa:2048 \
              -keyout streamingtelemetryserver.key \
              -subj '/CN=ndastreamingservertest' \
              -out streamingtelemetryserver.cer"
    localhost.shell(cmd)
    cmd = "openssl req \
              -x509 \
              -sha256 \
              -nodes \
              -newkey rsa:2048 \
              -keyout dsmsroot.key \
              -subj '/CN=ndastreamingclienttest' \
              -out dsmsroot.cer"
    localhost.shell(cmd)

    # Rotate certs
    duthost.copy(src="streamingtelemetryserver.cer", dest=path)
    duthost.copy(src="streamingtelemetryserver.key", dest=path)
    duthost.copy(src="dsmsroot.cer", dest=path)
    duthost.copy(src="dsmsroot.key", dest=path)
