import logging
import pytest
import json
import re
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_utils import GNMIEnvironment

logger = logging.getLogger(__name__)

# Backdate rotated telemetry cert notBefore so it survives clock skew
# between the sonic-mgmt runner and the DUT. Cryptography lib here
# instead of openssl shell because openssl 3.0.x has no CLI flag to
# set notBefore on `req -x509` (added only in 3.5).
_TELEMETRY_CERT_BACKDATE_DAYS = 7
_TELEMETRY_CERT_VALIDITY_DAYS = 365

METHOD_GET = "get"
METHOD_SUBSCRIBE = "subscribe"
SUBSCRIBE_MODE_STREAM = 0
SUBSCRIBE_MODE_POLL = 2
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


def check_gnmi_cli_running(duthost, ptfhost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    res = ptfhost.shell(f"netstat -tn | grep \":{env.gnmi_port} .*ESTABLISHED\"",
                        module_ignore_errors=True)
    return res and res["rc"] == 0


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
                        timeout=-1, polling_interval=10, max_sync_count=-1):
    """ Generate the py_gnmicli command line based on the given params.
    This version ensures the command runs from the correct directory and within the
    activated virtual environment to resolve dependency issues.
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    ns = ""
    if namespace is not None:
        ns = "/{}".format(namespace)

    # This command structure is critical. It does three things:
    # 1. Activates the virtual environment using the POSIX-compliant '.' command.
    # 2. Changes to the gnmi_cli_py directory, which is required for the protobuf imports to work.
    # 3. Executes the py_gnmicli.py script.
    cmdFormat = '. /root/env-python3/bin/activate && cd {7}gnmi_cli_py' \
                ' && python py_gnmicli.py -g -t {0} -p {1} -m {2} -x {3} -xt {4}{5} -o {6}'
    mgmt_ip = duthost.get_mgmt_ip()["mgmt_ip"]
    cmd = cmdFormat.format(mgmt_ip, env.gnmi_port,
                           method, xpath, target, ns,
                           "ndastreamingservertest", gnxi_path)

    if subscribe_mode == SUBSCRIBE_MODE_POLL:
        poll_cmd = " --subscribe_mode {0} --polling_interval {1} --update_count {2} --max_sync_count {3} --timeout {4}"
        cmd += poll_cmd.format(subscribe_mode, polling_interval, update_count, max_sync_count, timeout)
        return cmd

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


def _mint_self_signed_telemetry_cert(common_name, cert_path, key_path):
    """Generate a backdated self-signed leaf cert + key on the sonic-mgmt runner."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=_TELEMETRY_CERT_BACKDATE_DAYS)
    not_after = now + timedelta(days=_TELEMETRY_CERT_VALIDITY_DAYS)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def rotate_telemetry_certs(duthost, localhost):
    path = "/etc/sonic/telemetry/"
    # Mint fresh self-signed certs locally with a backdate so the rotated
    # PKI survives clock skew between the sonic-mgmt runner and the DUT.
    _mint_self_signed_telemetry_cert(
        "ndastreamingservertest", "streamingtelemetryserver.cer", "streamingtelemetryserver.key",
    )
    _mint_self_signed_telemetry_cert(
        "ndastreamingclienttest", "dsmsroot.cer", "dsmsroot.key",
    )

    # Rotate certs
    duthost.copy(src="streamingtelemetryserver.cer", dest=path)
    duthost.copy(src="streamingtelemetryserver.key", dest=path)
    duthost.copy(src="dsmsroot.cer", dest=path)
    duthost.copy(src="dsmsroot.key", dest=path)


def execute_ptf_gnmi_cli(ptfhost, cmd):
    rc = ptfhost.shell(cmd)['rc']
    return rc == 0


def invoke_py_cli_from_ptf(ptfhost, cmd, callback):
    ret = ptfhost.shell(cmd)
    assert ret["rc"] == 0, "PTF docker did not get a response"
    callback(ret["stdout"])
