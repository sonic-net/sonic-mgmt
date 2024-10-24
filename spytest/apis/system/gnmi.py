# This file contains the list of API's for operations of GNMI CLI
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

import tempfile
import json
import os
import re
import shlex

from spytest import st

from apis.common import redis
from apis.system.rest import fix_set_url, fix_get_url
from apis.system.basic import docker_operation

import utilities.utils as util_obj
import utilities.common as cutils

supported_gnmi_operations = ["set", "get", "cli"]


def get_docker_command(container="telemetry"):
    """
    API to return docker container command for execution
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param container:
    :return:
    """
    command = "docker exec -it {} bash".format(container)
    return command


def gnmi_get(dut, xpath, **kwargs):
    """
    API to do GNMI get operations
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param xpath:
    :param kwargs:
    :return:
    """
    gnmi_debug(dut)
    credentails = st.get_credentials(dut)
    ip_address = kwargs.get('ip_address', '127.0.0.1')
    port = kwargs.get('port', '8080')
    insecure = kwargs.get('insecure', '')
    skip_tmpl = kwargs.get('skip_tmpl', False)
    username = kwargs.get('username', credentails[0])
    password = kwargs.get('password', credentails[3])
    cert = kwargs.get('cert')
    target_name = kwargs.get('target_name')
    result = dict()
    try:
        docker_command = get_docker_command()
        if not docker_command:
            st.log("Docker command not found ..")
            return False
        gnmi_command = 'gnmi_get -xpath {} -target_addr {}:{}'.format(xpath, ip_address, port)
        if username:
            gnmi_command += " -username {}".format(username)
        if password:
            gnmi_command += " -password {}".format(password)
        if cert:
            gnmi_command += " -cert {}".format(cert)
        if target_name:
            gnmi_command += " -target_name {}".format(target_name)
        if insecure != 'none':
            gnmi_command += " -insecure {}".format(insecure)
        command = '{} -c "{}"'.format(docker_command, gnmi_command)
        output = st.show(dut, command, skip_tmpl=skip_tmpl)
        st.log("OUTPUT : {}".format(output))
        if not output:
            return result
        if skip_tmpl:
            if "data" in output[0]:
                data = json.dumps(output[0]["data"])
                if not data:
                    return result
                return json.loads(json.loads(json.loads(json.dumps(data[0]["data"]))))
            return result
        else:
            response = output[0]["data"]
            while True:
                if not isinstance(response, dict):
                    response = json.loads(response)
                else:
                    return response
    except Exception as e:
        st.log(e)
        return result


def gnmi_set(dut, xpath, json_content, **kwargs):
    """
    API to set GNMI configuration
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param xpath:
    :param json_content:
    :param kwargs:
    :return:
    """
    gnmi_debug(dut)
    credentails = st.get_credentials(dut)
    ip_address = kwargs.get('ip_address', '127.0.0.1')
    port = kwargs.get('port', '8080')
    insecure = kwargs.get('insecure', '')
    username = kwargs.get('username', credentails[0])
    password = kwargs.get('password', credentails[3])
    cert = kwargs.get('cert')
    target_name = kwargs.get('target_name')
    pretty = kwargs.get('pretty')
    logstostderr = kwargs.get('logstostderr')
    mode = kwargs.get('mode', '-update')

    docker_command = get_docker_command()
    if not docker_command:
        st.log("Docker command not found ..")
        return False

    if json_content:
        temp_dir = tempfile.gettempdir()
        current_datetime = util_obj.get_current_datetime()
        file_name = "sonic_gnmi_{}.json".format(current_datetime)
        tmp_path = "{}/{}".format(temp_dir, file_name)
        docker_path = '/{}'.format(file_name)
        cp_cmd = 'docker cp {} telemetry:{}'.format(tmp_path, docker_path)
        rm_cmds = ['rm {}'.format(tmp_path), '{} -c "rm {}"'.format(docker_command, docker_path)]
        file_operation = util_obj.write_to_json_file(json_content, tmp_path)
        if not file_operation:
            st.log("File operation failed.")
            return False
        st.upload_file_to_dut(dut, tmp_path, tmp_path)
        st.config(dut, cp_cmd)
        gnmi_command = 'gnmi_set {} {}:@{} -target_addr {}:{}'.format(mode, xpath, docker_path, ip_address, port)
        if username:
            gnmi_command += " -username {}".format(username)
        if password:
            gnmi_command += " -password {}".format(password)
        if cert:
            gnmi_command += " -cert {}".format(cert)
        if target_name:
            gnmi_command += " -target_name {}".format(target_name)
        if pretty:
            gnmi_command += " -pretty"
        if logstostderr:
            gnmi_command += " -alsologstostderr"
        if insecure != 'none':
            gnmi_command += " -insecure {}".format(insecure)
        command = '{} -c "{}"'.format(docker_command, gnmi_command)
        output = st.config(dut, command)
        for rm_cmd in rm_cmds:
            st.config(dut, rm_cmd)
        error_strings = ["Error response", "rpc error", "Set failed", "Unknown desc", "failed"]
        for err_code in error_strings:
            if err_code in util_obj.remove_last_line_from_string(output):
                st.log(output)
                return False
        return output
    else:
        return False


def gnmi_cli(dut, **kwargs):
    """
    API to configure gnmi using cli
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param :query_type: once, stream, poll
    :param kwargs:
    :return:
    """
    docker_command = get_docker_command()
    credentails = st.get_credentials(dut)
    query_type = kwargs.get('query_type', 'stream')
    ip_address = kwargs.get('ip_address', '127.0.0.1')
    port = kwargs.get('port', '8080')
    gnmi_utils_path = kwargs.get('gnmi_utils_path', '/tmp')
    if not docker_command:
        st.log("Docker command not found ..")
        return False
    if query_type not in ["stream", "poll", "once"]:
        st.log("Provided unsupported query type")
        return False
    mandatory_kwargs = ["query_type", "xpath"]
    for arg in mandatory_kwargs:
        if arg not in kwargs:
            st.log("Please provide {} attribute".format(arg))
            return False
    mode = kwargs.get("mode", 'remote')  # local | remote
    insecure = "" if kwargs.get("insecure") else "-insecure"
    logtostderr = "" if kwargs.get("logtostderr") else "-logtostderr"
    with_user_pass = "-with_user_pass" if kwargs.get("with_user_pass") else ""
    username = kwargs.get('username', credentails[0])
    password = kwargs.get('password', credentails[3])
    xpath_list = list(kwargs["xpath"]) if isinstance(kwargs["xpath"], list) else [kwargs["xpath"]]
    xpath_str = "".join(xpath_list)
    version = kwargs.get("version", 0)
    target = kwargs.get("target", "OC-YANG")
    encoding = kwargs.get("encoding")
    file_name = kwargs.get("file_name")
    background = kwargs.get("background")
    sample_interval = kwargs.get("sample_interval", 20)
    poll_interval = kwargs.get("poll_interval", 20)
    suppress_redundant = kwargs.get("suppress_redundant")
    updates_only = kwargs.get("updates_only")

    gnmi_cmd = "gnmi_cli {} {} {} -address {}:{} ".format(insecure, logtostderr, with_user_pass, ip_address, port)
    if username and password:
        gnmi_cmd += " -username {} -password {}".format(username, password)

    if query_type == "stream":
        stream_type = kwargs.get("streaming_type", 1)
        gnmi_cmd += " -query_type s -streaming_type {} -v {} -target {} -q {}".\
            format(stream_type, version, target, xpath_str)
        if stream_type == "SAMPLE":
            gnmi_cmd += " -streaming_sample_interval {} ".format(sample_interval)
            if suppress_redundant:
                gnmi_cmd += " -suppress_redundant "

    elif query_type == "poll":
        gnmi_cmd += " -query_type p -pi {} -q {} -v {} -target {} ".\
            format(poll_interval, xpath_str, version, target)
    else:
        gnmi_cmd += " -query_type o -q {} -v {} -target {} ".format(xpath_str, version, target)

    if encoding:
        gnmi_cmd += " -encoding {} ".format(encoding)
    if updates_only:
        gnmi_cmd += " -updates_only "
    if file_name:
        gnmi_cmd += " >{} 2>&1".format(file_name)
    if background:
        gnmi_cmd += " & "

    if mode == 'local':
        result = {}
        command = '{} -c "{}"'.format(docker_command, gnmi_cmd)
        output = st.config(dut, command)
        result.update({"output": output})
        result.update({"error": ''})
        result.update({"rc": ''})
        result.update({"pid": ''})
        if "Error response" in util_obj.remove_last_line_from_string(output):
            result.update({"error": output})
        st.log("RESULT {}".format(result))
        return result
    elif mode == 'remote':
        if not os.path.exists("{}/gnmi_cli".format(gnmi_utils_path)):
            copy_gnmi_utils(dut, src_path="/home/admin", dst_path=gnmi_utils_path,
                            gnmi_files=["gnmi_cli"])
        command = "{}/{} ".format(gnmi_utils_path, gnmi_cmd)
        return _run_gnmi_command(command, pid=True)


def dialout_server_cli(**kwargs):
    """
    API to start gnmi server (dialout)
    Author: Jack Pettrakool (jack.pettrakool@dell.com)
    :param kwargs:
    :return:
    """

    port = kwargs.get('port', '8080')
    cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'spytest', 'gnmi', "dialout_server_cli"))
    if not os.path.exists(cli_path):
        st.log("{} command not found ..".format(cli_path))
        return False
    flags = []
    for fg in ['allow_no_client_auth', 'insecure', 'logtostderr', 'logtostdout', 'alsologtostderr', 'alsologtosyslog', 'pretty']:
        if kwargs.get(fg, False):
            flags.append('-{}'.format(fg))
    opts = ['-port {}'.format(port), '-v={}'.format(kwargs.get("log_level", 2))]
    for op in ['ca_crt', 'log_backtrace_at', 'log_dir', 'server_crt', 'server_key', 'stderrthreshold', 'syslogthreshold', 'vmodule']:
        if kwargs.get(op, None) is not None:
            opts.append('-{} "{}"'.format(op, kwargs.get(op)))
    file_name = kwargs.get("file_name")
    background = kwargs.get("background")

    cmd = "{} {} {}".format(cli_path, " ".join(flags), " ".join(opts))
    if file_name:
        cmd += " >{} 2>&1".format(file_name)
    if background:
        cmd += " & "

    return _run_gnmi_command(cmd, pid=True)


def client_auth(dut, **kwargs):
    """
    To enable disable gNMI client auth.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param auth_type:
    :return:
    """
    st.log("Configuring gNMI authentication.")
    docker_name = "telemetry"
    command = redis.build(dut, redis.CONFIG_DB, 'hmset "TELEMETRY|gnmi" client_auth')
    if 'auth_type' in kwargs:
        if kwargs.get('auth_type'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "TELEMETRY|gnmi" client_auth "{}"'.format(kwargs.get('auth_type')))
        else:
            command = redis.build(dut, redis.CONFIG_DB, 'hdel "TELEMETRY|gnmi" client_auth')
        st.config(dut, command, on_cr_recover="retry5")
    if 'server_key' in kwargs:
        if kwargs.get('server_key'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "TELEMETRY|certs" server_key "{}"'.format(kwargs.get('server_key')))
        else:
            command = redis.build(dut, redis.CONFIG_DB, 'hdel "TELEMETRY|certs" server_key')
        st.config(dut, command, on_cr_recover="retry5")
    if 'server_crt' in kwargs:
        if kwargs.get('server_crt'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "TELEMETRY|certs" server_crt "{}"'.format(kwargs.get('server_crt')))
        else:
            command = redis.build(dut, redis.CONFIG_DB, 'hdel "TELEMETRY|certs" server_crt')
        st.config(dut, command, on_cr_recover="retry5")
    if 'ca_crt' in kwargs:
        if kwargs.get('ca_crt'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "TELEMETRY|certs" ca_crt "{}"'.format(kwargs.get('ca_crt')))
        else:
            command = redis.build(dut, redis.CONFIG_DB, 'hdel "TELEMETRY|certs" ca_crt')
        st.config(dut, command, on_cr_recover="retry5")
    if kwargs.get('restart'):
        docker_operation(dut, docker_name, 'restart')
    gnmi_debug(dut)
    return True


def telemetry_client_auth(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """

    auth_type = kwargs.get("auth_type")
    skip_errors = kwargs.get('skip_errors', True)
    cli_type = 'klish'
    cmd = "no ip telemetry authentication"
    if auth_type:
        cmd = "ip telemetry authentication {}".format(auth_type)
    st.config(dut, cmd, type=cli_type, skip_error_check=skip_errors)


def crypto_cert_key_install(dut, **kwargs):
    """
    To install cer-file and key-file and create security-profile
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    config = kwargs.get("config", True)
    home_dir = kwargs.get("home_dir", "/home/admin")
    cert_file = kwargs.get("cert_file", "")
    cert_file_name = os.path.basename(cert_file) if cert_file else ''
    cert_file_name_no_ext = cert_file_name.replace(".crt", "")
    key_file = kwargs.get("key_file")
    ca_cert = kwargs.get("ca_cert")
    ca_cert_file_name = os.path.basename(ca_cert) if cert_file else ''
    ca_cert_file_name_no_ext = ca_cert_file_name.replace(".crt", "")
    profile_name = kwargs.get("profile_name")
    trust_store = kwargs.get("trust_store")
    docker_name = kwargs.get("docker_name", "telemetry")
    skip_errors = kwargs.get('skip_errors', True)
    cli_type = 'klish'
    cmds = []
    if not (cert_file and key_file):
        st.error("please provide cert file and key file", dut=dut)
        return False
    if config:
        cmds += ["crypto cert install cert-file {} key-file {}".format(cert_file.replace(home_dir, "home:/"),
                                                                       key_file.replace(home_dir, "home:/"))]

        if ca_cert:
            cmds += ['crypto ca-cert install {}'.format(ca_cert.replace(home_dir, "home:/"))]
            if trust_store:
                cmds += ['crypto trust-store {} ca-cert {}'.format(trust_store, ca_cert_file_name_no_ext)]

        if profile_name and cert_file:
            cmds += ["crypto security-profile {}".format(profile_name)]
            cmds += ["crypto security-profile certificate {} {}".format(profile_name, cert_file_name_no_ext)]
            if trust_store:
                cmds += ["crypto security-profile trust-store {} {}".format(profile_name, trust_store)]
            cmds += ["ip telemetry security-profile {}".format(profile_name)]

    else:

        if 'profile_name' in kwargs:
            cmds += ["no ip telemetry security-profile"]
            if trust_store:
                cmds += ["no crypto security-profile trust-store {} ".format(profile_name)]
            cmds += ["no crypto security-profile certificate {}".format(profile_name)]
            cmds += ["no crypto security-profile {}".format(profile_name)]

        if ca_cert:
            if trust_store:
                cmds += ['no crypto trust-store {} ca-cert {}'.format(trust_store, ca_cert_file_name)]
            cmds += ["crypto ca-cert delete all"]

        cmds += ["crypto cert delete all"]

    st.config(dut, cmds, type=cli_type, skip_error_check=skip_errors)

    if kwargs.get("restart", False):
        docker_operation(dut, docker_name, 'restart')
    return True


def show_crypto_cert(dut, **kwargs):
    """
    Api to show crypto cerificates
    :param dut:
    :return:
    """
    cmd = "show crypto cert all"
    if kwargs.get('cert'):
        cmd += " | grep Certificate"
    return st.show(dut, cmd, **kwargs)


def show_crypto_security_profile(dut, **kwargs):
    """
    Api to show crypto security profile
    :param dut:
    :return:
    """
    cmd = "show crypto security-profile"
    if kwargs.get('cert') and kwargs.get('profile_name'):
        cmd += " | grep Security|Certificate"
    return st.show(dut, cmd, **kwargs)


def show_ip_telemetry_security_profile(dut, **kwargs):
    """
    Api to show ip telemetry security profile
    :param dut:
    :return:
    """
    cmd = "show ip telemetry security-profile"
    if kwargs.get('telemetry_profile_name'):
        cmd += " | grep Security"
    return st.show(dut, cmd, **kwargs)


def verify_cert_security_profile(dut, **kwargs):
    """
    Api to verify crypto certificates and crypto, ip telemetry security profiles
    :param dut:
    :param kwargs:
    :return:
    """
    cert = kwargs.get("cert")
    profile_name = kwargs.get("profile_name")
    telemetry_profile_name = kwargs.get("telemetry_profile_name", "")
    kwargs.setdefault("type", "klish")
    kwargs.setdefault("skip_tmpl", True)
    rv = True
    if cert:
        output = show_crypto_cert(dut, **kwargs)
        if cert not in output:
            st.error('certificate "{}" not found'.format(cert), dut=dut)
            rv = False
    if profile_name and cert:
        output = show_crypto_security_profile(dut, **kwargs)
        if profile_name not in output:
            st.error('crypto security profile "{}" not found'.format(profile_name), dut=dut)
            rv = False
        if cert not in output:
            st.error('crypto security profile {} not assigned with "{}"'.format(profile_name, cert), dut=dut)
            rv = False
    if telemetry_profile_name:
        output = show_ip_telemetry_security_profile(dut, **kwargs)
        if telemetry_profile_name not in output:
            st.error('ip telemetry security profile "{}" not found.'.format(telemetry_profile_name), dut=dut)
            rv = False
    return rv


def gnmi_delete(dut, xpath, **kwargs):
    """
    API to do GNMI get operations
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param xpath:
    :param kwargs:
    :return:
    """
    gnmi_debug(dut)
    st.log("Performing GNMI DELETE OPERATION ...")
    ip_address = kwargs.get('ip_address', '127.0.0.1')
    port = kwargs.get('port', '8080')
    insecure = kwargs.get('insecure', '')
    credentails = st.get_credentials(dut)
    username = kwargs.get('username', credentails[0])
    password = kwargs.get('password', credentails[3])
    cert = kwargs.get('cert')
    docker_command = get_docker_command()
    try:
        gnmi_command = 'gnmi_set --delete {} --target_addr {}:{}'.format(xpath, ip_address, port)
        if username:
            gnmi_command += " --username {}".format(username)
        if password:
            gnmi_command += " --password {}".format(password)
        if cert:
            gnmi_command += " --cert {}".format(cert)
        gnmi_command += " --insecure {}".format(insecure)
        command = '{} -c "{}"'.format(docker_command, gnmi_command)
        output = st.config(dut, command)
        st.log("OUTPUT : {}".format(output))
        if not output:
            st.log("Observed empty OUTPUT")
            return False
        error_strings = ["Error response", "rpc error", "gnmi_set.go", "Set failed", "Unknown desc", "failed"]
        for err_code in error_strings:
            if err_code in util_obj.remove_last_line_from_string(output):
                st.log(output)
                return False
        return output
    except Exception as e:
        st.error(e)
        return False


def gnmi_debug(dut):
    """
    API to check the debug commands for GNMI
    :param dut:
    :return:
    """
    command = 'sonic-cfggen -d -v "TELEMETRY"'
    st.config(dut, command)


def clear_gnmi_utils(path="/tmp/gnmi_*"):
    st.log('Clearing {}'.format(path))
    try:
        os.system("rm -f {}".format(path))
    except Exception as e:
        st.error(e)


def copy_gnmi_utils(dut, src_path, dst_path="/tmp", gnmi_files=["gnmi_set", "gnmi_get"]):
    st.log("Copying gNMI Utils {}".format(gnmi_files))
    dut_path = src_path
    for file in gnmi_files:
        command = "docker cp telemetry:/usr/sbin/{} {}".format(file, dut_path)
        st.config(dut, command)
        st.download_file_from_dut(dut, "{}/{}".format(dut_path, file), "{}/".format(dst_path))
    return True


def convert_rest_url_to_gnmi_url(path, url_params={}):
    pattern_match = re.findall(r"{(\w+(-*\w+)+)}", path)
    if pattern_match:
        for key, value in url_params.items():
            for attr in pattern_match:
                if key == attr[0]:
                    path = path.replace("={" + key + "}", "[{}={}]".format(key, value))
                    path = path.replace(",{" + key + "}", "[{}={}]".format(key, value))
    path = path.replace("/restconf/data", "")
    return path


def _run_gnmi_command(command, pid=False):
    result = dict()
    st.log("CMD: {}".format(command))
    if pid:
        process = cutils.process_popen(command, preexec_fn=os.setsid)
    else:
        process = cutils.process_popen(shlex.split(command), shell=False)
    data, error = process.communicate()
    rc = process.poll()
    result.update({"output": data})
    result.update({"rc": rc})
    result.update({"error": error})
    result.update({"pid": ''})
    if pid:
        result.update({"pid": process.pid})
    st.log("RESULT {}".format(result))
    return result


def _prepare_gnmi_command(dut, xpath, **kwargs):
    credentials = st.get_credentials(dut)
    ip_address = kwargs.get('ip_address', '127.0.0.1')
    port = kwargs.get('port', '8080')
    insecure = kwargs.get('insecure', '')
    username = kwargs.get('username', credentials[0])
    password = kwargs.get('password', credentials[3])
    gnmi_utils_path = kwargs.get("gnmi_utils_path", "/tmp")
    cert = kwargs.get('cert')
    action = kwargs.get("action", "get")
    pretty = kwargs.get('pretty')
    mode = kwargs.get('mode', '-update')
    target_name = kwargs.get('target_name')
    gnmi_command = ''
    if action == "get":
        gnmi_command = 'gnmi_get -xpath {} -target_addr {}:{}'.format(xpath, ip_address, port)
    elif action == "set":
        gnmi_command = 'gnmi_set {} {}:@{} -target_addr {}:{}'.format(mode, xpath, kwargs.get("data_file_path"),
                                                                      ip_address, port)
        if pretty:
            gnmi_command += " --pretty"
    elif action == "delete":
        gnmi_command = 'gnmi_set --delete {} --target_addr {}:{}'.format(xpath, ip_address, port)
    if username:
        gnmi_command += " --username {}".format(username)
    if password:
        gnmi_command += " --password {}".format(password)
    if cert:
        gnmi_command += " -cert {}".format(cert)
    if target_name:
        gnmi_command += " -target_name {}".format(target_name)
    if insecure:
        gnmi_command += " -insecure {}".format(insecure)
    gnmi_command += " -insecure -alsologtostderr"
    command = '{}/{}'.format(gnmi_utils_path, gnmi_command)
    return command


def gnmi_apply(dut, **kwargs):
    operation = kwargs.get("operation", "get")
    if operation == "patch":
        action = "set"
    elif operation == "delete":
        action = "delete"
    else:
        action = "get"
    xpath = kwargs.get("path")
    if not xpath:
        st.error("XPATH NOT PROVIDED")
        return False
    ip_addr = st.get_mgmt_ip(dut)
    kwargs.update({"ip_address": kwargs.get("ip_address", ip_addr)})
    xpath = convert_rest_url_to_gnmi_url(xpath, kwargs.get("url_params"))
    kwargs.update({"json_content": kwargs.get("data")})
    kwargs.update({"action": action})
    if action == "set":
        xpath, data = fix_set_url(xpath, kwargs.get("data"))
        kwargs.update({"json_content": data})
    else:
        xpath = fix_get_url(xpath)
    if action in ["get", "set", "delete"]:
        return _gnmi_operation(dut, xpath, **kwargs)
    else:
        st.log("Invalid operation for GNMI -- {}".format(action))
        return False


def _gnmi_operation(dut, xpath, **kwargs):
    """
    API to set GNMI configuration
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param xpath:
    :param json_content:
    :param kwargs:
    :return:
    """
    st.log("Performing GNMI {} OPERATION ...".format(kwargs.get("action").upper()))
    if kwargs.get("action") == "set":
        json_content = kwargs.get("json_content")
        if json_content:
            temp_dir = tempfile.gettempdir()
            current_datetime = cutils.get_current_datetime(fmt="%m%d%Y%H%M%S%f")
            file_name = "sonic_uignmi_{}.json".format(current_datetime)
            tmp_path = "{}/{}".format(temp_dir, file_name)
            rm_cmds = ['rm {}'.format(tmp_path)]
            kwargs.update({"devname": dut})
            kwargs.update({"json_content": json_content})
            kwargs.update({"data_file_path": tmp_path})
            command = _prepare_gnmi_command(dut, xpath, **kwargs)
            file_operation = cutils.write_to_json_file(json_content, tmp_path)
            if not file_operation:
                st.error("File operation failed.")
                return False
            output = _run_gnmi_command(command)
            st.debug("OUTPUT : {}".format(output))
            for rm_cmd in rm_cmds:
                _run_gnmi_command(rm_cmd)
            return output
        else:
            st.error("Could not find JSON CONTENT for SET operation")
            return False
    elif kwargs.get("action") in ["get", "delete"]:
        try:
            kwargs.update({"devname": dut})
            command = _prepare_gnmi_command(dut, xpath, **kwargs)
            output = _run_gnmi_command(command)
            output['output'] = _get_processed_gnmi_ouput(output['output']) if kwargs.get("action") == 'get' \
                else output['output']
            st.debug(output)
            return output
        except Exception as e:
            st.error(e)
            return False
    else:
        st.log("Invalid operation for GNMI -- {}".format(kwargs.get("action")))
        return False


def _get_processed_gnmi_ouput(data):
    """
    API to return GNMI GET processed output
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param xpath:
    :param json_content:
    :param kwargs:
    :return:
    """
    my_data = ""
    if data:
        out = data.replace("\n", "").replace(" ", "").replace(">", "").replace("<", "")\
            .replace("'\"", "").replace("\"'", "").replace("False", "false").replace("True", "true").replace("\\", "")
        processed_output = re.findall(r'json_ietf_val:(.*)', out)
        if processed_output:
            a = processed_output[0].strip('"')
            try:
                my_data = json.loads(a)
            except Exception as e:
                st.error("Exception occurred: {}".format(e))
    st.debug("Processed gnmi GET output: {}".format(my_data))
    return my_data
