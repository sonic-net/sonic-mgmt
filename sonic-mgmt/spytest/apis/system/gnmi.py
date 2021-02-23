# This file contains the list of API's for operations of GNMI CLI
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

from spytest import st
import tempfile
import utilities.utils as util_obj
import json, os, re, subprocess, shlex
from apis.system.basic import service_operations_by_systemctl
from apis.common import redis
import utilities.common as cutils
from apis.system.rest import fix_set_url, fix_get_url

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


def gnmi_cli(dut, query_type="once", ip_address="127.0.0.1", port=8080, **kwargs):
    """
    API to configure gnmi using cli
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param query_type: once, stream, poll
    :param ip_address:
    :param port:
    :param kwargs:
    :return:
    """
    docker_command = get_docker_command()
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
    insecure = "" if "insecure" in kwargs and not kwargs["insecure"] else "-insecure"
    logstostderr = "" if "logstostderr" in kwargs and not kwargs["logstostderr"] else "-logstostderr"
    xpath_list = list(kwargs["xpath"]) if isinstance(kwargs["xpath"], list) else [kwargs["xpath"]]
    version = kwargs["version"] if "version" in kwargs and kwargs["version"] else 0
    target = kwargs["target"] if "target" in kwargs and kwargs["target"] else "OC-YANG"
    gnmi_cmd = "gnmi_cli {} {} -address {}:{} ".format(insecure, logstostderr, ip_address, port)
    if query_type == "stream":
        stream_type = kwargs["streaming_type"] if "streaming_type" in kwargs and kwargs["streaming_type"] else 1
        gnmi_cmd += " -query_type {} -streaming_type {} -q {} -v {} -target {}".\
            format("s", stream_type, ",".join(xpath_list), version, target)
    elif query_type == "poll":
        poll_interval = kwargs["poll_interval"] if "poll_interval" in kwargs and kwargs["poll_interval"] else 1
        gnmi_cmd += " -query_type {} -pi {} -q {} -v {} -target {}".\
            format("p", poll_interval, ",".join(xpath_list), version, target)
    else:
        gnmi_cmd += " -query_type {} -q {} -v {} -target {}".format("o", ",".join(xpath_list), version, target)

    if gnmi_cmd:
        command = '{} -c "{}"'.format(docker_command, gnmi_cmd)
        output = st.config(dut, command)
        if "Error response" in util_obj.remove_last_line_from_string(output):
            st.log(output)
            return False
    return True


def client_auth(dut, **kwargs):
    """
    To enable disable gNMI client auth.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param auth_type:
    :return:
    """
    st.log("Configuring gNMI authentication.")
    docker_name= "telemetry"
    command = redis.build(dut, redis.CONFIG_DB, 'hmset "TELEMETRY|gnmi" client_auth')
    if 'auth_type' in kwargs:
        if kwargs.get('auth_type'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "TELEMETRY|gnmi" client_auth "{}"'.format(kwargs.get('auth_type')))
        else:
            command = redis.build(dut, redis.CONFIG_DB, 'hdel "TELEMETRY|gnmi" client_auth')
        st.config(dut, command)
    if 'server_key' in kwargs:
        if kwargs.get('server_key'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "DEVICE_METADATA|x509" server_key "{}"'.format(kwargs.get('server_key')))
        st.config(dut, command)
    if 'server_crt' in kwargs:
        if kwargs.get('server_crt'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "DEVICE_METADATA|x509" server_crt "{}"'.format(kwargs.get('server_crt')))
        st.config(dut, command)
    if 'ca_crt' in kwargs:
        if kwargs.get('ca_crt'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "DEVICE_METADATA|x509" ca_crt "{}"'.format(kwargs.get('ca_crt')))
        else:
            command = redis.build(dut, redis.CONFIG_DB, 'hdel "DEVICE_METADATA|x509" ca_crt')
        st.config(dut, command)
    service_operations_by_systemctl(dut, docker_name, 'stop')
    service_operations_by_systemctl(dut, docker_name, 'start')
    command = 'sonic-cfggen -d -v "TELEMETRY"'
    st.config(dut, command)
    return True

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
    output = st.config(dut, command)
    st.log("DEBUG OUPUT for GNMI STATUS --- {}".format(output))


def clear_gnmi_utils():
    try:
        os.system("rm -f /tmp/gnmi_*")
    except Exception:
        pass


def copy_gnmi_utils(dut, src_path, dst_path="/tmp"):
    gnmi_files = ["gnmi_set", "gnmi_get"]
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


def _run_gnmi_command(command):
    result = dict()
    st.log("CMD: {}".format(command))
    process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data, error = process.communicate()
    rc = process.poll()
    result.update({"output": data})
    result.update({"rc": rc})
    result.update({"error": error})
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
    if action == "get":
        gnmi_command = 'gnmi_get -xpath {} -target_addr {}:{}'.format(xpath, ip_address, port)
    elif action == "set":
        gnmi_command = 'gnmi_set {} {}:@{} -target_addr {}:{}'.format(mode, xpath, kwargs.get("data_file_path"), ip_address, port)
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
    kwargs.update({"ip_address":kwargs.get("ip_address", ip_addr)})
    xpath = convert_rest_url_to_gnmi_url(xpath, kwargs.get("url_params"))
    kwargs.update({"json_content":kwargs.get("data")})
    kwargs.update({"action":action})
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
            output['output'] = _get_processed_gnmi_ouput(output['output']) if kwargs.get("action") == 'get' else output['output']
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
        out=data.replace("\n", "").replace(" ", "").replace(">", "").replace("<", "").replace("'\"", "").replace("\"'", "").replace("False", "false").replace("True", "true").replace("\\", "")
        processed_output = re.findall(r'json_ietf_val:(.*)', out)
        if processed_output:
            a = processed_output[0].strip('"')
            try:
                my_data = json.loads(a)
            except Exception as e:
                st.error("Exception occurred: {}".format(e))
    st.debug("Processed gnmi GET output: {}".format(my_data))
    return my_data
