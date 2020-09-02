# This file contains the list of API's for operations of GNMI CLI
# @author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

from spytest import st
import tempfile
import utilities.utils as util_obj
import json
from apis.system.basic import service_operations_by_systemctl

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
    docer_name = "TELEMETRY"
    docker_name= "telemetry"
    command = 'redis-cli -n 4 hmset "TELEMETRY|gnmi" client_auth'
    if 'auth_type' in kwargs:
        if kwargs.get('auth_type'):
            command = 'redis-cli -n 4 hmset "TELEMETRY|gnmi" client_auth "{}"'.format(kwargs.get('auth_type'))
        else:
            command = 'redis-cli -n 4 hdel "TELEMETRY|gnmi" client_auth'
        st.config(dut, command)
    if 'server_key' in kwargs:
        if kwargs.get('server_key'):
            command = 'redis-cli -n 4 hmset "DEVICE_METADATA|x509" server_key "{}"'.format(kwargs.get('server_key'))
        st.config(dut, command)
    if 'server_crt' in kwargs:
        if kwargs.get('server_crt'):
            command = 'redis-cli -n 4 hmset "DEVICE_METADATA|x509" server_crt "{}"'.format(kwargs.get('server_crt'))
        st.config(dut, command)
    if 'ca_crt' in kwargs:
        if kwargs.get('ca_crt'):
            command = 'redis-cli -n 4 hmset "DEVICE_METADATA|x509" ca_crt "{}"'.format(kwargs.get('ca_crt'))
        else:
            command = 'redis-cli -n 4 hdel "DEVICE_METADATA|x509" ca_crt'
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