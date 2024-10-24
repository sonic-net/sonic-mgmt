
import re

from spytest import st

from utilities.utils import get_supported_ui_type_list
import utilities.common as utils

try:
    import apis.yang.codegen.messages.platform_i2c as umf_i2c
    import apis.yang.codegen.messages.platform_i2c.PlatformI2cRpc as umf_i2c_rpc
    from apis.yang.codegen.yang_rpc_service import YangRpcService
except ImportError:
    pass


def err_simulation(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    device_addr = kwargs.get('device_addr', None)
    i2c_error = kwargs.get('i2c_error', None)
    state = kwargs.get('state', 'start')
    cli_type = 'click' if cli_type in get_supported_ui_type_list() + ['klish'] else cli_type
    command = []
    if device_addr:
        cmd = 'sh -c "echo {} > /sys/kernel/i2c_error_stats/simulation/device"'.format(device_addr)
        command.append(cmd)
    if i2c_error:
        cmd = 'sh -c "echo {} > /sys/kernel/i2c_error_stats/simulation/error"'.format(i2c_error)
        command.append(cmd)
    if state == "start":
        cmd = 'sh -c "echo 1 > /sys/kernel/i2c_error_stats/simulation/state"'
        command.append(cmd)
    else:
        cmd = 'sh -c "echo 0 > /sys/kernel/i2c_error_stats/simulation/state"'
        command.append(cmd)
    st.config(dut, command, type=cli_type)
    return True


def show_i2c(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    device_name = kwargs.get('device_name', None)
    yang_data_type = kwargs.get("yang_data_type", "ALL")
    if cli_type in get_supported_ui_type_list():
        if 'device_name' not in kwargs:
            cli_type = "klish"
    if cli_type == 'click':
        if device_name:
            cmd = 'show platform i2c errors {}'.format(device_name)
        else:
            cmd = 'show platform i2c errors'
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type == 'klish':
        if device_name:
            cmd = 'show platform i2c errors {}'.format(device_name)
        else:
            cmd = 'show platform i2c errors'
        output = st.show(dut, cmd, type=cli_type)
    elif cli_type in get_supported_ui_type_list():
        i2c_obj = umf_i2c.I2cError(Name=device_name)
        query_params_obj = utils.get_query_params(yang_data_type=yang_data_type, cli_type=cli_type)
        out = i2c_obj.get_payload(dut, query_param=query_params_obj, cli_type=cli_type)
        if not out.ok():
            return False
        output = process_i2c_output(out.payload)
    return output


def clear_i2c(dut, **kwargs):
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type == 'click':
        cmd = 'show platform i2c errors -c'
        st.config(dut, cmd, type=cli_type)
    elif cli_type == 'klish':
        cmd = 'clear i2c errors'
        st.config(dut, cmd, type=cli_type)
    elif cli_type in get_supported_ui_type_list():
        service = YangRpcService()
        rpc = umf_i2c_rpc.I2cErrorClearRpc()
        service.execute(dut, rpc, timeout=60)
    return True


def check_log_msgs(dut, log_path=["/var/log/syslog-debug.log", "/var/log/syslog"], skip_error_check=True, **kwargs):
    """
    :param dut:
    :param log_path:
    :return:
    """
    expected_message_cnt = kwargs.get('expected_message_cnt', 0)
    message = kwargs.get('message', '')
    date_range = kwargs.get('date_range', [])
    logs_path = utils.make_list(log_path)
    total_msg_cnt = 0
    for path in logs_path:
        if date_range and len(date_range) == 2:
            command = "sudo sed -n '/{}/,/{}/p' {}".format(date_range[0], date_range[1], path)
        elif date_range and len(date_range) == 1:
            command = "sudo sed -n '/{}/,$p' {}".format(date_range[0], path)
        output = st.show(dut, command, skip_tmpl=True, skip_error_check=skip_error_check)
        if output:
            msgs = re.findall(r"{}".format(message), output)
            if msgs:
                if len(msgs) != int(expected_message_cnt):
                    total_msg_cnt += len(msgs)
                else:
                    total_msg_cnt = len(msgs)
        if total_msg_cnt == expected_message_cnt:
            break
    return total_msg_cnt


def process_i2c_output(data):
    retval = []
    if data.get("openconfig-platform-i2c:i2c-error") and isinstance(data["openconfig-platform-i2c:i2c-error"], list):
        i2c_info = data["openconfig-platform-i2c:i2c-error"]
    else:
        return False
    for output in i2c_info:
        temp = dict()
        if isinstance(output, dict) and output.get("state") and isinstance(output["state"], dict):
            temp["device"] = output["state"]["name"] if output["state"].get("name") else 0
            temp["busaddress"] = output["state"]["dev_addr"] if output["state"].get("dev_addr") else 0
            temp["input_output_error"] = output["state"]["eio"] if output["state"].get("eio") else 0
            temp["timeout_error"] = output["state"]["etimedout"] if output["state"].get("etimedout") else 0
            temp["busbusy_error"] = output["state"]["ebusy"] if output["state"].get("ebusy") else 0
            temp["nack_error"] = output["state"]["enxio"] if output["state"].get("enxio") else 0
            temp["arbitartion_error"] = output["state"]["eagain"] if output["state"].get("eagain") else 0
            temp["timestamp"] = output["state"]["timestamp"] if output["state"].get("timestamp") else ""
            retval.append(temp)
    st.debug(retval)
    return retval


def verify(dut, **kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    result = show_i2c(dut, **kwargs)
    if cli_type not in get_supported_ui_type_list():
        if result[0]['message_string'] == "No I2C error stats data available for CPL1":
            result = False
    return result
