import re
from spytest import st
from apis.system.rest import config_rest



def config_ecn(dut, status, profile, **kwargs):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param status:
    :type status:
    :param profile:
    :type profile:
    :return:
    :rtype:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type == 'klish':
        cli_type = 'rest-patch'  ##Using OC-YANG even the cli_type is 'klish' because we don't have support to configure individual paramters.
    kwargs.pop('cli_type', None)
    data = kwargs
    if not data or not status or not profile:
        st.error("Please provide ecn parameters to be configured. Mandatory are status on/off and profile name")
        return False
    if cli_type == 'click':
        command = "ecnconfig -p {} {} ".format(profile,status)
        command += ' '.join('-{} {}'.format(key, value) for key, value in data.items())
        st.debug(command)
        st.config(dut, command)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if data.get('ecnmode'):
            url = rest_urls['wred_params_config'].format(profile)
            config_json = {"openconfig-qos-ext:wred-profile": [{"name": profile, "config": {"name": profile, "ecn": data['ecnmode'].upper()}}]}
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                st.error('Failed to configure ECN: {} for WRED_PROFILE: {}'.format(data['ecnmode'], profile))
                return False
        if data.get('gmax'):
            url = rest_urls['wred_green_max_threshold_config'].format(profile)
            config_json = {"openconfig-qos-ext:green-max-threshold": str(data['gmax'])}
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                st.error('Failed to configure the green_max_threshold: {} for WRED_PROFILE: {}'.format(data['gmax'], profile))
                return False
        if data['gmin']:
            url = rest_urls['wred_green_min_threshold_config'].format(profile)
            config_json = {"openconfig-qos-ext:green-min-threshold": str(data['gmin'])}
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                st.error('Failed to configure the green_min_threshold: {} for WRED_PROFILE: {}'.format(data['gmin'], profile))
                return False
        if data.get('gdrop'):
            url = rest_urls['wred_green_drop_probability_config'].format(profile)
            config_json = {"openconfig-qos-ext:green-drop-probability": str(data['gdrop'])}
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                st.error('Failed to configure the green_drop_probability: {} for WRED_PROFILE: {}'.format(data['gdrop'], profile))
                return False
        if status:
            url = rest_urls['wred_green_enable_config'].format(profile)
            config_json = {"openconfig-qos-ext:wred-green-enable": True}
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                st.error('Failed to configure the wred_green_enable for WRED_PROFILE: {}'.format(profile))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def show_ecn_config(dut):

    command = "show ecn"
    output = st.show(dut, command)
    retval = dict()
    for entry in output:
        retval["profile"] = entry["profile"]
        var = re.split(r"\s+", entry["data"])
        if var[0]: retval[var[0]] = var[1]
    return retval
