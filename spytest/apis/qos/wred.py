import json
from spytest import st
from apis.system.rest import config_rest
from utilities.utils import get_interface_number_from_name

errors_list = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']

get_klish_rate = lambda a: int(int(a)/1000)


def apply_wred_ecn_config(dut, config, cli_type=''):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param config:
    :type config:
    :param cli_type:
    :type cli_type:
    :return:
    :rtype:
    """
    if not 'WRED_PROFILE' in config:
        st.debug('Invalid config data: {}'.format(config))
        return False
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if cli_type == 'click':
        json_config = json.dumps(config)
        json.loads(json_config)
        st.apply_json2(dut, json_config)
    elif cli_type in ['klish', 'rest-patch', 'rest-put']:
        wred_data = config['WRED_PROFILE']
        port_data = config.get('QUEUE', None)
        for profile, wred_config in wred_data.items():
            ecn = wred_config.get('ecn', None)
            green_min_threshold = wred_config.get('green_min_threshold', None)
            green_max_threshold = wred_config.get('green_max_threshold', None)
            green_dp = wred_config.get('green_drop_probability', None)
            green_enable = wred_config.get('wred_green_enable', None)
            commands = list()
            if cli_type == 'klish':
                commands.append('qos wred-policy {}'.format(profile))
                if ecn:
                    commands.append('ecn {}'.format(ecn.replace('ecn_', '')))
                if all([green_max_threshold, green_min_threshold, green_dp]):
                    commands.append('green minimum-threshold {} maximum-threshold {} drop-probability {}'.format(get_klish_rate(green_min_threshold), get_klish_rate(green_max_threshold), green_dp))
                commands.append('exit')
            else:
                rest_urls = st.get_datastore(dut, 'rest_urls')
                if ecn:
                    url = rest_urls['wred_params_config'].format(profile)
                    config_json = {"openconfig-qos-ext:wred-profile": [{"name": profile, "config": {"name": profile, "ecn": ecn.upper()}}]}
                    if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                        st.error('Failed to configure ECN: {} for WRED_PROFILE: {}'.format(ecn, profile))
                        return False
                if green_min_threshold:
                    url = rest_urls['wred_green_min_threshold_config'].format(profile)
                    config_json = {"openconfig-qos-ext:green-min-threshold": str(green_min_threshold)}
                    if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                        st.error('Failed to configure the green_min_threshold: {} for WRED_PROFILE: {}'.format(green_min_threshold, profile))
                        return False
                if green_max_threshold:
                    url = rest_urls['wred_green_max_threshold_config'].format(profile)
                    config_json = {"openconfig-qos-ext:green-max-threshold": str(green_max_threshold)}
                    if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                        st.error('Failed to configure the green_max_threshold: {} for WRED_PROFILE: {}'.format(green_max_threshold, profile))
                        return False
                if green_dp:
                    url = rest_urls['wred_green_drop_probability_config'].format(profile)
                    config_json = {"openconfig-qos-ext:green-drop-probability": str(green_dp)}
                    if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                        st.error('Failed to configure the green_drop_probability: {} for WRED_PROFILE: {}'.format(green_dp, profile))
                        return False
                if green_enable:
                    url = rest_urls['wred_green_enable_config'].format(profile)
                    config_json = {"openconfig-qos-ext:wred-green-enable": True}
                    if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_json):
                        st.error('Failed to configure the wred_green_enable for WRED_PROFILE: {}'.format(profile))
                        return False
        if port_data:
            config_apply_list = list()
            for port, wred_map in port_data.items():
                temp = dict()
                p, q = port.split('|')
                temp['port'] = p.split(',')
                if '-' in q:
                    queue1, queue2 = q.split('-')
                    temp['queue'] = list(range(int(queue1), int(queue2)+1))
                else:
                    temp['queue'] = q.split(',')
                temp['wred_profile'] = wred_map['wred_profile']
                config_apply_list.append(temp)
            st.debug('port map data is: {}'.format(config_apply_list))
            for entry in config_apply_list:
                for port in entry['port']:
                    if cli_type == 'klish':
                        intf_data = get_interface_number_from_name(port)
                        commands.append('interface {} {}'.format(intf_data['type'], intf_data['number']))
                        commands.extend(['queue {} wred-policy {}'.format(queue, entry['wred_profile']) for queue in entry['queue']])
                        commands.append('exit')
                    else:
                        urls = [rest_urls['wred_profile_apply_config'].format(port, queue) for queue in entry['queue']]
                        config_json = {"openconfig-qos:config": {"openconfig-qos-ext:wred-profile": entry['wred_profile']}}
                        for url in urls:
                            if not config_rest(dut, http_method=cli_type, rest_url = url, json_data=config_json):
                                st.error('Failed to apply WRED_PROFILE: {} to port: {}'.format(entry['wred_profile'], port))
                                return False

        if commands:
            response = st.config(dut, commands, type=cli_type)
            if any(error in response.lower() for error in errors_list):
                st.error("The response is: {}".format(response))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True
