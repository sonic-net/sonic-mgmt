import json
import re
import datetime
import copy
from spytest import st

from utilities.common import filter_and_select, iterable, make_list
from utilities.utils import ensure_service_params, get_interface_number_from_name

from apis.system.rest import config_rest, get_rest, delete_rest
errors_list = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']


def add_ntp_servers(dut, iplist=[], cli_type=''):
    """
    :param dut:
    :param iplist:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("add ntp servers")
    final_data = {}
    temp_data = {}
    if iplist:
        for ip in iplist:
            temp_data[ip] = {}
    else:
        st.log("please provide atleast 1 server to configure")
        return False
    if cli_type == "click":
        final_data['NTP_SERVER'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
    elif cli_type == "klish":
        for ip in iplist:
            commands = "ntp server {}".format(ip)
            st.config(dut, commands, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        for ip in iplist:
            data={
              "openconfig-system:servers": {
                  "server": [
                {
                  "address": str(ip),
                  "config": {
                    "address": str(ip)
                  }
                }
                ]
              }
            }
            rest_urls = st.get_datastore(dut, "rest_urls")
            url1 = rest_urls['config_ntp_server'].format(ip)
            if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=data):
                st.error("Failed to configure ntp {} server".format(ip))
                return False
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    st.log("Regenerate the ntp-config")
    command = "systemctl restart ntp-config"
    st.config(dut, command)
    return True

def delete_ntp_servers(dut, cli_type=''):
    """
    :param dut:
    :param iplist:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    output = show_ntp_server(dut)
    commands = []
    if output is None:
        st.log("No servers to delete")
        return True
    else:
        for ent in iterable(output):
            server_ip = ent["remote"].strip("+*#o-x").strip()
            if cli_type == "click":
                commands.append("config ntp del {}".format(server_ip))
            elif cli_type == "klish":
                commands.append("no ntp server {}".format(server_ip))
            elif cli_type in ['rest-patch', 'rest-put']:
                rest_urls = st.get_datastore(dut, "rest_urls")
                url1 = rest_urls['config_ntp_server'].format(server_ip)
                if not delete_rest(dut, rest_url=url1):
                    st.error("Failed to delete ntp {} server".format(server_ip))
            else:
                st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
                return False
    st.config(dut, commands, type=cli_type)
    return True


def enable_ntp(dut):
    """

    :param dut:
    :return:
    """
    st.log("enable ntp")
    command = "sudo timedatectl set-ntp true"
    st.config(dut, command)
    return True


def disable_ntp(dut):
    """

    :param dut:
    :return:
    """
    st.log("disable ntp")
    command = "sudo timedatectl set-ntp false"
    st.config(dut, command)
    return True


def enable_local_rtc(dut):
    st.log("enable set-local-rtc")
    command = "sudo timedatectl set-local-rtc true"
    st.config(dut, command)
    return True


def disable_local_rtc(dut):
    """

    :param dut:
    :return:
    """
    st.log("disable set-local-rtc")
    command = "sudo timedatectl set-local-rtc false"
    st.config(dut, command)
    return True


def config_timezone(dut, zone):
    """

    :param dut:
    :param zone:
    :return:
    """
    st.log("config timezone")
    if zone:
        command = "sudo timedatectl set-timezone {}".format(zone)
        st.config(dut, command)
        return True
    else:
        st.log("please provide zone name")
        return False


def show_ntp_server(dut, cli_type=''):
    """

    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("show ntp servers")
    if cli_type == "click":
        command = "show ntp"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == "klish":
        command = "show ntp associations"
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url1 = rest_urls['show_ntp']
        server_output = get_rest(dut, rest_url=url1)
        output = get_rest_server_info(server_output['output'])
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    data = output
    output = _get_show_ntp_with_hostname_to_ip_conversion(data)
    return output

def verify_ntp_server_details(dut, server_ip=None, **kwargs):
    output = show_ntp_server(dut)
    flag = 1
    if not output:
       flag = 0
    if server_ip is None:
        if "No association ID's returned" in str(output):
            return True
        elif "%Error: Resource not found" in str(output):
            return True
        else:
            return False
    else:
        server_ips = [server_ip] if type(server_ip) is str else list([str(e) for e in server_ip])
        data = kwargs
        for ent in iterable(output):
            remote_ip = ent["remote"].strip("+*#o-x").strip()
            if remote_ip in server_ips:
                if 'remote' in data and remote_ip not in data['remote']:
                    st.log("Remote Server IP is not matching")
                    flag = 0
                if 'refid' in data and ent["refid"] != data["refid"]:
                    st.log("Ref ID is not matching")
                    flag = 0
                if 'st' in data and ent["st"] != data["st"]:
                    st.log("Stratum value is not matching")
                    flag = 0
                if 't' in data and ent["t"] != data["t"]:
                    st.log("Type is not matching")
                    flag = 0
                if 'when' in data and ent["when"] != data["when"]:
                    st.log("Polling value is not matching")
                    flag = 0
                if 'poll' in data and ent["poll"] != data["poll"]:
                    st.log("Polling in seconds is not matching")
                    flag = 0
                if 'reach' in data and ent["reach"] != data["reach"]:
                    st.log("Reach is not matching")
                    flag = 0
                if 'delay' in data and ent["delay"] != data["delay"]:
                    st.log("Delay is not matching")
                    flag = 0
                if 'offset' in data and ent["offset"] != data["offset"]:
                    st.log("Offset value is not matching")
                    flag = 0
                if 'jitter' in data and ent["jitter"] != data["jitter"]:
                    st.log("Jitter value is not matching")
                    flag = 0
            else:
                st.log("Server IP is not matching")
                flag = 0
        if flag:
            st.log("Server IP's  matched.")
            return True
        else:
            st.log("Server IP's not matched.")
            return False

def show_ntp_status(dut,mvrf=False):
    """

    :param dut:
    :return:
    """
    st.log("show ntp status")
    if mvrf:
        command = "sudo cgexec -g l3mdev:mgmt ntpstat"
    else:
        command = "ntpstat"
    output = st.show(dut, command)
    retval = []
    entries = filter_and_select(output, ["server", "stratum", "time", "poll"])
    for ent in entries:
        retval.append(ent["server"].strip("()"))
        retval.append(ent["stratum"])
        retval.append(ent["time"])
        retval.append(ent["poll"])
    return retval


def config_date(dut, date):
    """

    :param dut:
    :param date:
    :return:
    """
    st.log("config date")
    command = "date --set='{}'".format(date)
    st.config(dut, command)
    return True

def set_date_ntp(dut):
    """

    :param dut:
    :param date:
    :return:
    """
    st.log("set date using ntpd")
    command = "sudo /usr/sbin/ntpd -q -g -x &"
    st.config(dut, command)
    return True


def show_timedatectl_status(dut):
    """

    :param dut:
    :return:
    """
    st.log("timedatectl status")
    command = "timedatectl status"
    output = st.show(dut, command)
    return output


def show_clock(dut, cli_type=''):
    """

    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    st.log("show clock")
    if cli_type in ["click", "klish"]:
        command = "show clock"
        output = st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url1 = rest_urls['show_clock']
        data=get_rest(dut, rest_url=url1)
        data = data['output']['openconfig-system-ext:clock']
        output = get_time_zone_info(data)
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return output[0]


def verify_clock(dut, time):
    """

    :param dut:
    :param time:
    :return:
    """
    st.log("verifying show clock")
    retval = show_clock(dut)
    if retval == time:
        return True
    else:
        return False


def verify_timedatectl(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    st.log("verifying timedatectl")
    retval = show_timedatectl_status(dut)
    flag = 1
    data = kwargs
    if not data:
        st.error("Please provide details to be verified.")
        return False
    else:
        if 'rtctime' in data:
            if retval[0]['rtctime'] != data['rtctime']:
                flag = 0
        if 'universaltime' in data:
            if retval[0]['universaltime'] != data['universaltime']:
                flag = 0
        if 'networktimeon' in data:
            if retval[0]['networktimeon'] != data['networktimeon']:
                flag = 0
        if 'ntpsynchronized' in data:
            if retval[0]['ntpsynchronized'] != data['ntpsynchronized']:
                flag = 0
        if 'timezone' in data:
            if retval[0]['timezone'] != data['timezone']:
                flag = 0
        if 'localtime' in data:
            if retval[0]['localtime'] != data['localtime']:
                flag = 0
    if flag:
        return True
    else:
        return False


def verify_ntp_status(dut, iteration=1, delay=1, mvrf=False, **kwargs):
    """
    Verify NTP status with polling.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param server: single or list of servers.
    :param stratum:
    :param time:
    :param poll:
    :param iteration: 1 sec (default)
    :param delay: 1 sec (default)
    :return:
    """
    st.log("verifying ntp status")
    i = 0
    if not kwargs:
        st.error("Please provide details to be verified.")
        return False
    else:
        while True:
            flag = 0
            retval = show_ntp_status(dut,mvrf)
            if not retval:
                st.log("No o/p from ntpstat command")
                if i > iteration:
                    st.log("NTP status failed.")
                    st.log("Max iterations {} reached".format(i))
                    return False
                i += 1
                st.wait(delay)
                continue
            if 'server' in kwargs:
                server_li = list(kwargs['server']) if isinstance(kwargs['server'], list) else [kwargs['server']]
                if retval[0] in server_li:
                    st.log("Detected NTP server - {}".format(retval[0]))
                    flag += 1
            if 'stratum' in kwargs:
                if retval[1] == kwargs['stratum']:
                    flag += 1
            if 'time' in kwargs:
                if retval[2] == kwargs['time']:
                    flag += 1
            if 'poll' in kwargs:
                if retval[3] == kwargs['poll']:
                    flag += 1
            if flag == len(kwargs):
                return True
            if i > iteration:
                st.log("NTP status failed.")
                st.log("Max iterations {} reached".format(i))
                return False
            i += 1
            st.wait(delay)


def verify_ntp_server(dut, serverip, **kwargs):
    """

    :param dut:
    :param serverip:
    :param kwargs:
    :return:
    """
    st.log("verifying ntp server")
    flag = 1
    data = kwargs
    if not data or not serverip:
        st.error("Please provide details to be verified.")
        return False
    else:
        retval = show_ntp_server(dut)
        if not retval:
            return False
        else:
            if 'remote' in data:
                if retval[0] != data['remote']:
                    flag = 0
            if 'refid' in data:
                if retval[1] != data['refid']:
                    flag = 0
            if 'st' in data:
                if retval[2] != data['st']:
                    flag = 0
            if 't' in data:
                if retval[3] != data['t']:
                    flag = 0
            if 'when' in data:
                if retval[4] != data['when']:
                    flag = 0
            if 'poll' in data:
                if retval[5] != data['poll']:
                    flag = 0
            if 'reach' in data:
                if retval[6] != data['reach']:
                    flag = 0
            if 'delay' in data:
                if retval[7] != data['delay']:
                    flag = 0
            if 'offset' in data:
                if retval[8] != data['offset']:
                    flag = 0
            if 'jitter' in data:
                if retval[9] != data['jitter']:
                    flag = 0
    if flag:
        return True
    else:
        return False


def verify_ntp_service_status(dut, status, iteration=1, delay=1):
    """
    Verify NTP service status with polling
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param status:
    :param iteration: 1 sec (default)
    :param delay: 1 sec (default)
    :return:
    """
    command = "service ntp status | grep Active"
    i = 1
    while True:
        output = st.config(dut, command)
        if status in output:
            st.log("NTP service status is '{}' iteration".format(i))
            return True
        if i > iteration:
            st.log("NTP service status is not '{}'")
            st.log("Max iterations {} reached".format(i))
            return False
        i += 1
        st.wait(delay)

def verify_ntp_server_exists(dut, server_ip=None, **kwargs):
    output = show_ntp_server(dut)
    if server_ip is None:
        if "No association ID's returned" in str(output):
            return True
        else:
            return False
    else:
        server_ips = [server_ip] if type(server_ip) is str else list([str(e) for e in server_ip])
        data = kwargs
        for ent in iterable(output):
            remote_ip = ent["remote"].strip("+*#o-x").strip()
            if remote_ip in server_ips:
                if 'remote' in data and remote_ip not in data['remote']:
                    st.log("Remote Server IP is not matching")
                    return False
                else:
                    return True


def ensure_ntp_config(dut,iplist=[], cli_type=''):
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if not iplist:
        iplist = ensure_service_params(dut, "ntp", "default")
    if not iplist:
        st.log("NTP server IPs missing")
        return False
    commands = []
    for ip in iplist:
        if not verify_ntp_server_exists(dut, ip, remote=ip):
            if cli_type == "click":
                commands.append("config ntp add {}".format(ip))
            elif cli_type == "klish":
                commands.append("ntp server {}".format(ip))
            elif cli_type in ['rest-patch', 'rest-put']:
                data = {
                    "openconfig-system:servers": {
                        "server": [
                        {
                        "address": str(ip),
                        "config": {
                            "address": str(ip)
                        }
                        }
                        ]
                    }
                    }
                rest_urls = st.get_datastore(dut, "rest_urls")
                url1 = rest_urls['config_ntp_server'].format(ip)
                if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=data):
                    st.error("Failed to configure ntp {} server".format(ip))
                    return False
            else:
                st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
                return False
    st.config(dut, commands, type=cli_type)
    return True

def _get_show_ntp_with_hostname_to_ip_conversion(data):
    ret_val = list()
    ntp_server_hostname_ip_map = {"io.crash-override.org": "47.190.36.230", "horp-bsd01.horp.io": "192.111.144.114", "time3.google.com":"216.239.35.8", "time4.google.com":"216.239.35.12", "time2.google.com":"216.239.35.4"}
    for entry in data:
        for hostname, ip in ntp_server_hostname_ip_map.items():
            if ('remote' in entry) and (entry['remote'][1:] in hostname):
                entry.update(remote=ip)
        ret_val.append(entry)
    return ret_val

def get_rest_server_info(server_output):
    ret_val = []
    try:
        servers = server_output["openconfig-system:server"]
        for server in servers:
            temp = dict()
            server_details = server['state']
            req_params = ['address', 'openconfig-system-ext:reach', 'openconfig-system-ext:now', 'stratum', 'openconfig-system-ext:peerdelay', 'openconfig-system-ext:peertype', 'openconfig-system-ext:peeroffset', 'openconfig-system-ext:peerjitter', 'poll-interval', 'openconfig-system-ext:refid', 'openconfig-system-ext:selmode']
            if all(param in server_details for param in req_params):
                temp['remote'] = str(server_details['openconfig-system-ext:selmode']+server_details['address'])
                temp['reach'] = str(server_details['openconfig-system-ext:reach'])
                temp['when'] = str(server_details['openconfig-system-ext:now'])
                temp['st'] = str(server_details['stratum'])
                temp['delay'] = str(server_details['openconfig-system-ext:peerdelay'])
                temp['t'] = str(server_details['openconfig-system-ext:peertype'])
                temp['offset'] = str(server_details['openconfig-system-ext:peeroffset'])
                temp['jitter'] = str(server_details['openconfig-system-ext:peerjitter'])
                temp['poll'] = str(server_details['poll-interval'])
                temp['refid'] = str(server_details['openconfig-system-ext:refid'])
                ret_val.append(temp)
        st.debug(ret_val)
        return ret_val
    except Exception as e:
        st.error("{} exception occurred".format(e))
        st.debug("Given data is: {}".format(server_output))
        return ret_val

def get_time_zone_info(data):
    elements =  re.findall(r"(\S+)\,\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\:(\d+)\:(\d+)\s+(\S+)", data)
    if len(elements[0])==8:
        data = elements[0]
        ret_val = list()
        out = dict()
        out['day'] = data[0]
        out['monthday'] = data[1]
        out['month'] = data[2]
        out['year'] = data[3]
        out['hours'] = data[4]
        out['minutes'] = data[5]
        out['seconds'] = data[6]
        out['timezone'] = data[7]
        ret_val.append(out)
        return ret_val
    else:
        st.error("invalid data")
        return False


def get_ntp_logs(dut, filter=None):
    """
    To get the NTP related logs from /var/log/ntp.log
    :param dut:
    :param filter:
    :return out_list
    """
    command = "cat /var/log/ntp.log"
    command = "{} | grep '{}'".format(command, filter) if filter else command
    output = st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False, max_time=1200)
    out_list = output.strip().split('\n')[:-1]
    for _ in range(out_list.count("'")):
        out_list.remove("'")
    return out_list


def verify_time_synch(server_time, client_time):
    diff=10
    month_dict = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
    try:
        time1 = datetime.datetime(int(server_time['year']), month_dict[server_time['month']], int(server_time['monthday']), int(server_time['hours']), int(server_time['minutes']), int(server_time['seconds']))
        time2 = datetime.datetime(int(client_time['year']), month_dict[client_time['month']], int(client_time['monthday']), int(client_time['hours']), int(client_time['minutes']), int(client_time['seconds']))
        difference = (time1 - time2).total_seconds()
    except Exception as e:
        st.error("'{}' exception occurred".format(e))
        return False
    return True if int(difference) < diff else False


def verify_ntp_synch(dut, server):
    entries = show_ntp_server(dut)
    if filter_and_select(entries, None, {'remote': "*{}".format(server)}):
        st.debug("NTP synchronized with server: {}".format(server))
        return True
    st.error("NTP not synchronized with server: {}".format(server))
    return False


def config_ntp_parameters(dut, **kwargs):
    """
    To Configure NTP paramters
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', True)
    skip_error = kwargs.get('skip_error', False)
    commands = list()
    if cli_type == "klish":
        if 'source_intf' in kwargs:
            config_string = '' if config else 'no '
            for src_intf in make_list(kwargs['source_intf']):
                intf_data = get_interface_number_from_name(src_intf)
                commands.append('{}ntp source-interface {} {}'.format(config_string, intf_data['type'], intf_data['number']))
        if 'vrf' in kwargs:
            if not config:
                commands.append('no ntp vrf')
            else:
                commands.append('ntp vrf {}'.format(kwargs['vrf']))
        if 'authenticate' in kwargs:
            config_string = '' if config else 'no '
            commands.append('{}ntp authenticate'.format(config_string))
        if kwargs.get('auth_key_id'):
            if not config:
                commands.append('no ntp authentication-key {}'.format(kwargs['auth_key_id']))
            else:
                if kwargs.get('auth_type') and kwargs.get('auth_string'):
                    commands.append('ntp authentication-key {} {} "{}"'.format(kwargs['auth_key_id'], kwargs['auth_type'], kwargs['auth_string']))
        if kwargs.get('trusted_key'):
            config_string = '' if config else 'no '
            commands.append('{}ntp trusted-key {}'.format(config_string, kwargs['trusted_key']))
        if kwargs.get('servers'):
            servers = make_list(kwargs.get('servers'))
            for server in servers:
                if not config:
                    commands.append('no ntp server {}'.format(server))
                else:
                    commands.append('ntp server {} key {}'.format(server, kwargs['server_key']) if kwargs.get('server_key') else 'ntp server {}'.format(server))
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if 'source_intf' in kwargs:
            for src_intf in make_list(kwargs['source_intf']):
                src_intf = 'eth0' if src_intf == "Management0" else src_intf
                if config:
                    url = rest_urls['ntp_config_source_interface']
                    payload = json.loads("""{"openconfig-system-ext:ntp-source-interface": ["string"]}""")
                    payload["openconfig-system-ext:ntp-source-interface"] = [src_intf]
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        return False
                else:
                    url = rest_urls['ntp_delete_source_interface'].format(src_intf)
                    if not delete_rest(dut, rest_url=url):
                        return False
        if 'vrf' in kwargs:
            if config:
                url = rest_urls['ntp_config_vrf_delete']
                payload = json.loads("""{"openconfig-system-ext:vrf": "string"}""")
                payload["openconfig-system-ext:vrf"] = kwargs['vrf']
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
            else:
                url = rest_urls['ntp_config_vrf_delete']
                if not delete_rest(dut, rest_url=url):
                    return False
        if 'authenticate' in kwargs:
            url = rest_urls['ntp_config']
            if config:
                payload = json.loads("""{"openconfig-system:config": {"enable-ntp-auth": true}}""")
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
            else:
                payload = json.loads("""{"openconfig-system:config": {"enable-ntp-auth": false}}""")
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
        if kwargs.get('auth_key_id'):
            keymap = {"md5" : "NTP_AUTH_MD5", 'sha1' : 'NTP_AUTH_SHA1', 'sha2-256' : 'NTP_AUTH_SHA2_256'}
            if not config:
                url = rest_urls['ntp_key_delete'].format(kwargs['auth_key_id'])
                if not delete_rest(dut, rest_url=url):
                    return False
            else:
                if kwargs.get('auth_type') and kwargs.get('auth_string'):
                    url = rest_urls['ntp_key_config']
                    payload = json.loads("""{"openconfig-system:ntp-keys": {
                                                "ntp-key": [
                                                  {
                                                    "key-id": 0,
                                                    "config": {
                                                      "key-id": 0,
                                                      "key-type": "string",
                                                      "openconfig-system-ext:encrypted": false,
                                                      "key-value": "string"
                                                    }
                                                  }
                                                ]
                                              }
                                            }""")
                    payload["openconfig-system:ntp-keys"]["ntp-key"][0]["key-id"] = int(kwargs['auth_key_id'])
                    payload["openconfig-system:ntp-keys"]["ntp-key"][0]["config"]["key-id"] = int(kwargs['auth_key_id'])
                    payload["openconfig-system:ntp-keys"]["ntp-key"][0]["config"]["key-type"] = keymap[kwargs['auth_type']]
                    payload["openconfig-system:ntp-keys"]["ntp-key"][0]["config"]["key-value"] = kwargs['auth_string']
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        return False
        if kwargs.get('trusted_key'):
            if config:
                url = rest_urls['ntp_config']
                payload = json.loads("""{"openconfig-system:config": {"openconfig-system-ext:trusted-key": [0]}}""")
                payload["openconfig-system:config"]["openconfig-system-ext:trusted-key"] = [int(kwargs['trusted_key'])]
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                    return False
            else:
                url = rest_urls["ntp_trusted_key_delete"].format(kwargs['trusted_key'])
                if not delete_rest(dut, rest_url=url):
                    return False
        if kwargs.get('servers'):
            servers = make_list(kwargs.get('servers'))
            for server in servers:
                if not config:
                    url = rest_urls['delete_ntp_server'].format(server)
                    if not delete_rest(dut, rest_url=url):
                        return False
                else:
                    url = rest_urls['config_ntp_server']
                    if kwargs.get('server_key'):
                        payload = json.loads("""{"openconfig-system:servers": {
                                                    "server": [
                                                      {
                                                        "address": "string",
                                                        "config": {
                                                          "address": "string",
                                                          "openconfig-system-ext:key-id": 0
                                                        }
                                                      }
                                                    ]
                                                  }
                                                }""")
                        payload["openconfig-system:servers"]["server"][0]["address"] = server
                        payload["openconfig-system:servers"]["server"][0]["config"]["address"] = server
                        payload["openconfig-system:servers"]["server"][0]["config"]["openconfig-system-ext:key-id"] = int(kwargs.get('server_key'))
                    else:
                        payload = json.loads("""{"openconfig-system:servers": {
                                                    "server": [
                                                      {
                                                        "address": "string",
                                                        "config": {
                                                          "address": "string"
                                                        }
                                                      }
                                                    ]
                                                  }
                                                }""")
                        payload["openconfig-system:servers"]["server"][0]["address"] = server
                        payload["openconfig-system:servers"]["server"][0]["config"]["address"] = server
                    if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=payload):
                        return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if commands:
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error in response.lower() for error in errors_list):
            st.error("The response is: {}".format(response))
            return False
    return True

def show(dut, kwargs):
    """
    To get the show output of NTP servers/global configuration
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = 'klish' if cli_type == 'click' else cli_type
    if cli_type == 'klish':
        if kwargs.get('server'):
            command = 'show ntp server'
        elif kwargs.get('global'):
            command = 'show ntp global'
        else:
            st.error('show command is not called for server/global')
            return False
        return st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        output = []
        rest_urls = st.get_datastore(dut, "rest_urls")
        if kwargs.get('server'):
            url = rest_urls["show_ntp_server"]
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-system:server"]
            for row in payload:
                table_data = {'server': row["state"]["address"]}
                output.append(copy.deepcopy(table_data))
        elif kwargs.get('global'):
            url = rest_urls["show_ntp_global"]
            table_data = {'source_intf' : "", 'vrf' : ""}
            payload = get_rest(dut, rest_url=url)["output"]["openconfig-system:state"]
            if "openconfig-system-ext:ntp-source-interface" in payload:
                table_data['source_intf'] = payload["openconfig-system-ext:ntp-source-interface"]
            if "openconfig-system-ext:vrf" in payload:
                table_data['vrf'] = payload["openconfig-system-ext:vrf"]
            output.append(copy.deepcopy(table_data))
        else:
            st.error('show command is not called for server/global')
            return False
        st.log("OUTPUT : {}".format(output))
        return output
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False

