from spytest.utils import filter_and_select
from spytest import st
import json
from utilities.utils import ensure_service_params


def add_ntp_servers(dut, iplist=[]):
    """

    :param dut:
    :param iplist:
    :return:
    """
    st.log("add ntp servers")
    final_data = {}
    temp_data = {}
    if iplist:
        for ip in iplist:
            temp_data[ip] = {}
    else:
        st.log("please provide atleast 1 server to configure")
        return False
    final_data['NTP_SERVER'] = temp_data
    final_data = json.dumps(final_data)
    st.apply_json(dut, final_data)
    st.log("Regenerate the ntp-config")
    command = "systemctl restart ntp-config"
    st.config(dut, command)
    return True


def delete_ntp_servers(dut, iplist=[]):
    """

    :param dut:
    :param iplist:
    :return:
    """
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


def show_ntp_server(dut):
    """

    :param dut:
    :return:
    """
    st.log("show ntp servers")
    command = "show ntp"
    output = st.show(dut, command)
    return output

def verify_ntp_server_details(dut, server_ip=None, **kwargs):
    output = show_ntp_server(dut)
    flag = 1
    if server_ip is None:
        if "No association ID's returned" in output:
            return True
        else:
            return False
    else:
        server_ips = [server_ip] if type(server_ip) is str else list([str(e) for e in server_ip])
        data = kwargs
        for ent in output:
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


def show_clock(dut):
    """

    :param dut:
    :return:
    """
    st.log("show clock")
    command = "show clock"
    output = st.show(dut, command)
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
    flag = 1
    if server_ip is None:
        if "No association ID's returned" in output:
            return True
        else:
            return False
    else:
        server_ips = [server_ip] if type(server_ip) is str else list([str(e) for e in server_ip])
        data = kwargs
        for ent in output:
            remote_ip = ent["remote"].strip("+*#o-x").strip()
            if remote_ip in server_ips:
                if 'remote' in data and remote_ip not in data['remote']:
                    st.log("Remote Server IP is not matching")
                    return False
                else:
                    return True


def ensure_ntp_config(dut,iplist=[]):
    if not iplist:
        iplist = ensure_service_params(dut, "ntp", "default")
    if not iplist:
        st.log("NTP server IPs missing")
        return False
    commands = []
    for ip in iplist:
        if not verify_ntp_server_exists(dut, ip, remote=ip):
            commands.append("config ntp add {}".format(ip))
    st.config(dut, commands)
    return True

