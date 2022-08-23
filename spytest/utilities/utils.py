# This file contains the list of command utility functions
# Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com) / Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re
import socket
import datetime
import json
import random

from binascii import hexlify

from spytest import st

import utilities.parallel as pll
from utilities.common import filter_and_select, dicts_list_values, make_list

def remove_last_line_from_string(data):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to remove the last line of the string
    :param data:
    :return:
    """
    return data[:data.rfind('\n')]


def get_last_line_from_string(data):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to get last line of the string
    :param data:
    :return:
    """
    output = data.split("\n")
    return output[0]


def date_time_delta(datetime_1, datetime_2, timezone=False):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to get the date time delta
    :param datetime_1:
    :param datetime_2:
    :param timezone:
    :return:
    """
    try:
        datetime_1 = datetime.datetime.strptime(str(datetime_1), "%Y-%m-%d %H:%M:%S %Z") \
            if timezone else datetime.datetime.strptime(str(datetime_1), "%Y-%m-%d %H:%M:%S")
        datetime_2 = datetime.datetime.strptime(str(datetime_2), "%Y-%m-%d %H:%M:%S %Z") \
            if timezone else datetime.datetime.strptime(str(datetime_2), "%Y-%m-%d %H:%M:%S")
        date_diff = datetime_2 - datetime_1
        return divmod(date_diff.days * 86400 + date_diff.seconds, 60)
    except Exception as e:
        st.log(e)
        st.error(e)
        return None


def check_file_exists(file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to check the file path
    :param file_path:
    :return:
    """
    import os
    exists = os.path.isfile(file_path)
    return True if exists else False


def get_mac_address(base_mac="00:00:00:00:00:00", start=0, end=100, step=1):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to generate MAC addresses
    :param base_mac:
    :param start:
    :param end:
    :param step:
    :return:
    """
    mac_address_list = list()
    base_mac = base_mac.replace(":", '').replace(" ", '')
    mac_int = int("0x"+base_mac, 16)
    for i in range(mac_int+start, (mac_int+end)*step, step):
        mac_address = "{0:0{1}x}".format(i, 12)
        mac_formated = ":".join([mac_address[i:i+2] for i in range(0, len(mac_address), 2)])
        mac_address_list.append(mac_formated)
    return mac_address_list


def log_parser(logs):
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Common function to parse the logs
    :param logs:
    :return:
    """
    log_li = list(logs) if isinstance(logs, list) else [logs]
    pattern = r'(\S+)\s*(\d+)\s*(\d+):(\d+):(\d+).(\d+)\s(\S+)\s*(\S+)\s*(.*)'
    rv = []
    for each_log in log_li:
        temp = {}
        out = re.findall(pattern, each_log)
        temp['month'], temp['date'], temp['hours'], temp['minutes'], temp['seconds'], temp[
            'micro_second'], temp['hostname'], temp['severity'], temp['message'] = out[0]
        rv.append(temp)
    st.debug(rv)
    return rv


def get_current_datetime():
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to get current date time
    :return:
    """
    now = datetime.datetime.now()
    return now.strftime("%m%d%Y%H%M%S")


def write_to_json_file(content, file_path):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    Common function to write the json file
    :param content:
    :param file_path:
    :return:
    """
    json_dump = json.dumps(content)
    parsed = json.loads(json_dump)
    json_content = json.dumps(parsed, indent=4, sort_keys=True)
    src_fp = open(file_path, "w")
    src_fp.write(json_content)
    src_fp.close()
    return file_path


def convert_time_to_seconds(days=0, hours=0, minutes=0, seconds=0):
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Common function to converting time in seconds
    :param days:
    :param hours:
    :param minutes:
    :param seconds:
    :return:
    """
    seconds = int(seconds)
    if days:
        days = int(days) * 3600 * 24
    if hours:
        hours = int(hours) * 3600
    if minutes:
        minutes = int(minutes) * 60
    retval = days + hours + minutes + seconds
    return retval


def convert_time_to_milli_seconds(days=0, hours=0, minutes=0, seconds=0, milli_second=0):
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Common function to converting time in milli seconds
    :param days:
    :param hours:
    :param minutes:
    :param seconds:
    :param milli_second:
    :return:
    """
    seconds = int(seconds)
    milli_second = int(milli_second)
    if days:
        days = int(days) * 3600 * 24
    if hours:
        hours = int(hours) * 3600
    if minutes:
        minutes = int(minutes) * 60
    retval = ((days + hours + minutes + seconds)*1000 * 1000) + milli_second
    return retval


def ensure_service_params(dut, *argv):
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param argv: Service Name, follower by keys or list index.
    :return:

    How to use?:
    # Importing module:
     import utilities.utils as utils_obj
    # Below API call will check and get the tftp ip addresses from "sonic_services.yaml".
    # Also it first check weather "tftp" service is present in "sonic_services.yaml" or not ,
    # if present then checks for "ip" and return the ip addresses.
    # If any of "tftp" or "ip" no present in "sonic_services.yaml" file, then test case aborted and
    # moved to the "NES" state " saying "Test case Not Executed(s) - Required service parameters
    # is not defined " tftp->ip."
    tftp_ip = utils_obj.ensure_service_params(dut,"tftp","ip")
    tftp_path = utils_obj.ensure_service_params(dut,"tftp","path")

    tacacs_first_server = utils_obj.ensure_service_params(dut, "tacacs", "hosts",0,"ip")
    tacacs_first_username = utils_obj.ensure_service_params(dut, "tacacs", "hosts",0,"username")
    tacacs_first_password = utils_obj.ensure_service_params(dut, "tacacs", "hosts",0,"password")
    tacacs_second_server = utils_obj.ensure_service_params(dut, "tacacs", "hosts",1,"ip")
    tacacs_second_username = utils_obj.ensure_service_params(dut, "tacacs", "hosts",1,"username")
    tacacs_second_password = utils_obj.ensure_service_params(dut, "tacacs", "hosts",1,"password")

    """
    if not argv:
        st.error("Provide atleast one service to ensure")
        return None

    service_string = ' -> '.join([str(e) for e in argv])
    st.log("Ensure service parameter(s) - {}".format(service_string))
    output = st.get_service_info(dut, argv[0])
    if not output:
        st.error("'{}' is not specified in services/default.".format(argv[0]))
        st.report_env_fail("test_case_not_executed_s_service", service_string)

    for each in argv[1:]:
        try:
            output = output[each]
        except KeyError as e1:
            st.log(e1)
            st.error("Inside key '{}' : parameter {} is not specified in services/default.".format(argv[0], e1))
            st.report_env_fail("test_case_not_executed_s_service", service_string)
        except IndexError as e2:
            st.log(e2)
            st.error("Inside Key '{}' : list index '{}' is not specified in services/default.".format(argv[0], each))
            st.report_env_fail("test_case_not_executed_s_service", service_string)
        except Exception as e3:
            st.log(e3)
            st.error("Service or Parm '{}' not found.".format(each))
            st.report_env_fail("test_case_not_executed_s_service", service_string)
    st.log("Return : {}".format(output))
    return output


def banner_log(msg, width=80, delimiter="#", wrap=True):
    import textwrap
    msg = str(msg)
    if wrap:
        output = ["{0} {1} {0}".format(delimiter, each.center(width-4)) for each in textwrap.wrap(msg, width=width-4)]
    else:
        output = ["{0} {1:{2}} {0}".format(delimiter, each, (width-4)) for each in textwrap.wrap(msg, width=width-4)]
    msg_full = "\n" + "{}".format(delimiter)*width + "\n" + "{}".format('\n'.join(output)) + \
               '\n' + "{}".format(delimiter)*width + "\n"
    for each_line in msg_full.split("\n"):
        st.log(each_line)


def get_dut_name_from_no(dut_no):
    return 'D1'+str(dut_no).zfill(2)


def get_dut_ports_dict_from_topo(min_req_topo):
    """
    :param : None
    :return: a dict of all dut-ports

    Returned dict will map all port connections in globals()['vars'] with some additional details.
    key : dut
    val : list of intf_properties_tuple
       intf_properties_tuple : (
                                ifname,
                                destination_dut,
                                linkno,
                                speed)
    More interface specific details shall be added to the intf_tuple as and when required

    Example:
    For the below given topology in testbed.yaml

       topology:
           DUT1:
               interfaces:
                   Ethernet0: {EndDevice: DUT2, EndPort: Ethernet0, params: def_link}
                   Ethernet4: {EndDevice: DUT2, EndPort: Ethernet4, params: def_link}
                   Ethernet8: {EndDevice: DUT3, EndPort: Ethernet8, params: def_link}
                   Ethernet12: {EndDevice: DUT4, EndPort: Ethernet12, params: def_link}
           DUT2:
               interfaces:
                   Ethernet16: {EndDevice: DUT3, EndPort: Ethernet16, params: def_link}
                   Ethernet20: {EndDevice: DUT4, EndPort: Ethernet20, params: def_link}

    This api will return the following dictionary. This output was captured on vsonic.
    topology =    {'D101': [('Ethernet0', 'D102', '1', 'N/A'),
                                     ('Ethernet4', 'D102', '2', 'N/A'),
                                     ('Ethernet8', 'D103', '1', 'N/A'),
                                     ('Ethernet12', 'D104', '1', 'N/A')],
                            'D102': [('Ethernet0', 'D101', '1', 'N/A'),
                                     ('Ethernet4', 'D101', '2', 'N/A'),
                                     ('Ethernet16', 'D103', '1', 'N/A'),
                                     ('Ethernet20', 'D104', '1', 'N/A')],
                            'D103': [('Ethernet8', 'D101', '1', 'N/A'),
                                     ('Ethernet16', 'D102', '1', 'N/A')],
                            'D104': [('Ethernet12', 'D101', '1', 'N/A'),
                                     ('Ethernet20', 'D102', '1', 'N/A')]}

    """
    import apis.system.interface as intf_obj
    sys_vars = st.ensure_min_topology(*min_req_topo)
    topology = {}
    service_string = ' -> '.join("Build topology dictionary")
    for key in sys_vars.keys():
        port_info = re.match(r'D([\d+])([DT])([\d+])P([\d+])', key)
        if port_info:
            ifname = ''
            dest_dut = ''
            link_no = ''
            intf_speed = ''
            (src_dut_no, dst_dut_or_tg, dest_dut_no, link_no) = port_info.groups()
            src_dut = 'D' + str(src_dut_no)
            src_dut = sys_vars[src_dut]
            dest_dut = dst_dut_or_tg+str(dest_dut_no)
            if dst_dut_or_tg == 'D':
                dest_dut = sys_vars[dest_dut]

            ifname = sys_vars[key]
            if (not ifname) or (not ifname.startswith("Ethernet")):
                st.error("'{}' is not a Valid Interface name.".format(ifname))
                st.report_env_fail("test_case_not_executed_s_service", service_string)

            intf_status = intf_obj.interface_status_show(src_dut, ifname)
            if not intf_status:
                st.error("'{}' Interface Speed not Available.".format(ifname))
                st.report_env_fail("test_case_not_executed_s_service", service_string)
            intf_speed = intf_status[0]['speed']

            topology.setdefault(src_dut, []).append((ifname, dest_dut, link_no, intf_speed))
    return topology


def remove_duplicates_from_list(params_list):
    """
    Common function to remove duplicates from a list
    Author: Chaitanya-vella.kumar@broadcom.com
    :param params_list:
    :return:
    """
    if params_list:
        return list(dict.fromkeys(params_list))
    return list()


def list_diff(list1, list2, identical=False):
    """
    API to get the differece in 2 lists
    :param list1:
    :param list2:
    :param identical:
    :return:
    """
    result = list()
    for value in list1:
        if identical:
            if value in list2:
                result.append(value)
        else:
            if value not in list2:
                result.append(value)
    return result


def get_random_vlans_in_sequence(count=1, start=2, end=3000):
    vlan_list = []
    while True:
        vlan_list = random.sample([range(start, end)[x:x + count] for x in range(0, len(range(start, end)), count)],
                                  k=1)[0]
        if len(vlan_list) == count:
            break
    return vlan_list


def check_empty_values_in_dict(data):
    """
    Common function to check the empty values in dictionary
    :param data:
    :return:
    """
    if isinstance(data, dict):
        count = 0
        for key, value in data.items():
            if value == "":
                st.debug("Getting empty value for key={} and value={}".format(key, value))
                count += 1
        if count != 0:
            return False
        else:
            return True
    return None


def remove_duplicate_dicts_from_list(list_data):
    result = list()
    if isinstance(list_data, list):
        for i in range(len(list_data)):
            if list_data[i] not in list_data[i+1:]:
                result.append(list_data[i])
    return result


def get_interface_number_from_name(interface_name):

    """
    Common function to get the interface number from name using for KLISH CLI
    Author: Chaitanya-vella.kumar@broadcom.com
    :param interface_name:
    :return:
    """
    if interface_name and not re.search(r':|\.',interface_name):
        data = re.search(r'([A-Za-z\-]+)\s*([0-9\/]+)', interface_name)
        if data:
            if 'PortChannel' in interface_name:
                return {'type': data.group(1), 'number': data.group(2).lstrip('0')}
            return {'type': data.group(1), 'number': data.group(2)}
    return interface_name


def get_dict_from_redis_cli(data):
    """
    This will convert show_redis_cli_key_search.tmpl output to the dict(key value pair)
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param data:
    :return:

    EX:
    data = [{'id': '1', 'name': 'sample'}, {'id': '2', 'name': '100'}, {'id': '3', 'name': 'ipaddress-type'},
            {'id': '4', 'name': 'ipv4'}]
    return output: {'ipaddress-type': 'ipv4', 'sample': '100'}
    """
    id_list = dicts_list_values(data, 'id')
    chunks = [id_list[x:x + 2] for x in range(0, len(id_list), 2)]
    output = {filter_and_select(data, ['name'], {'id': each[0]})[0]['name']:
                  filter_and_select(data, ['name'], {'id': each[1]})[0]['name'] for each in chunks}
    return output


def list_filter_and_select(data, filter_list):
    """
      This will search all elements in data list w.r.t to filter list and return matched elements of data.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param data: list
    :param filter_list: list
    :return:
    """
    result = []
    filter_li = make_list(filter_list)
    st.debug("Filter List : {}".format(filter_li))
    for each in make_list(data):
        if len([x for x in filter_li if re.search(x, each)]) == len(filter_li):
            st.debug("Match Found : {}".format(each))
            result.append(each)
    return result


def util_ip_addr_to_hexa_conv(ipaddr):
    """
    This will convert IPv4/v6  address to hex format
    :param ipaddr:
    :return:
    """
    return hexlify(socket.inet_aton(ipaddr)).upper()

def util_ipv6_addr_to_hexa_conv(ip6addr):
    """
    This will convert IPv6  address to hex format
    :param ipaddr:
    :return:
    """
    return hexlify(socket.inet_pton(socket.AF_INET6, ip6addr)).upper()


def util_int_to_hexa_conv(int_data, z_fill=4):
    """
    This will convert data into hex format and append zero's
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param int_data:
    :param z_fill:
    :return:
    """
    return (hex(int(int_data)))[2:].zfill(z_fill).upper()


def ensure_cli_type(cli_type, expected=list()):
    if cli_type not in make_list(expected):
        st.log("UNSUPPORTED CLI TYPE {} -- EXPECTING {}".format(cli_type, expected))
        return False
    else:
        return True


def hex2int(value, w=0):
    """
    This will convert data into hex to int
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param value:
    :param w:
    :return:
    """
    return int("0x{}".format(value), w)

def int2hex(data):
    try:
        return hex(int(data))
    except Exception:
        return hex(int(data.replace('L', '').upper()[2:].zfill(8), 16))

def fail_on_error(output):
    """
    Common function to fail the test case when there is an error in command execution
    :return:
    """
    if "%Error:" in output or "% Error:" in output:
        st.report_fail("test_case_failed")


def convert_ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary


def get_network_from_address(address, net_size):
    ip_bin = convert_ip_to_binary(address)
    network = ip_bin[0:32 - (32 - net_size)]
    return network


def verify_ip_in_network(ip_address, prefix):
    st.debug("IP ADDRESS : {}".format(ip_address))
    st.debug("NETWORK : {}".format(prefix))
    [prefix_address, net_size] = prefix.split("/")
    net_size = int(net_size)
    prefix_network = get_network_from_address(prefix_address, net_size)
    ip_network = get_network_from_address(ip_address, net_size)
    return ip_network == prefix_network


def get_word_count(dut, command, **kwargs):
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param command:
    :param kwargs:
    :return:
    """
    output = st.config(dut, command, **kwargs)
    out = re.findall(r"^(\d+)", output)
    return int(out[0]) if out else 0


def verify_ip4_ip6_in_subnetwork(ip_address, subnetwork):
    (ip_integer, version1) = ip4_ip6_to_integer(ip_address)
    (ip_lower, ip_upper, version2) = subnetwork_to_ip4_ip6_range(subnetwork)

    if version1 != version2:
        raise ValueError("incompatible IP versions")
    return (ip_lower <= ip_integer <= ip_upper)


def ip4_ip6_to_integer(ip_address):
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            ip_hex = socket.inet_pton(version, ip_address)
            ip_integer = int(hexlify(ip_hex), 16)

            return (ip_integer, 4 if version == socket.AF_INET else 6)
        except Exception:
            pass
    raise ValueError("invalid IP address")


def subnetwork_to_ip4_ip6_range(subnetwork):
    try:
        fragments = subnetwork.split('/')
        network_prefix = fragments[0]
        netmask_len = int(fragments[1])
        for version in (socket.AF_INET, socket.AF_INET6):

            ip_len = 32 if version == socket.AF_INET else 128
            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) - suffix_mask
                ip_hex = socket.inet_pton(version, network_prefix)
                ip_lower = int(hexlify(ip_hex), 16) & netmask
                ip_upper = ip_lower + suffix_mask

                return (ip_lower,
                        ip_upper,
                        4 if version == socket.AF_INET else 6)
            except Exception:
                pass
    except Exception:
        pass
    raise ValueError("invalid subnetwork")


def bitwise_OR_to_char(char, val):
    if len(char) != 1:
        st.error('Error, char({}) len > 1.'.format(char))
        return char

    return str(int(char) | int(val))

def retry_api(func, *args,**kwargs):
    retry_count = kwargs.pop("retry_count", 10)
    delay = kwargs.pop("delay", 3)
    for i in range(retry_count):
        st.log("Attempt {} of {}".format((i+1),retry_count))
        if func(*args,**kwargs):
            #print('API_Call: {} Successful'.format(func))
            return True
        if retry_count != (i+1):
            st.log("waiting for {} seconds before retyring again".format(delay))
            st.wait(delay)
    return False

def retry_parallel(func,dict_list=[],dut_list=[],api_result=True,retry_count=3,delay=2):
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        result = pll.exec_parallel(True,dut_list,func,dict_list)
        if api_result:
            if False not in result[0]:
                return api_result
        else:
            if True not in result[0]:
                return api_result
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retrying again"%delay)
            st.wait(delay)
    return  False if api_result else True

def hex_conversion(data):
    try:
        return hex(int(data))
    except Exception:
        return hex(int(data.replace('L', '').upper()[2:].zfill(8), 16))

def get_portchannel_name_for_rest(interface_name):
    portchanne_name = interface_name
    if "PortChannel" in portchanne_name:
        intf_name = interface_name.split("PortChannel")
        portchanne_name = "PortChannel{}".format(int(intf_name[1]))
    return portchanne_name

def is_valid_ipv4_address(address):
    """
    Validate ipv4 address.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param address:
    :return:
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True

def is_valid_ipv6_address(address):
    """
    Validate ipv6 address.
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param address:
    :return:
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

def is_valid_ip_address(address, family, subnet=None):
    """
    Validate ip address.
    Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

    :param address:
    :param family
    :param subnet
    :return:
    """

    if not address or not family:
        st.error("Parameter Family or address is Null")
        return False

    if family == "ipv4":
        if not is_valid_ipv4_address(address):
            st.error("Invalid IPv4 address {} ".format(address))
            return False
        if subnet:
            subnet = int(subnet)
            if subnet < 1 or subnet > 32:
                st.error("Invalid IPv4 subnet {}".format(subnet))
                return False
    elif family == "ipv6":
        if not is_valid_ipv6_address(address):
            st.error("Invalid IPv6 address {} ".format(address))
            return False
        if subnet:
            subnet = int(subnet)
            if subnet < 1 or subnet > 128:
                st.error("Invalid IPv6 subnet {}".format(subnet))
                return False
    else:
        st.error("Invalid address family {} ".format(family))
        return False

    return True

def convert_microsecs_to_time(microseconds):
    from datetime import timedelta
    time = str(timedelta(microseconds=int(microseconds))).split(".")
    if time:
        return time[0]
    return "0:00:00"