# This file contains the list of command utility functions
# Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com) / Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import re
import os
import sys
import json
import socket
import random
import string
import struct
import binascii
import datetime
import logging

from spytest import st
from spytest.datamap import DataMap

import utilities.parallel as pll
from utilities.common import filter_and_select, dicts_list_values
from utilities.common import make_list
from utilities.common import str_encode,str_decode

msgs = DataMap("messages").get()
test_func_name = None


def get_supported_ui_type_list(*more):
    retval = ['gnmi', 'gnmi-update', 'gnmi-replace', 'rest']
    for add in more:
        retval.extend(make_list(add))
    return retval

def force_cli(cli_type, default="click"):
    if cli_type not in ["klish"]:
        return cli_type
    return "klish" if st.is_feature_supported("klish") else "click"

def force_klish_ui(*args, **kwargs):
    cli_type = kwargs.get("cli_type", "klish")
    if cli_type not in get_supported_ui_type_list(*args):
        return cli_type
    return force_cli(cli_type, cli_type)

# use use_cli if the cli_type is one of args
def override_ui(*args, **kwargs):
  cli_type = kwargs.get("cli_type", "klish")
  use_cli = kwargs.get("use_cli", "klish")
  default = kwargs.get("default", "click")
  use_cli = use_cli if cli_type in args else cli_type
  if use_cli != "klish": return use_cli
  return use_cli if st.is_feature_supported(use_cli) else default

# use use_cli if the cli_type is one of args or supported uis
def override_supported_ui(*args, **kwargs):
  new_args = get_supported_ui_type_list(*args)
  return override_ui(*new_args, **kwargs)

def cli_type_for_get_mode_filtering():
    """
    list for cli types support get mode filtering
    :return:
    """
    return ["gnmi"]


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
    exists = os.path.isfile(file_path)
    return True if exists else False


def generate_mac_sequence(base_mac="00:00:00:00:00:00", start=0, end=100, step=1):
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

def generate_ip_sequence(type, startip, count=1):
    ipaddr_list = []
    for i in range(count):
        if type == "ipv4":
            ipaddr_list.append(socket.inet_ntoa(struct.pack('!I', struct.unpack('!I', socket.inet_aton(startip))[0] + (i * 256))))
        else:
            tmp = int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, startip)), 16) + (i*256)
            tmp = hex(tmp)[2:].replace("L", "")
            ipaddr_list.append(socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(tmp)))
    return ipaddr_list

def log_parser(logs):
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Common function to parse the logs
    :param logs:
    :return:
    """
    log_li = list(logs) if isinstance(logs, list) else [logs]
    pattern = r'(\S+)\s*(\d+)\s*(\d+):(\d+):(\d+).(\d+)[+](\d+):(\d+)\s(\S+)\s*(\S+)\s*(\S+)\s*(.*)'
    pattern2 = r'(\S+)\s*(\d+)\s*(\d+):(\d+):(\d+).(\d+)\s(\S+)\s*(\S+)\s*(.*)'  # For Community build
    rv = []
    for each_log in log_li:
        temp = {}
        out = re.findall(pattern, each_log)
        out2 = re.findall(pattern2, each_log)
        if out:
            temp['month'], temp['date'], temp['hours'], temp['minutes'], temp['seconds'], temp['micro_second'],\
            temp['utc_hours'], temp['utc_minutes'], temp['year'], temp['hostname'], temp['severity'], \
            temp['message'] = out[0]
            rv.append(temp)
        elif out2:
            temp['month'], temp['date'], temp['hours'], temp['minutes'], temp['seconds'], temp['micro_second'], \
            temp['hostname'], temp['severity'], temp['message'] = out2[0]
            temp['utc_hours'], temp['utc_minutes'], temp['year'] = '', '', ''
            rv.append(temp)
        else:
            st.error("Pattern is not match for log - {}".format(each_log))
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

    env_name = "SPYTEST_OVERRIDE_SERVICE_{}".format(str(argv[0]).upper())
    for each in argv[1:]:
        env_name = "{}_{}".format(env_name, str(each).upper())
    output = st.getenv(env_name)
    if output:
        st.log("Ensure service parameter(s) - {} = {} (from {})".format(service_string, output, env_name))
        return output

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
    st.log("Ensure service parameter(s) - {} = {}".format(service_string, output))
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
        vlan_list = random.sample([range(start, end)[x:x + count] for x in range(0, len(range(start, end)), count)], k=1)[0]
        if len(vlan_list) == count:
            break
    return vlan_list if sys.version_info[0] < 3 else list(vlan_list)


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
    if interface_name and not is_valid_ipv4_address(interface_name) and not is_valid_ipv6_address(interface_name):
        data = re.search(r'([A-Za-z\-]+)\s*([0-9\/\.]+(-?\d+)?)', interface_name)
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
    return str(str_decode(str_encode(binascii.hexlify(socket.inet_aton(ipaddr))))).upper()

def util_ipv6_addr_to_hexa_conv(ip6addr):
    """
    This will convert IPv6  address to hex format
    :param ipaddr:
    :return:
    """
    return str(str_decode(str_encode(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ip6addr))))).upper()


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
            ip_integer = int(binascii.hexlify(ip_hex), 16)

            return (ip_integer, 4 if version == socket.AF_INET else 6)
        except Exception:
            pass
    raise ValueError("invalid IP address '{}'".format(ip_address))


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
                ip_lower = int(binascii.hexlify(ip_hex), 16) & netmask
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

def retry_api_base(retry_count, delay, api_result, func, *args,**kwargs):
    for i in range(retry_count):
        st.debug("Attempt {} of {}".format((i+1),retry_count))
        if api_result:
            if func(*args, **kwargs):
                return api_result
        else:
            if not func(*args, **kwargs):
                return api_result
        if retry_count != (i+1):
            st.wait(delay, "before retyring again")
    return  False if api_result else True

def retry_api(func, *args,**kwargs):
    retry_count = kwargs.pop("retry_count", 10)
    delay = kwargs.pop("delay", 3)
    api_result = kwargs.pop("api_result", True)
    return retry_api_base(retry_count, delay, api_result, func, *args,**kwargs)

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
    if not address:
        st.error("address is Null")
        return False
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

    if not address:
        st.error("Parameter address is Null")
        return False

    if not family:
        st.error("Parameter Family is Null")
        return False

    if family == "ipv4":
        if not is_valid_ipv4_address(address):
            st.warn("Invalid IPv4 address '{}' ".format(address))
            return False
        if subnet:
            subnet = int(subnet)
            if subnet < 1 or subnet > 32:
                st.warn("Invalid IPv4 subnet '{}'".format(subnet))
                return False
    elif family == "ipv6":
        if not is_valid_ipv6_address(address):
            st.warn("Invalid IPv6 address '{}' ".format(address))
            return False
        if subnet:
            subnet = int(subnet)
            if subnet < 1 or subnet > 128:
                st.warn("Invalid IPv6 subnet '{}'".format(subnet))
                return False
    else:
        st.warn("Invalid address family '{}' ".format(family))
        return False

    return True

def convert_microsecs_to_time(microseconds):
    from datetime import timedelta
    time = str(timedelta(microseconds=int(microseconds))).split(".")
    if time:
        return time[0]
    return "0:00:00"


def read_json(file_path):
    try:
        fp = open(file_path, 'r')
        obj = fp.read().replace("\x00", '')
        fp.close()
        st.debug(obj)
        rv = json.loads(obj)
        st.log(rv)
    except Exception as e:
        st.error(e)
        rv = obj
    return rv


def has_value(obj, val):
    if isinstance(obj, dict):
        values = obj.values()
    elif isinstance(obj, list):
        values = obj
    if val in values:
        st.log("Value present in Object")
        return True
    for v in values:
        if isinstance(v, (dict, list)) and has_value(v, val):
            return True
    st.error("Value not present in Object")
    return False


def run_os_cmd(cmd):
    for each_cmd in make_list(cmd):
        st.log("Running cmd : {}".format(each_cmd))
        try:
            st.log(os.popen(each_cmd).read())
        except Exception as e:
            st.error(e)


def erase_file_content(file_name):
    st.log("Erasing content of : {}".format(file_name))
    try:
        fp = open(file_name, 'r+')
        fp.truncate(0)
        fp.close()
    except Exception as e:
        st.error(e)



def get_intf_short_name(interface_name):

    """
    Common function to get the shorter interface notation for Subinterface
    Author: Sooriya.Gajendrababu@broadcom.com
    :param interface_name:
    :return:
    """
    if interface_name and not is_valid_ipv4_address(interface_name) and not is_valid_ipv6_address(interface_name):
        if '.' in interface_name:
            interface_name = interface_name.replace('Ethernet','Eth').replace('PortChannel','Po')
    return interface_name


def report_tc_fail(tc, msg, *args):
    """
    Common function for test case Fail
    Author: jagadish.chatrasi@broadcom.com
    :param tc:
    :param msg:
    :return:
    """

    import inspect
    global test_func_name
    if msg in msgs:
        message = msgs[msg].format(*args)
    else:
        message = msg

    calling_func_name = None

    for each_tupple in inspect.stack():
        for each_entry in each_tupple:
            if re.match(r'test_', str(each_entry).strip()) and '.py' not in str(each_entry):
                calling_func_name = each_entry

    try:
        #when this func is called for 2nd time onwards - from test_func_1
        if test_func_name == calling_func_name:
            collect_tech_support = False
        else:
            #when this func is called for first time - from test_func_2
            test_func_name = calling_func_name
            collect_tech_support = True
    except NameError:
        #when this func is called for first time - from test_func_1
        test_func_name = calling_func_name
        collect_tech_support = True

    st.warn('Current Test Func: {} Previous Test Func: {}'.format(calling_func_name, test_func_name))
    st.warn("test_step_failed, tc_id: {}, fail_reason: {}".format(tc, message))
    if collect_tech_support:
        st.banner('Collecting tech support on all DUTs')
        st.generate_tech_support(dut=None, name=tc)

    if msg in msgs:
        return st.report_tc_fail(tc, msg, *args)

    return st.report_tc_fail(tc, "msg", msg, *args)


def convert_intf_range_to_list(intf, range_format=False):
    """
    convert_intf_range_to_list(intf=['Ethernet0'], range_format=False)
    INPUT :  ['Ethernet0'] and range_format : False
    OUTPUT : ['Ethernet0']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet0'], range_format=True)
    INPUT :  ['Ethernet0'] and range_format : True
    OUTPUT : ['Ethernet0']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet6-10'], range_format=False)
    INPUT :  ['Ethernet6-10'] and range_format : False
    OUTPUT : ['Ethernet6', 'Ethernet7', 'Ethernet8', 'Ethernet9', 'Ethernet10']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet6-10'], range_format=True)
    INPUT :  ['Ethernet6-10'] and range_format : True
    OUTPUT : ['Ethernet6-10']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet6', 'Ethernet7-Ethernet10', 'Ethernet11'], range_format=False)
    INPUT :  ['Ethernet6', 'Ethernet7-Ethernet10', 'Ethernet11'] and range_format : False
    OUTPUT : ['Ethernet7', 'Ethernet8', 'Ethernet9', 'Ethernet10', 'Ethernet11']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet6', 'Ethernet7-Ethernet10', 'Ethernet11'], range_format=True)
    INPUT :  ['Ethernet6', 'Ethernet7-Ethernet10', 'Ethernet11'] and range_format : True
    OUTPUT : ['Ethernet6,7-10,11']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet6', 'Ethernet7-10', 'Ethernet11'], range_format=False)
    INPUT :  ['Ethernet6', 'Ethernet7-10', 'Ethernet11'] and range_format : False
    OUTPUT : ['Ethernet7', 'Ethernet8', 'Ethernet9', 'Ethernet10', 'Ethernet11']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet6', 'Ethernet7-10', 'Ethernet11'], range_format=True)
    INPUT :  ['Ethernet6', 'Ethernet7-10', 'Ethernet11'] and range_format : True
    OUTPUT : ['Ethernet6,7-10,11']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet6-10,25,30-31'], range_format=False)
    INPUT :  ['Ethernet6-10,25,30-31'] and range_format : False
    OUTPUT : ['Ethernet6', 'Ethernet7', 'Ethernet8', 'Ethernet9', 'Ethernet10', 'Ethernet30', 'Ethernet31', 'Ethernet25']
    ====================================
    convert_intf_range_to_list(intf=['Ethernet6-10,25,30-31'], range_format=True)
    INPUT :  ['Ethernet6-10,25,30-31'] and range_format : True
    OUTPUT : ['Ethernet6-10,25,30-31']
    ====================================
    INPUT :  ['Eth1/2'] and range_format : False
    OUTPUT : ['Eth1/2']
    ====================================
    INPUT :  ['Eth1/2'] and range_format : True
    OUTPUT : ['Eth1/2']
    ====================================
    INPUT :  ['Eth1/6-10'] and range_format : False
    OUTPUT : ['Eth1/6', 'Eth1/7', 'Eth1/8', 'Eth1/9', 'Eth1/10']
    ====================================
    INPUT :  ['Eth1/6-10'] and range_format : True
    OUTPUT : ['Eth1/6-10']
    ====================================
    INPUT :  ['Ethernet1/6', 'Ethernet1/7-Ethernet1/10', 'Ethernet1/11'] and range_format : False
    OUTPUT : ['Ethernet1/6', 'Ethernet1/7', 'Ethernet1/8', 'Ethernet1/9', 'Ethernet1/10', 'Ethernet1/11']
    ====================================
    INPUT :  ['Ethernet1/6', 'Ethernet1/7-Ethernet1/10', 'Ethernet1/11'] and range_format : True
    OUTPUT : ['Ethernet1/6,1/7-1/10,1/11']
    ====================================
    INPUT :  ['Ethernet1/6', 'Ethernet1/7-1/10', 'Ethernet1/11'] and range_format : False
    OUTPUT : ['Ethernet1/6', 'Ethernet1/7', 'Ethernet1/8', 'Ethernet1/9', 'Ethernet1/10', 'Ethernet1/11']
    ====================================
    INPUT :  ['Ethernet1/6', 'Ethernet1/7-1/10', 'Ethernet1/11'] and range_format : True
    OUTPUT : ['Ethernet1/6,1/7-1/10,1/11']
    ====================================
    INPUT :  ['Ethernet1/6-1/10,1/25,1/30-1/31'] and range_format : False
    OUTPUT : ['Ethernet1/6', 'Ethernet1/7', 'Ethernet1/8', 'Ethernet1/9', 'Ethernet1/10', 'Ethernet1/25', 'Ethernet1/30', 'Ethernet1/31']
    ====================================
    INPUT :  ['Ethernet1/6-1/10,1/25,1/30-1/31'] and range_format : True
    OUTPUT : ['Ethernet1/6-1/10,1/25,1/30-1/31']
    ====================================
    INPUT :  ['Ethernet1/2/6-1/2/10,1/2/25,1/2/30-1/2/31'] and range_format : False
    OUTPUT : ['Ethernet1/2/6', 'Ethernet1/2/7', 'Ethernet1/2/8', 'Ethernet1/2/9', 'Ethernet1/2/10', 'Ethernet1/2/25', 'Ethernet1/2/30', 'Ethernet1/2/31']
    ====================================
    INPUT :  ['Ethernet1/2/6-1/2/10,1/2/25,1/2/30-1/2/31'] and range_format : True
    OUTPUT : ['Ethernet1/2/6-1/2/10,1/2/25,1/2/30-1/2/31']
    ====================================
    INPUT :  ['Eth1/2/1'] and range_format : False
    OUTPUT : ['Eth1/2/1']
    ====================================
    INPUT :  ['Eth1/2/1'] and range_format : True
    OUTPUT : ['Eth1/2/1']
    ====================================
    :param intf:
    :param range_format:
    :return:
    """
    if not isinstance(intf, list): intf=make_list(intf)
    result = []
    intf_range = ','.join([str(elem) for elem in intf])
    t1_intf_range = re.sub(r'([A-Za-z]+)', '', intf_range)
    intf_name = re.search(r'([A-Za-z]+)', intf_range).group(1)
    if range_format:
        result.append(intf_name + t1_intf_range)
        return result
    for ea in t1_intf_range.split(','):
        if '-' in str(ea):
            intf_slot_port = ''
            intf_range = ea.split('-')
            intf_range_start = intf_range[0]
            intf_range_end = intf_range[1]
            if '/' in intf_range[0]:
                intf_range_start = str(intf_range[0]).split('/')[-1]
                intf_slot_port = '/'.join(str(intf_range[0]).split('/')[:-1]) + '/'
            if '/' in intf_range[1]:
                intf_range_end = str(intf_range[1]).split('/')[-1]
                intf_slot_port = '/'.join(str(intf_range[1]).split('/')[:-1]) + '/'
            intf_range_updated = sorted([intf_name + intf_slot_port + str(j) for j in
                                         range(int(intf_range_start), int(intf_range_end) + 1)])
            result += intf_range_updated
        else:
            result.append(intf_name + ea)
    return result

def segregate_intf_list_type(intf, range_format=False, log=None):
    """
    segregare_intf_list_type(intf=['Ethernet2','Ethernet6-9','Portchannel12-20','Vlan40-50','Loopback10','Loopback20'], range_format=True)
    returns the dictionary {range_intf_phy=[Ethernet2',Ethernet6-9'],range_intf_pc = ['Portchannel12-20'], range_intf_vlan=['Vlan40-50'],
    range_intf_lb=['Loopback10','Loopback20']}
    :param intf:
    :return:
    """
    log = log or st.log
    log('API_NAME: segregate_intf_list_type, API_ARGS: {}'.format(locals()))
    intf_hash_list = {'range_intf_mgmt' : [],'range_intf_phy' : [],'range_intf_vlan': [],'range_intf_pc' : [],
                      'intf_list_all':[], 'range_intf_lb':[], 'range_intf_sub_phy':[], 'range_intf_sub_pc':[]}
    intf_list_phy = list()
    intf_list_vlan = list()
    intf_list_pc = list()
    intf_list_lb = list()
    intf_list_mgmt = list()
    intf_list_sub_phy = list()
    intf_list_sub_pc = list()

    intf = make_list(intf)
    for each in intf:
        if 'eth' in each.lower() and '.' in each.lower():
            intf_hash_list['range_intf_sub_phy'].append(each)
        elif 'portchannel' in each.lower() and '.' in each.lower():
            intf_hash_list['range_intf_sub_pc'].append(each)
        elif 'portchannel' in each.lower():
            intf_hash_list['range_intf_pc'].append(each)
        elif 'vlan' in each.lower():
            intf_hash_list['range_intf_vlan'].append(each)
        elif 'eth' in each.lower():
            intf_hash_list['range_intf_phy'].append(each)
        elif 'loopback' in each.lower():
            intf_hash_list['range_intf_lb'].append(each)
        elif 'management' in each.lower():
            intf_hash_list['range_intf_mgmt'].append(each)
        else:
            log('Unsupported interface name - {}'.format(each), lvl=logging.ERROR)
            return intf_hash_list

    if intf_hash_list['range_intf_lb']:
        intf_list_lb = convert_intf_range_to_list(intf=intf_hash_list['range_intf_lb'], range_format=False)
    if intf_hash_list['range_intf_phy']:
        intf_list_phy = convert_intf_range_to_list(intf=intf_hash_list['range_intf_phy'], range_format=range_format)
    if intf_hash_list['range_intf_vlan']:
        intf_list_vlan = convert_intf_range_to_list(intf=intf_hash_list['range_intf_vlan'], range_format=range_format)
    if intf_hash_list['range_intf_pc']:
        intf_list_pc = convert_intf_range_to_list(intf=intf_hash_list['range_intf_pc'], range_format=range_format)
    if intf_hash_list['range_intf_mgmt']:
        intf_list_mgmt = convert_intf_range_to_list(intf=intf_hash_list['range_intf_mgmt'], range_format=False)
    if intf_hash_list['range_intf_sub_phy']:
        intf_list_sub_phy = convert_intf_range_to_list(intf=intf_hash_list['range_intf_sub_phy'], range_format=False)
    if intf_hash_list['range_intf_sub_pc']:
        intf_list_sub_pc = convert_intf_range_to_list(intf=intf_hash_list['range_intf_sub_pc'], range_format=False)

    intf_list_all = intf_list_phy + intf_list_pc + intf_list_vlan + intf_list_lb + intf_list_mgmt + intf_list_sub_phy + intf_list_sub_pc

    intf_hash_list['intf_list_all'] = intf_list_all
    intf_hash_list['range_intf_phy'] = intf_list_phy
    intf_hash_list['range_intf_pc'] = intf_list_pc
    intf_hash_list['range_intf_vlan'] = intf_list_vlan
    intf_hash_list['range_intf_lb'] = intf_list_lb
    intf_hash_list['range_intf_mgmt'] = intf_list_mgmt
    intf_hash_list['range_intf_sub_phy'] = intf_list_sub_phy
    intf_hash_list['range_intf_sub_pc'] = intf_list_sub_pc

    return intf_hash_list

def is_a_single_intf(intf):
    """
    is_a_single_intf('Ethernet1-4') returns False
    is_a_single_intf('Ethernet4') returns True

    :param intf:
    :return:
    """
    if '-' in intf or ',' in intf:
        return False
    else:
        return True

def rif_support_check(dut, platform, sub_intf=False):
    common_constants = st.get_datastore(dut, "constants", "default")
    if sub_intf:
        return True if platform in common_constants['TD3_PLATFORMS'] else False
    plat = []
    for key, value in common_constants.items():
        if key in ['TD3_PLATFORMS', 'TH_PLATFORMS', 'TD2_PLATFORMS', 'TH2_PLATFORMS']:
            plat.append(value)
            final_list = [item for sublist in plat for item in sublist]
    if platform in final_list:
        st.log("RIF is supported on {}".format(platform))
        return True
    else:
        return False

def validate_data_path(dut=None):
    if st.is_sonicvs(dut):
        return False
    return True

def validate_link_events(dut=None):
    if not st.is_sonicvs(dut):
        return True
    linkmon = st.getenv("SPYTEST_SONICVS_LINKMON", "0")
    return bool(linkmon != "0")

def get_random_string(N=4):
    """
    Function to generate random string in the given length
    :param N:
    :return:
    """
    return ''.join(random.sample(string.ascii_uppercase +
                                 string.digits, k=N))

def get_traffic_loss_duration(tx_count,rx_count,tx_rate):
    '''

    :param dut:
    :param tx_count: source tg port tx_pkt count
    :param rx_count: destination tg port rx_pkt count
    :param tx_rate: Tgen PPS rate
    :return:
    '''
    traffic_loss = abs(int(tx_count) - int(rx_count))
    traffic_loss_duration = traffic_loss/int(tx_rate)
    st.log("traffic loss is {} PPS".format(traffic_loss))
    traffic_loss_msec = convert_time_to_milli_seconds(0,0,0,traffic_loss_duration,0)
    st.log("traffic loss duration is {} msec".format(traffic_loss_msec))
    return traffic_loss_msec


def get_random_mac_address(no_of_macs):
    macs = set()
    while True:
        if len(macs) == no_of_macs:
            return list(macs)
        macs.add("02:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))


def compare_lists(list1, list2, equals=True):
    """
    Author: Chaitanya Vella (chaitanya-kumar.vella@broadcom.com)
    Common function to compare 2 lists
    :param list1:
    :param list2:
    :param equals:
    :return: True/False
    """
    import functools
    if functools.reduce(lambda x, y: x and y, map(lambda p, q: p == q, list1, list2), True):
        return True if equals else False
    else:
        return False if equals else True

def compare_lists_by_count(list_to_be_compared, parent_list, length):
    """
    Author: Chaitanya Vella (chaitanya-kumar.vella@broadcom.com)
    :param list1:
    :param list2:
    :param length:
    :return:
    """
    cnt = 0
    for l in list_to_be_compared:
        for x in parent_list:
            if l.upper() == x.upper():
                cnt += 1
    if cnt != length:
        return False
    return True

def copy_files_to_dut(dut, src_file_list, dst_folder, cft=0):
    for src_file in make_list(src_file_list):
        dst_file = os.path.join(dst_folder, os.path.basename(src_file))
        st.upload_file_to_dut(dut, src_file, dst_file, cft)

def convert_to_timestamp(timedate):
    """
    Function to convert unix time to timestamp
    :param timedate:
    :return:
    """
    month_dict = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10,
                  "Nov": 11, "Dec": 12}
    output = re.split(':| ', timedate)
    try:
        output[2] = month_dict[output[2]]
        if output[7] == "PM" and int(output[4]) < 12:
            output[4] = int(output[4]) + 12
        dt = datetime.datetime(int(output[3]),int(output[2]),int(output[1]),int(output[4]),int(output[5]),int(output[6]))
        return int((dt - datetime.datetime(1970, 1, 1)).total_seconds())
    except Exception as e:
        st.error(e)
        return False


def convert_intf_name_to_component(dut, intf_list, **kwargs):

    '''
    alias-Intf              std/alias                               std-exd
    Eth1/1          kernel/database/Appl:  Ethernet0        kernel:             E1_1
                    all-other-places:      Eth1/1           all-other-places:   Eth1/1

    Eth1/49/1       kernel/database/Appl:  Ethernet48       kernel:             E1_49_1
                    all-other-places:      Eth1/49/1        all-other-places:   Eth1/49/1

    PortChannel7    kernel/database/Appl:  PortChannel7     kernel:             PortChannel7
                    all-other-places:      PortChannel7     all-other-places:   PortChannel7

    Eth1/1.10       kernel/database/Appl:  Eth0.10          kernel:             E1_1.10
                    all-other-places:      Eth1/1.10        all-other-places:   Eth1/1.10

    PortChannel7.7  kernel/database/Appl:  Po7.7            kernel:             Po7.7
                    all-other-places:      PortChannel7.7   all-other-places:   PortChannel7.7
    '''

    '''
    convert_intf_name_to_component(dut, intf_list=['Eth1/1', 'Eth1/1.10', 'PortChannel7', 'PortChannel7.7'], ifname_type='alias')
    2022-08-10 16:36:35,157 T0000: INFO  Interface-naming: alias
    ['Ethernet0', 'Eth0.10', 'PortChannel7', 'Po7.7']

    convert_intf_name_to_component(dut, intf_list=['Ethernet0', 'Ethernet0.10', 'PortChannel7', 'PortChannel7.7'])
    2022-08-10 16:37:39,517 T0000: INFO  Interface-naming: native
    ['Ethernet0', 'Eth0.10', 'PortChannel7', 'Po7.7']

    convert_intf_name_to_component(dut, intf_list=['Eth1/1', 'Eth1/1.10', 'PortChannel7', 'PortChannel7.7'], ifname_type='std-exd')
    2022-08-10 16:38:00,749 T0000: INFO  Interface-naming: std-exd
    ['E1_1', 'E1_1.10', 'PortChannel7', 'Po7.7']

    convert_intf_name_to_component(dut, intf_list='Eth1/1.10', ifname_type='alias')
    2022-08-10 16:34:48,957 T0000: INFO  Interface-naming: alias
    'Eth0.10'

    convert_intf_name_to_component(dut, intf_list='Eth1/1.10', ifname_type='std-exd')
    2022-08-10 16:41:52,292 T0000: INFO  Interface-naming: std-exd
    'E1_1.10'



    '''

    intf_list = make_list(intf_list)
    component = kwargs.get('component', 'kernel')
    ifname_type = kwargs.get('ifname_type', st.get_ifname_type(dut))
    ret_intf_list = list()
    for intf in intf_list:
        if not ('Eth' in intf or 'PortChannel' in intf):
            st.log('Interface naming is applicable to Ethernet or PortChannel only', dut=dut)
            ret_intf_list.append(intf)
            continue
        if ifname_type in ['native', 'none']:
            #No error check, as in native mode intf names are same
            if '.' in intf:
                ret_intf_list.append(intf.replace('Ethernet', 'Eth').replace('PortChannel','Po'))
            else:
                ret_intf_list.append(intf)
        if ifname_type == 'alias':
            if 'Eth' in intf and '/' not in  intf:
                st.log('Intf: {} is not a valid alias/standard name'.format(intf), dut=dut)
                ret_intf_list.append(intf)
                continue
            if component.lower() in ['kernel', 'databases', 'applications', 'frr']:
                if '.' in intf:
                    short_name = None
                    other_name = st.get_other_names(dut, [intf.split('.')[0]])[0]
                    short_name = other_name.replace('Ethernet', 'Eth').replace('PortChannel', 'Po')
                    if short_name:
                        ret_intf_list.append(short_name + '.' + intf.split('.')[1])
                    else:
                        st.log('test_step_failed: Invalid Interface Name', dut=dut)
                        ret_intf_list.append(intf)
                else:
                    other_name = st.get_other_names(dut, [intf])[0]
                    ret_intf_list.append(other_name)
            else:
                ret_intf_list.append(intf)
        if ifname_type == 'std-ext':
            if 'Eth' in intf and '/' not in intf:
                st.log('Intf: {} is not a valid std-ext name'.format(intf), dut=dut)
                ret_intf_list.append(intf)
                continue
            if component == 'kernel':
                #For all types of Ethernet interface, replace Eth with E and / with _
                if 'Eth' in intf: ret_intf_list.append(intf.replace('Eth', 'E').replace('/','_'))
                if 'PortChannel' in intf:
                    #For sub interface only, replace PortChannel with Po
                    if '.' in intf:
                        ret_intf_list.append(intf.replace('PortChannel','Po'))
                    else:
                        ret_intf_list.append(intf)
            elif component == 'frr':
                if 'PortChannel' in intf and '.' in intf:
                    ret_intf_list.append(intf.replace('PortChannel','Po'))
                else:
                    ret_intf_list.append(intf)
            else:
                ret_intf_list.append(intf)
    st.log('Intf-naming: {}, Input Intf: {}, Output Intf: {}'.format(ifname_type, intf_list, ret_intf_list), dut=dut)
    if len(ret_intf_list) == 1: return ret_intf_list[0]
    return ret_intf_list

def is_octype_gnmi():
    oc_type = os.getenv('SPYTEST_OPENCONFIG_API')
    if oc_type is None or oc_type.lower() == 'gnmi':
        return True
    else:
        return False
