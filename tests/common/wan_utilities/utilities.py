from net_devices2.factory import PatchworkAnchor
from kusto_proxy.teams import PhyNetKustoProxy
from tests.common.wan_utilities import wan_constants
import logging
import time
import json


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def compare_dictionaries(dict_1, dict_2, dict_1_name, dict_2_name, path=""):
    """Compare two dictionaries recursively to find non mathcing elements
    Args:
        dict_1: dictionary 1
        dict_2: dictionary 2
    Returns:
    """
    err = ''
    key_err = ''
    value_err = ''
    old_path = path
    # Keys in pre_check_metrics
    for k in dict_1.keys():
        path = old_path + "[%s]" % k
        # Keys present in pre-checks and absent in post-checks
        if k not in dict_2:
            key_err += "Key %s%s not in %s\n" % (dict_1_name, path, dict_2_name)
        else:
            if isinstance(dict_1[k], dict) and isinstance(dict_2[k], dict):
                err += compare_dictionaries(dict_1[k], dict_2[k], dict_1_name, dict_2_name, path)
            else:
                if dict_1[k] != dict_2[k]:
                    value_err += "Value of %s%s (%s) not same as %s%s (%s)\n"\
                        % (dict_1_name, path, dict_1[k], dict_2_name, path, dict_2[k])

    # Keys present in pre-checks and absent in post-checks
    for k in dict_2.keys():
        path = old_path + "[%s]" % k
        if k not in dict_1:
            key_err += "Key %s%s not in %s\n" % (dict_2_name, path, dict_1_name)

    return key_err + value_err + err


def kusto_query(query, kusto_cluster='https://waneng.westus2.kusto.windows.net', kusto_database='waneng'):
    kusto_client = PhyNetKustoProxy(kusto_cluster=kusto_cluster)
    response = kusto_client.execute_query(kusto_database, query)
    return [dict(row) for row in response.fetchall()]


def device_type_lookup(dut):
    dut = dut.lower()
    query = f"Devices | where DeviceName == '{dut}'"
    out = kusto_query(query)
    if not out:
        return wan_constants.DEVICE_NOT_IN_NGS
    elif out[0]["DcCode"] != "str":
        return wan_constants.NON_STARLAB_DEVICE
    else:
        return out[0]["Vender"]


def collect_topology(dut, topology_requirements):
    topology_list = []
    query = f"DeviceInterfaceLinks| where (StartDevice == tolower('{dut}') or " \
            f"EndDevice == tolower('{dut}'))"
    out = kusto_query(query)
    # Checking for device types DUT can connect to
    for interop in topology_requirements:
        for connection in out:
            if interop in connection["EndDevice"].lower():
                topology_list.append({
                    "DeviceA": connection["StartDevice"],
                    "InterfaceA": connection["StartPort"],
                    "PortChannelA": connection["StartPortChannel"],
                    "DeviceB": connection["EndDevice"],
                    "InterfaceB": connection["EndPort"],
                    "PortChannelB": connection["EndPortChannel"]})
                break
            elif interop in connection["StartDevice"].lower():
                topology_list.append({
                    "DeviceA": connection["EndDevice"],
                    "InterfaceA": connection["EndPort"],
                    "PortChannelA": connection["EndPortChannel"],
                    "DeviceB": connection["StartDevice"],
                    "InterfaceB": connection["StartPort"],
                    "PortChannelB": connection["StartPortChannel"]})
                break
    if len(topology_list) != len(topology_requirements):
        topo_test_result = False
    else:
        topo_test_result = True
    return topo_test_result, topology_list


def collect_topology_all(dut):
    topology_list = []
    query = (
        f"DeviceInterfaceLinks"
        f"| where (StartDevice == tolower('{dut}') or EndDevice == tolower('{dut}'))"
        f"| where DataCenter == 'STARLab'"
        f"| where StartPort !contains 'console'"
        f"| where EndPort !contains 'console'"

    )
    out = kusto_query(query)
    # Checking for device types DUT can connect to
    for connection in out:
        if dut in connection["StartDevice"].lower():
            topology_list.append({
                "DeviceA": connection["StartDevice"],
                "InterfaceA": connection["StartPort"],
                "PortChannelA": connection["StartPortChannel"],
                "DeviceB": connection["EndDevice"],
                "InterfaceB": connection["EndPort"],
                "PortChannelB": connection["EndPortChannel"]})
        elif dut in connection["EndDevice"].lower():
            topology_list.append({
                "DeviceA": connection["EndDevice"],
                "InterfaceA": connection["EndPort"],
                "PortChannelA": connection["EndPortChannel"],
                "DeviceB": connection["StartDevice"],
                "InterfaceB": connection["StartPort"],
                "PortChannelB": connection["StartPortChannel"]})
    topo_test_result = True
    if not topology_list:
        topo_test_result = False
    return topo_test_result, topology_list


def convert_mac_dotted_to_column(mac):
    """
    :param mac: dotted format MAC address, e.g. 1234.5678.9abc
    :return: mac_reformatted: column format, e.g. 12:34:56:78:9a:bc
    """
    index = 0
    mac_reformatted = ""
    for char in mac:
        if char != ".":
            if index % 2 == 0:
                mac_reformatted += char
                index += 1
            elif index == 11:  # do not add a ":" at the end of the string
                mac_reformatted += char
            else:
                mac_reformatted += char + ":"
                index += 1

    return mac_reformatted


def get_links_matching_topology_requirements(dut, topology_requirements):
    """
    :param dut: DUT name
    :param topology_requirements:dictionary representing topology requirements
    e.g
    ['ibr', 'sw']
    :return
    topo_test_result: Boolean - represents required topology found or not
    topology_list: list of all links matching topology requirements
    e.g. [{'DeviceA':
    'rwa02.str01', 'InterfaceA': 'et-2/0/12', 'PortChannelA': 'PortChannel15', 'DeviceB': 'ibr02.str01',
    'InterfaceB': 'HundredGigE0/2/0/10', 'PortChannelB': 'PortChannel15'}, {'DeviceA': 'rwa02.str01', 'InterfaceA':
    'et-2/0/14', 'PortChannelA': 'PortChannel16', 'DeviceB': 'ibr02.str02', 'InterfaceB': 'HundredGigE0/2/0/12',
    'PortChannelB': 'PortChannel16'}, {'DeviceA': 'rwa02.str01', 'InterfaceA': 'et-2/0/15', 'PortChannelA':
    'PortChannel16', 'DeviceB': 'ibr02.str02', 'InterfaceB': 'HundredGigE0/2/0/13', 'PortChannelB': 'PortChannel16'},
    {'DeviceA': 'rwa02.str01', 'InterfaceA': 'et-2/0/13', 'PortChannelA': 'PortChannel15', 'DeviceB': 'ibr02.str01',
    'InterfaceB': 'HundredGigE0/2/0/11', 'PortChannelB': 'PortChannel15'}, {'DeviceA': 'rwa02.str01', 'InterfaceA':
    'et-2/0/9', 'PortChannelA': 'PortChannel206', 'DeviceB': 'str06-0100-0001-02sw', 'InterfaceB': 'Ethernet5/24/1',
    'PortChannelB': 'PortChannel206'}, {'DeviceA': 'rwa02.str01', 'InterfaceA': 'et-2/0/11', 'PortChannelA':
    'PortChannel208', 'DeviceB': 'str06-0100-0001-01sw', 'InterfaceB': 'Ethernet4/10/1', 'PortChannelB':
    'PortChannel208'}, {'DeviceA': 'rwa02.str01', 'InterfaceA': 'et-2/0/8', 'PortChannelA': 'PortChannel206',
    'DeviceB': 'str06-0100-0001-02sw', 'InterfaceB': 'Ethernet5/23/1', 'PortChannelB': 'PortChannel206'}, {'DeviceA':
    'rwa02.str01', 'InterfaceA': 'et-2/0/10', 'PortChannelA': 'PortChannel208', 'DeviceB': 'str06-0100-0001-01sw',
    'InterfaceB': 'Ethernet4/9/1', 'PortChannelB': 'PortChannel208'}]
    """
    topology_list = []
    query = f"DeviceInterfaceLinks| where (StartDevice == '{dut}' or " \
            f"EndDevice == '{dut}')"
    connection_list = kusto_query(query)

    for peerType in topology_requirements:
        for connection in connection_list:
            if peerType in connection["EndDevice"].lower():
                topology_list.append({
                    "DeviceA": connection["StartDevice"],
                    "InterfaceA": connection["StartPort"],
                    "PortChannelA": connection["StartPortChannel"],
                    "DeviceB": connection["EndDevice"],
                    "InterfaceB": connection["EndPort"],
                    "PortChannelB": connection["EndPortChannel"]})
            elif peerType in connection["StartDevice"].lower():
                topology_list.append({
                    "DeviceA": connection["EndDevice"],
                    "InterfaceA": connection["EndPort"],
                    "PortChannelA": connection["EndPortChannel"],
                    "DeviceB": connection["StartDevice"],
                    "InterfaceB": connection["StartPort"],
                    "PortChannelB": connection["StartPortChannel"]})
    if len(topology_list) == 0:
        topo_test_result = False
    else:
        topo_test_result = True
    return topo_test_result, topology_list


def filter_ngs_topology(dut, topology_requirements, macsec='False', min_lag_member_links_count=2,
                        number_of_required_portchannels=1, traffic=False):
    """
    This function further filters the topology to match more detailed requirements like min links in lag,
    macsec enabled links, etc
    :param dut: DUT name
    :param topology_requirements:
    :param macsec: Boolean
    :param min_lag_member_links_count: integer
    :param number_of_required_portchannels: integer
    :param traffic: Boolean for traffic check
    :return
    topo_test_result: Boolean - reflects desired topology found or not
    result_message - Verbose message of result e.g 'Successfully found required topology links'
    port_channel_topo_dict_filtered: Nested dictionary with Key as the portchannel number and
    value is a list of links that are part of that portchannel.
    Each item within the list is itself is a dictionary with keys -
    DeviceA, InterfaceA, PortChannelA, DeviceB, InterfaceB, PortChannelB
    e.g.
    {
                    "PortChannel16": [
                        {
                            "DeviceA": "rwa02.str01",
                            "DeviceB": "ibr02.str02",
                            "InterfaceA": "et-2/0/14",
                            "InterfaceB": "HundredGigE0/2/0/12",
                            "PortChannelA": "PortChannel16",
                            "PortChannelB": "PortChannel16"
                        },
                        {
                            "DeviceA": "rwa02.str01",
                            "DeviceB": "ibr02.str02",
                            "InterfaceA": "et-2/0/15",
                            "InterfaceB": "HundredGigE0/2/0/13",
                            "PortChannelA": "PortChannel16",
                            "PortChannelB": "PortChannel16"
                        }
                    ],
                    "PortChannel206": [
                        {
                            "DeviceA": "rwa02.str01",
                            "DeviceB": "str06-0100-0001-02sw",
                            "InterfaceA": "et-2/0/9",
                            "InterfaceB": "Ethernet5/24/1",
                            "PortChannelA": "PortChannel206",
                            "PortChannelB": "PortChannel206"
                        },
                        {
                            "DeviceA": "rwa02.str01",
                            "DeviceB": "str06-0100-0001-02sw",
                            "InterfaceA": "et-2/0/8",
                            "InterfaceB": "Ethernet5/23/1",
                            "PortChannelA": "PortChannel206",
                            "PortChannelB": "PortChannel206"
                        }
                    ]
                }
    """
    filtered_topology_list = {}
    topo_test_result, topology_list = get_links_matching_topology_requirements(dut, topology_requirements)
    if not topo_test_result:
        return topo_test_result, filtered_topology_list
    else:
        port_channel_topo_dict = {}
        for link in topology_list:
            # link is a dictionary. set list1 to be list of dictionaries with first element as the link
            list1 = [link]
            # if this is the first link for the corresponding portchannel then add new key, value pair to the dictionary
            # key will be portchannel name and value will be set to as list with first element as the link
            if link['PortChannelA'] not in port_channel_topo_dict.keys():
                key1 = link['PortChannelA']
                port_channel_topo_dict[key1] = list1
            else:
                # if the Portchannel name is already present as key in the dictionary, then append this link
                # to the existing list of links
                port_channel_topo_dict[link['PortChannelA']].append(link)

        # Check that portchannel has the required number of links
        # need to convert dict items to list else it gives error in python3
        for key, value in list(port_channel_topo_dict.items()):
            link_members = value
            if len(link_members) < min_lag_member_links_count:
                del port_channel_topo_dict[key]

        # confirm that we got the required number of port-channels and create filtered dictionary
        port_channel_topo_dict_filtered = {}
        topo_test_result = True
        for peerType in topology_requirements:
            port_channel_count = 0
            for pkey, pvalue in list(port_channel_topo_dict.items()):
                if peerType in pvalue[0]["DeviceB"].lower():
                    port_channel_count += 1
                    port_channel_topo_dict_filtered[pkey] = pvalue
                if port_channel_count == number_of_required_portchannels:
                    break
            if port_channel_count < number_of_required_portchannels:
                topo_test_result = False
                break

        return topo_test_result, port_channel_topo_dict_filtered


def validate_dut_dc_code(dut_handler):
    """
    :param dut_handler: device in test handler
    :return: boolean, test_msg for logging
    """
    if dut_handler.dc_code != "str":
        test_msg = "DC code {0} not permitted, 'str' DC code only".format(dut_handler.dc_code)
        return False, test_msg
    else:
        test_msg = "DC code {0} permitted".format(dut_handler.dc_code)
        return True, test_msg


def capture_prestate(dut_handler, testname):
    """
    :param dut_handler: device handler to capture configuration on
    :param testname: optional field to specify test name as part of filename
    :return: capture_result, testmsg, prechange_filename
    """
    prechange_filename = "wantest_preconfig_{0}_{1}.cfg".format(testname, time.strftime("%Y%m%d-%H%M%S"))
    capture_result, testmsg = dut_handler.capture_prechange_config(prechange_filename)
    return capture_result, testmsg, prechange_filename


def load_prestate(dut_handler, prechange_filename):
    """
    :param dut_handler:
    :param prechange_filename:
    :return:
    """
    load_result, testmsg = dut_handler.load_prechange_config(prechange_filename)
    return load_result, testmsg


def elongate_cisco_interface(interface):
    """
    Give interface short form like BE Hu Te ...
    :param interface: str Give interface short name
    :return str : interface full name
    """

    if "be" in interface or "BE" in interface:
        interface = interface.replace("be", "Bundle-Ether")
        interface = interface.replace("BE", "Bundle-Ether")
        return interface
    elif "Fi0" in interface:
        return interface.replace("Fi0", "FiftyGigE0")
    elif "Fo0" in interface:
        return interface.replace("Fo0", "FortyGigE0")
    elif "F0" in interface:
        return interface.replace("F0", "FourHundredGigE0")
    elif "Gi0" in interface:
        return interface.replace("Gi0", "GigabitEthernet0")
    elif "Hu0" in interface:
        return interface.replace("Hu0", "HundredGigE0")
    elif "Te0" in interface:
        return interface.replace("Te0", "HundredGigE0")
    elif "TF0" in interface:
        return interface.replace("TF0", "TwentyFiveGigE0")
    elif "TH0" in interface:
        return interface.replace("TH0", "TwoHundredGigE0")
    else:
        return interface


class WanPatchwork(PatchworkAnchor):
    def parse_output(self, output):
        """ do some parsing """
        return json.dumps(output)

    def my_method(self):
        raise NotImplementedError(f"'my_method' not implemented for {self.hardware_sku}")

    def check_version(self, expected_versions):
        current_version = self.running_os_version
        if current_version == expected_versions:
            return True, {'current_version': current_version,
                          'expected_version': expected_versions}
        return False, {'current_version': current_version,
                       'expected_version': expected_versions}
