from spytest.utils import filter_and_select
from spytest import st
from spytest.utils import exec_all
import apis.system.basic as basic_obj
import utilities.utils as utils_obj


def get_mac(dut,**kwargs):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    cli_type = kwargs.get("cli_type") if kwargs.get("cli_type") else "click"
    if cli_type == "click":
        return st.show(dut, "show mac")
    elif cli_type == "klish":
        response = dict()
        attrs = ["address", "interface", "type", "vlan", "count"]
        command = "show mac address-table"
        if kwargs.get("count"):
            command += " count"
            output = st.show(dut, command, type=cli_type)
            if output:
                for data in output:
                    for key, value in data.items():
                        if value:
                            response[key] = value
            return response
        else:
            for attr in attrs:
                if kwargs.get(attr):
                    if attr not in ["type", "count"]:
                        if attr == "interface":
                            interface_number = utils_obj.get_interface_number_from_name(kwargs.get(attr))
                            if interface_number:
                                command += " {} {} {}".format(attr, interface_number["type"], interface_number["number"])
                        elif attr == "type":
                            command += " {} {}".format(attr, kwargs.get(attr))
                    else:
                        command += " {}".format(kwargs.get(attr))
            return st.show(dut, command,  type=cli_type)
    else:
        st.log("Invalid cli type")
        return False



def get_mac_all_intf(dut, intf):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    output = get_mac(dut)
    retval = []
    entries = filter_and_select(output, ["macaddress"], {'port': str(intf)})
    for ent in entries:
        retval.append(ent["macaddress"])
    return retval


def get_mac_all(dut, vlan, cli_type="click"):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    output = get_mac(dut, cli_type=cli_type)
    retval = []
    entries = filter_and_select(output, ["macaddress"], {'vlan': str(vlan)})
    for ent in entries:
        retval.append(ent["macaddress"])
    return retval


def get_mac_entries_by_mac_address(dut, mac_address):
    command="show mac | grep {}".format(mac_address)
    mac_entries = st.show(dut, command)
    if not mac_entries:
        return list
    return mac_entries


def get_mac_count(dut):
    """
    To get the MAC count using - 'show mac count' command.
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    output = st.show(dut, "show mac count")
    count = int(output[0]['mac_count'])
    return count


def get_mac_address_count(dut, vlan=None, port=None, type=None, mac_search=None):
    """
     To verify the MAC count after applying given filters vlan/port/type/mac_pattern
    :param dut:
    :param vlan: vlan id which needs to be filtered
    :param port: port which needs to be filtered like Ethernet4/PortChannel1
    :param type: mac type to be filtered, Values can be Static/Dynamic
    :param mac_search: mac_pattern to be grepped from show mac output
    :return:
    """
    dec_flag = 0
    if mac_search:
        entries = get_mac_entries_by_mac_address(dut, mac_search)
    else:
        entries = get_mac(dut)
        ###Decrement by 1 as output has "Total number of entries" as one list element
        dec_flag = 1
    if entries == list or entries == None:
        ### If entries is null, no need to apply filter, return 0
        return 0

    if vlan:
        entries = filter_and_select(entries, None, {"vlan": str(vlan)})
        dec_flag = 0
    if port:
        entries = filter_and_select(entries, None, {"port": port})
        dec_flag = 0
    if type:
        entries = filter_and_select(entries, None, {"type": type})
        dec_flag = 0
    return len(entries)-1 if dec_flag==1 else len(entries)


def verify_mac_address(dut, vlan, mac_addr):
    """

    :param dut:
    :param vlan:
    :param mac_addr:
    :return:
    """

    if basic_obj.is_vsonic_device(dut):
        st.log("For vSONiC device, waiting for 10 sec")
        st.wait(10)

    st.log("Checking provided mac entries are present in mac table under specified vlan")
    mac_address_all = get_mac_all(dut, vlan)
    mac_addr_list = [mac_addr] if type(mac_addr) is str else mac_addr
    return set(mac_addr_list).issubset(set(mac_address_all))


def get_sbin_intf_mac(dut, interface):
    """
    This proc is to return the mac address of the interface from the ifconfig o/p.
    :param dut: DUT Number
    :param interface: Interface number
    :return:
    """
    my_cmd = "/sbin/ifconfig {}".format(interface)
    output = st.show(dut, my_cmd)
    output = dict(output[0])
    mac = output['mac']
    return mac


def clear_mac(dut,port=None,vlan=None,**kwargs):
    """
    This proc is to clear mac address/fdb entries of the dut.
    :param dut: DUT Number
    :return:
    """
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut))
    if cli_type == "click":
        if port:
            command = "sonic-clear fdb port {}".format(port)
        elif vlan:
            command = "sonic-clear fdb vlan Vlan{}".format(vlan)
        else:
            command = "sonic-clear fdb all"
    elif cli_type == "klish":
        if kwargs.has_key('address'):
            command = "clear mac address-table address  {}".format(kwargs['address'])
        elif kwargs.has_key('vlan'):
            command = "clear mac address-table dynamic Vlan {}".format(kwargs['vlan'])
        else:
            command = "clear mac address-table dynamic all"

    st.config(dut, command,cli_type=cli_type)
    return True


def config_mac(dut, mac, vlan, intf):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    #st.log("config mac add <mac> <vlan> <intf>")
    command = "sudo config mac add {} {} {}".format(mac, vlan, intf)
    st.config(dut, command)
    return True


def delete_mac(dut, mac, vlan):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    #st.log("config mac del <mac> <vlan>")
    command = "sudo config mac del {} {}".format(mac, vlan)
    st.config(dut, command)
    return True


def config_mac_agetime(dut, agetime):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    #st.log("config mac aging_time")
    command = "sudo config mac aging_time {}".format(agetime)
    st.config(dut, command)
    return True


def config_fdb_aging_time(dut, agetime):
    """
    This proc is to clear mac address/fdb entries of the dut.
    :param dut: DUT Number
    :param agetime: fdg age time in seconds
    :return:
    """
    st.config(dut, "config mac aging_time {}".format(agetime))
    return True


def get_mac_agetime(dut):
    """
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    output = st.show(dut, "show mac aging_time")
    retval = output[0]["aging_time"]
    return int(retval)


def get_mac_address_list(dut, mac=None, vlan=None, port=None, type=None):
    """

    :param dut:
    :param mac:
    :param vlan:
    :param port:
    :param type:
    :return:
    """
    entries = get_mac(dut)
    if mac:
        entries = filter_and_select(entries, None, {"macaddress": str(mac)})
    if vlan:
        entries = filter_and_select(entries, None, {"vlan": str(vlan)})
    if port:
        entries = filter_and_select(entries, None, {"port": port})
    if type:
        entries = filter_and_select(entries, None, {"type": type})
    return [ent["macaddress"] for ent in filter_and_select(entries, ['macaddress'], None)]


def verify_mac_address_table(dut, mac_addr, vlan=None, port=None, type=None, dest_ip=None):
    """
    To verify the MAC parameters
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mac_addr:
    :param vlan:
    :param port:
    :param type:
    :param dest_ip:
    :return:
    """

    if basic_obj.is_vsonic_device(dut):
        st.log("For vSONiC device, waiting for 10 sec")
        st.wait(10)

    output = get_mac(dut)
    entries = filter_and_select(output, None, {"macaddress": mac_addr})
    if not entries:
        st.log("Provided MAC {} entry is not exist in table".format(mac_addr))
        return False
    if vlan and not filter_and_select(entries, None, {"vlan": str(vlan)}):
        st.log("Provided VLAN {} is not exist in table with MAC  {}".format(vlan, mac_addr))
        return False
    if port and not filter_and_select(entries, None, {"port": port}):
        st.log("Provided Port {} is not exist in table with MAC  {}".format(port, mac_addr))
        return False
    if type and not filter_and_select(entries, None, {"type": type}):
        st.log("Provided Type {} is not exist in table with MAC  {}".format(type, mac_addr))
        return False
    if dest_ip and not filter_and_select(entries, None, {"dest_ip": dest_ip}):
        st.log("Provided DEST_IP {} is not exist in table with MAC {}".format(dest_ip, mac_addr))
        return False
    return True


def get_mac_all_dut(dut_list, thread=True):
   st.log("Displaying mac ..in all dut")
   dut_li = list([str(e) for e in dut_list]) if isinstance(dut_list, list) else [dut_list]
   params = list()
   for dut in dut_li:
       params.append([get_mac, dut])
   if params:
       exec_all(thread, params)
