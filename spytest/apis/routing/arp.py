# This file contains the list of API's which performs ARP operations.
# @author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest import st
from utilities.common import filter_and_select, dicts_list_values


def show_arp(dut, ipaddress=None, interface=None):
    """
    To get arp table info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param ipaddress:
    :param interface:
    :return:
    """

    command = "show arp"
    if ipaddress:
        command += " {}".format(ipaddress)
    if interface:
        command += " -if {}".format(interface)
    return st.show(dut, command)


def get_arp_count(dut, ipaddress=None, interface=None):
    """
    To get arp count
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param ipaddress:
    :param interface:
    :return:
    """
    command = "show arp"
    if ipaddress:
        command += " {}".format(ipaddress)
    if interface:
        command += " -if {}".format(interface)
    command += " | grep 'Total number of entries'"
    output = st.show(dut, command)
    out = dicts_list_values(output, 'count')
    return int(out[0]) if out else 0

    
def add_static_arp(dut, ipaddress, macaddress, interface=None):
    """
    To add static arp
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param ipaddress:
    :param macaddress:
    :param interface:
    :return:
    """

    command = "arp -s {} {}".format(ipaddress, macaddress)
    if interface:
        command += " -i {}".format(interface)
    st.config(dut, command)
    return True


def delete_static_arp(dut, ipaddress, interface=None):
    """
    To delete static arp
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param ipaddress:
    :param interface:
    :return:
    """

    command = "arp -d {} ".format(ipaddress)
    if interface:
        command += " -i {}".format(interface)
    st.config(dut, command)
    return True


def clear_arp_table(dut):
    """
    Clear arp table
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    command = "sonic-clear arp"
    st.config(dut, command)
    return True


def set_arp_ageout_time(dut, timeout):
    """
    To set arp aging time
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param timeout:
    :return:
    """

    command = "sudo bash -c 'echo {} >/proc/sys/net/ipv4/neigh/default/gc_stale_time'".format(timeout)
    st.config(dut, command)
    return True


def get_arp_ageout_time(dut):
    """
    To get arp aging time.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    command = "cat /proc/sys/net/ipv4/neigh/default/gc_stale_time"
    out = st.config(dut, command)
    try:
        return out.split("\n")[0]
    except IndexError as e:
        st.log(e)
        st.error("Failed to get the ARP age-out time")
        return None


def verify_arp(dut, ipaddress, macaddress=None, interface=None, vlan=None):
    """
    To verify arp table
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param ipaddress:
    :param macaddress:
    :param interface:
    :param vlan:
    :return:
    """

    output = show_arp(dut, ipaddress)
    entries = filter_and_select(output, None, {"address": ipaddress})
    if not entries:
        st.error("No ARP entry found for the provided IP Address -{}".format(ipaddress))
        return False
    if macaddress and not filter_and_select(entries, None, {"address": ipaddress, "macaddress": macaddress}):
        st.error("Provided and configured macaddress values are not same.")
        return False
    if interface and not filter_and_select(entries, None, {"address": ipaddress, 'iface': interface}):
        st.error("Provided and configured interface values are not same.")
        return False
    if vlan and not filter_and_select(entries, None, {"address": ipaddress, "vlan": vlan}):
        st.error("Provided and configured vlan values are not same.")
        return False
    return True


def get_max_arp_entries_supported_count(dut):
    """
    To get max supported arp entries.
    Author: Rakesh Kumar Vooturi (rakesh-kumar.vooturi@broadcom.com)

    :param dut:
    :return:
    """
    command = "cat /proc/sys/net/ipv4/neigh/default/gc_thresh3"
    out = st.config(dut, command)
    try:
        return int(out.split("\n")[0])
    except Exception as e:
        st.log(e)
        st.error("Failed to get the max arp entries supported count.")
        return None


def show_ndp(dut, inet6_address=None, **kwargs):
    """
    to get ndp table info
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param inet6_address:
    :return:
    """
    command = "show ndp"
    if inet6_address:
        command += " {}".format(inet6_address)
    if "interface" in kwargs and kwargs["interface"]:
        command += " -if {}".format(kwargs["interface"])
    return st.show(dut, command)


def verify_ndp(dut, inet6_address, **kwargs):
    """
    To Verify ndt table info
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param inet6_address
    :param mac_address:
    :param interface:
    :param vlan:
    :param status:
    :return:
    """

    if "interface" in kwargs and kwargs["interface"]:
        response = show_ndp(dut, inet6_address, interface = kwargs["interface"])
    else:
        response = show_ndp(dut, inet6_address)
    st.log("Response {}".format(response))
    if not response:
        return False
    st.log("Kwargs {}".format(kwargs))
    entries = filter_and_select(response, None, kwargs)
    st.log("Entries {}".format(entries))
    if not entries:
        return False
    return True


def config_static_ndp(dut, ip6_address, mac_address, interface, operation="add"):
    """
    Config static ndp
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

    :param dut:
    :param ip6_address:
    :param mac_address:
    :param interface:
    :param operation:
    :return:
    """
    oper = "replace" if operation == "add" else "del"
    command = "ip -6 neighbor {} {} lladdr {} dev {}".format(oper, ip6_address, mac_address, interface)
    st.config(dut, command)


def get_ndp_count(dut):
    """
    To get ndp count
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    command = "show ndp | grep 'Total number of entries'"
    output = st.show(dut, command)
    out = dicts_list_values(output, 'count')
    return int(out[0]) if out else 0


def clear_ndp_table(dut):
    """
    Clear ndp table
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    command = "sonic-clear ndp"
    st.config(dut, command)
    return True


def set_ndp_ageout_time(dut, timeout):
    """
    To set ndp aging time
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :param timeout:
    :return:
    """

    command = "sudo bash -c 'echo {} >/proc/sys/net/ipv6/neigh/default/gc_stale_time'".format(timeout)
    st.config(dut, command)
    return True


def get_ndp_ageout_time(dut):
    """
    To get ndp aging time.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    command = "cat /proc/sys/net/ipv6/neigh/default/gc_stale_time"
    out = st.config(dut, command)
    try:
        return out.split("\n")[0]
    except IndexError as e:
        st.log(e)
        st.error("Failed to get the NDP age-out time")
        return None


def get_max_ndp_entries_supported_count(dut):
    """
    To get max supported ndp entries.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)

    :param dut:
    :return:
    """
    command = "cat /proc/sys/net/ipv6/neigh/default/gc_thresh3"
    out = st.config(dut, command)
    try:
        return int(out.split("\n")[0])
    except Exception as e:
        st.log(e)
        st.error("Failed to get the max ndp entries supported count.")
        return None
