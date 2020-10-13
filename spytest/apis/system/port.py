from spytest.utils import filter_and_select

from spytest import st

def set_status(dut, portlist, status):
    """

    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    :param status: "shutdown" or "startup"
    :type status: string
    :return:
    :rtype:
    """

    if '-' in portlist:
        st.config(dut, "config interface {} {}".format(status, portlist))
        return

    if not st.is_community_build():
        try:
            port = ",".join(portlist)
            return st.config(dut, "config interface {} {}".format(status, port))
        except Exception as exp:
            st.warn("Failed to execute {} command - try alternative".format(status))

    for port in portlist:
        try:
            st.config(dut, "config interface {} {}".format(status, port))
        except ValueError as ex:
            st.warn("Failed to execute {} command - try alternative".format(status))
            st.config(dut, "config interface {} {}".format(port, status))
    return ""

def shutdown(dut, portlist):
    """

    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    :return:
    :rtype:
    """
    set_status(dut, portlist, "shutdown")

def noshutdown(dut, portlist):
    """

    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    :return:
    :rtype:
    """
    set_status(dut, portlist, "startup")

def get_status(dut, port=None):
    """

    :param dut:
    :type dut:
    :param port:
    :type port:
    :return:
    :rtype:
    """

    if not port:
        return st.show(dut, "show interfaces status")

    # no range support in community build
    if st.is_community_build():
        if "," in port or "-" in port:
            return st.show(dut, "show interfaces status")

    # port could be range switch to all when failed
    try:
        return st.show(dut, "show interfaces status {}".format(port))
    except ValueError as ex:
        st.warn("Failed to use interface command - try global")

    return st.show(dut, "show interfaces status")

def get_interfaces_by_status(dut, status):
    """

    :param dut:
    :type dut:
    :param status:
    :type status:
    :return:
    :rtype:
    """
    output = get_status(dut, None)
    retval = []
    match = {"oper": status} if status else None
    entries = filter_and_select(output, ["interface"], match)
    for ent in entries:
        retval.append(ent["interface"])
    return retval


def get_interfaces_up(dut):
    """

    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    return get_interfaces_by_status(dut, "up")


def get_interfaces_down(dut):
    """

    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    return get_interfaces_by_status(dut, "down")


def get_interfaces_all(dut):
    """

    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    return get_interfaces_by_status(dut, None)


def get_interface_status(dut, port):
    """

    :param dut:
    :type dut:
    :param port:
    :type port:
    :return:
    :rtype:
    """
    output = get_status(dut, port)
    match = {"interface": port}
    entries = filter_and_select(output, ["oper"], match)
    for ent in entries:
        return ent["oper"]
    return None


def verify_oper_state(dut, port, state):
    """

    :param dut:
    :type dut:
    :param port:
    :type port:
    :param state:
    :type state:
    :return:
    :rtype:
    """
    if get_interface_status(dut, port) != state:
        return False
    return True

def get_interface_counters_all(dut):
    return st.show(dut, "show interfaces counters -a")

def clear_interface_counters(dut):
    if st.is_community_build():
        return st.config(dut, "sonic-clear counters")
    else:
        return st.show(dut, "show interfaces counters -c")

def get_interface_counters(dut, port, *counter):
    output = get_interface_counters_all(dut)
    entries = filter_and_select(output, counter, {'iface': port})
    return entries

