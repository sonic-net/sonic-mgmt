from spytest import st
from apis.system.rest import get_rest

non_physical_ports = ['vlan', 'portchannel', 'loopback']

def get_subinterface_index(dut, port):
    """
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :return:
    :rtype
    """
    if len(port.split(".")) == 2:
        return port.split(".")[-1]
    else:
        return '0'
    #Following part of code is not needed. Will remove it after a complete run
    if any(intf in port.lower() for intf in non_physical_ports):
        return "0"
    rest_urls = st.get_datastore(dut, "rest_urls")
    url = rest_urls['sub_interface_config'].format(port)
    output = get_rest(dut, rest_url = url)
    try:
        index = output['output']['openconfig-interfaces:subinterfaces']['subinterface'][0]['index']
        return str(index)
    except Exception as e:
        st.log("{} exception occurred".format(e))
        st.log("The actual output is: {}".format(output))
        return False
