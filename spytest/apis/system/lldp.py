# This file contains the list of API's which performs LLDP operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
from spytest import st
from spytest.utils import filter_and_select
import json


def get_lldp_table(dut, interface=None):
    """
    Get LLDP table Info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface: localport
    :return:
    """
    command = "show lldp table"
    output = st.show(dut, command)
    if interface:
        return filter_and_select(output, None, {"localport": interface})
    return output


def get_lldp_neighbors(dut, interface=None):
    """
    Get LLDP Neighbours Info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface: localport
    :return:
    """
    command = "show lldp neighbors"
    if interface:
        command = "show lldp neighbors {}".format(interface)
    return st.show(dut, command)

def lldp_config(dut, **kwargs):
    """
           Set LLDP non default config parameters
           Author: Prasad Darnasi (prasad.darnasi@broadcom.com)
           :param dut:
           :param txinterval:LLDP update packet interval
           :param txhold:LLDP hold time
           :param interface:remote interface
           :param status:LLDP enable|disable
           :param hostname:remote system name
           :param capability:LLDP optional capabilities
           :return:
    """
    if 'txinterval' in kwargs:
        command = "configure lldp {} {}".format('tx-interval',kwargs['txinterval'])
        st.config(dut, command, type='lldp')
    if 'txhold' in kwargs:
        command = "configure lldp {} {}".format('tx-hold',kwargs['txhold'])
        st.config(dut, command, type='lldp')
    if 'interface' in kwargs and 'status' in kwargs:
        command = "configure ports {} lldp status {}".format(kwargs['interface'], kwargs['status'])
        st.config(dut, command, type='lldp')
    if 'hostname' in kwargs:
        command = "configure system hostname {}".format(kwargs['hostname'])
        st.config(dut, command, type='lldp')
    if 'capability' in kwargs and 'config' in kwargs:
        cap = kwargs['capability']
        cap_li = list(cap) if isinstance(cap, list) else [cap]
        for each_cap in cap_li:
            if kwargs['config'] == 'yes':
                command = "config lldp {}".format(each_cap)
            else:
                command = "unconfigure lldp {}".format(each_cap)
            st.config(dut, command, type='lldp')


def set_lldp_local_parameters(dut, name, **kwargs):
    """
    Set LLDP Local parameters
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut: 
    :param name: 
    :param mgmt_addr:
    :param hwsku:
    :param lo_addr:
    :param local_port:
    :param local_port:
    :param type:
    :param port:
    :return:
    """
    st.log("Adding local lldp data")
    temp_local_data = {}
    lldp_local_final = {}
    if not kwargs:
        st.error("SET LLDP Local parameters failed because of invalid data.")
        return False
    if 'mgmt_addr' in kwargs:
        temp_local_data['mgmt_addr'] = kwargs['mgmt_addr']
    if 'hwsku' in kwargs:
        temp_local_data['hwsku'] = kwargs['hwsku']
    if 'lo_addr' in kwargs:
        temp_local_data['lo_addr'] = kwargs['lo_addr']
    if 'local_port' in kwargs:
        temp_local_data['local_port'] = kwargs['local_port']
    if 'type' in kwargs:
        temp_local_data['type'] = kwargs['type']
    if 'port' in kwargs:
        temp_local_data['port'] = kwargs['port']

    lldp_local_final['DEVICE_NEIGHBOR'] = {name: temp_local_data}
    lldp_local_final_json = json.dumps(lldp_local_final)
    st.apply_json(dut, lldp_local_final_json)
    return True


def poll_lldp_neighbors(dut, iteration_count=180, delay=1, interface=None):
    """
    Poll for LLDP Neighbours Info
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param iteration_count:
    :param delay:
    :param interface:
    :return:
    """
    i = 1
    while True:
        rv = get_lldp_neighbors(dut, interface)
        if rv:
            return rv
        if i > iteration_count:
            st.log(" Max {} tries Exceeded for lldp neighbors polling .Exiting ...".format(i))
            return False
        i += 1
        st.wait(delay)
