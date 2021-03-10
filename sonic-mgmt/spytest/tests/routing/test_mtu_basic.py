#! /usr/bin/env python

'''
Executes the following cases from the master testplan:
SFD_MTU_BASIC_2: Verify that the MTU can be set on all interfaces : Mgmt, Ethernet, PortChannel, Vlan

SFD_MTU_BASIC_3: Verify that the MTU cannot be set to a value greater than 9k(ipv6)

SFD_MTU_BASIC_4: Verify that the MTU is set to the correct value after loading the config(ipv6).

SFD_MTU_BASIC_5: Verify that the MTU can be set on all interfaces : Mgmt, Ethernet, PortChannel, Vlan(ipv6)

SFD_MTU_BASIC_6: Verify that the MTU cannot be set to a value greater than 9k(ipv6)
'''

import re
import math
import pytest
from spytest import st, tgapi, SpyTestDict

from apis.routing.ip import ping, get_interface_ip_address, config_unconfig_interface_ip_addresses, clear_ip_configuration
from apis.system.interface import interface_status_show, show_interfaces_counters
from apis.system.reboot import config_save
from apis.system.basic import get_ps_aux
from apis.switching.portchannel import create_portchannel, add_portchannel_member
from apis.switching.vlan import create_vlan, add_vlan_member
import apis.system.logging as slog_obj

data = SpyTestDict()
global test_vars

def setup_duts():
  global test_vars
  try:
    test_vars
    return
  except NameError:
    st.log("pre-fill-data is not done yet, doing it now")
  test_vars = st.ensure_min_topology('D1D2:4')
  test_vars.interface_list = {}
  test_vars.interface_list['dut1'] = []
  test_vars.interface_list['dut2'] = []
  for i in range(1,2):
    try:
      test_vars.interface_list['dut1'].append(test_vars['D1D2P{}'.format(i)])
      test_vars.interface_list['dut2'].append(test_vars['D2D1P{}'.format(i)])
    except KeyError:
      raise RuntimeError("Couldnot find the interface for count:{}, we need atleast 4 interfaces between DUTs. test_vars={}".format(i, test_vars))

  # Config IP addresses for all intfs.
  test_vars.ipv4_prefix = "200.0.{}.{}"
  test_vars.ipv6_prefix = "CCCC:{}::{}"

  # The set up is as follows:
  # Interfaces 1 and 2 are for Ethernet itself.
  # Interfaces 3 is for portChannel
  # Interfaces 4 is for Vlans.
  clear_ip_configuration([test_vars.D1, test_vars.D2])

  # Setup Ethernet 1 and 2:
  for i in range(1,2):
    if_data4 = {'name': test_vars['D1D2P{}'.format(i)],
               'ip' : test_vars.ipv4_prefix.format(i,1),
               'subnet': 24,
               'family': "ipv4"
              }
    if_data6 = {'name': test_vars['D1D2P{}'.format(i)],
               'ip' : test_vars.ipv6_prefix.format(i,1),
               'subnet': 64,
               'family': "ipv6"
              }
    config_unconfig_interface_ip_addresses(test_vars.D1, [if_data4, if_data6], config='add')

    if_data4 = {'name': test_vars['D2D1P{}'.format(i)],
               'ip' : test_vars.ipv4_prefix.format(i,2),
               'subnet': 24,
               'family': "ipv4"
              }
    if_data6 = {'name': test_vars['D1D2P{}'.format(i)],
               'ip' : test_vars.ipv6_prefix.format(i,2),
               'subnet': 64,
               'family': "ipv6"
              }
    config_unconfig_interface_ip_addresses(test_vars.D2, [if_data4, if_data6], config='add')

  """
  # Unsupported ? Gives this error:
    cisco@sonic:~$ sudo config interface  mtu PortChannel1 1512
    Invalid port specified
    cisco@sonic:~$ 
  # Setup Ethernet 3 - Port Channel.
  member_names = [test_vars['D1D2P{}'.format(3)], test_vars['D2D1P{}'.format(3)]]
  for i in [1, 2]:
    dut = test_vars['D{}'.format(i)]
    create_portchannel(dut, portchannel_list=['PortChannel1'])
    add_portchannel_member(dut, portchannel="PortChannel1", members=[member_names[i-1]])
    if_data4 = {'name': "PortChannel1",
                 'ip' : test_vars.ipv4_prefix.format(3,i),
                 'subnet': 24,
                 'family': "ipv4"
                }
    if_data6 = {'name': "PortChannel1",
                 'ip' : test_vars.ipv6_prefix.format(3,i),
                 'subnet': 64,
                 'family': "ipv6"
                }
    config_unconfig_interface_ip_addresses(dut, [if_data4, if_data6], config='add')

  # Setup Ethernet 4 - Vlan
  member_names = [test_vars['D1D2P{}'.format(4)], test_vars['D2D1P{}'.format(4)]]
  for i in [1, 2]:
    dut = test_vars['D{}'.format(i)]
    create_vlan(dut, vlan_list=['Vlan1'])
    add_vlan_member(dut, vlan="Vlan1", members=[member_names[i-1]])
    if_data4 = {'name': "Vlan1",
                 'ip' : test_vars.ipv4_prefix.format(4,i),
                 'subnet': 24,
                 'family': "ipv4"
                }
    if_data6 = {'name': "Vlan1",
                 'ip' : test_vars.ipv6_prefix.format(4,i),
                 'subnet': 64,
                 'family': "ipv6"
                }
    config_unconfig_interface_ip_addresses(dut, [if_data4, if_data6], config='add')
    """

@pytest.fixture(params=["ipv4", "ipv6"])
def afamily(request):
    return request.param

def test_mtu_basic_1(afamily):
  global test_vars
  setup_duts()
  # This is a long running process.
  # So I am cutting down to only one.
  for dut in [test_vars.D1]:
    for mtu in [1500, 9100]:
      for i in range(1,2):
        set_mtu(dut, test_vars['D1D2P{}'.format(i)], mtu)
      """ Unsupported
      set_mtu(dut, "PortChannel1", mtu)
      set_mtu(dut, "Vlan1", mtu)
      """
      config_save(dut)
      st.reboot(dut)
      for i in range(1,2):
        verify_mtu(dut, test_vars['D1D2P{}'.format(i)], mtu)
      """ Unsupported
      verify_mtu(dut, "PortChannel1", mtu)
      verify_mtu(dut, "Vlan1", mtu)
      """
  st.report_pass("mtu_test_status", "Mtu gets loaded after reload as expected")

def test_mtu_basic_2(afamily):
  global test_vars
  setup_duts()
  for mtu in [1500, 9100]:
    for i in range(1,2):
      set_mtu_ping_verify(test_vars.D1, test_vars.D2, test_vars['D1D2P{}'.format(i)], test_vars['D2D1P{}'.format(i)], mtu, afamily)
    """ Unsupported
    set_mtu_ping_verify(test_vars.D1, test_vars.D2, "PortChannel1", "PortChannel1", mtu, afamily)
    set_mtu_ping_verify(test_vars.D1, test_vars.D2, "Vlan1", "Vlan1",  mtu, afamily)
    """
  st.report_pass('mtu_test_status', "Setting MTU, and checking ping packet count worked as required")

def test_mtu_basic_3(afamily):
  global test_vars
  setup_duts()
  for dut in [test_vars.D1]:
    for mtu in [10000, 20000]:
      for i in range(1,2):
        # Unsupported
        #intfs = [test_vars['D1D2P{}'.format(i)], "PortChannel1", "Vlan1"]
        intfs = [test_vars['D1D2P{}'.format(i)]]
        for intf in intfs:
          msg = "Setting mtu:{} on {}:{}".format(mtu, dut, intf)
          if not check_orchagent(dut):
            st.report_fail("The orchagent is not running even before setting MTU, pls check.")
          default = get_mtu(dut, intf)
          set_mtu(dut, intf, mtu)
          slog_obj.clear_logging(dut)
          try:
            if check_logs_for_mtu_message(dut):
              st.log("The orchagent gives error as expected when we configure too big values for MTU.")
            else:
              st.report_fail("mtu_test_status", "{} seems to work, not expected".format(msg))
          finally:
            set_mtu(dut, intf, default)

  st.report_pass('mtu_test_status', "Everything above the max value failed as expected")

def check_logs_for_mtu_message(dut):
  """ 
    Check for the error message "Failed to set MTU" in the log and return true if found.
  """ 
  global test_vars
  error_msg = ["Failed to set MTU"]
  msglist = slog_obj.show_logging(dut, severity='ERR', filter_list=error_msg)
  if msglist:
    st.log("Found the required error message in the logfile, continuing")
    return 1
  else:
    raise RuntimeError("Didnot observe the required error message({}) in the logfile.".format(error_msg))

def set_mtu_ping_verify(dut, dut2, intf, neigh_intf, mtu, afamily, sizes=[64, 1500, 8192]):
  '''
    1. Set the given mtu on an interface, and its neighbor as well.
    2. Verify that the given mtu is configured on the interface.
    3. Ping the interface's neighbor, and the interface itself.
    4. Check the counters to verify how many packets are getting counted.
    5.  number of packets should be = ping count * (ping size / mtu).

    Arguments:
      dut: The Device under test
      intf: The interface to test with.
      mtu:  The mtu to use.
      afamily: IPv4 or IPv6.
      sizes: Array of packet sizes to test.
  '''
  set_mtu(dut, intf, mtu)
  set_mtu(dut2, neigh_intf, mtu)
  verify_mtu(dut, intf, mtu)
  ping_count = 50

  for size in sizes:
    clear_counter(dut)
    ping_neighbor(dut, dut2, neigh_intf, afamily, ping_count, size)
    ping_local(dut, intf, afamily, ping_count, size)
    (rx_count, tx_count) = get_counters(dut, intf)
    st.log("set_mtu_ping_verify:ping_count={}, size={}, mtu={}".format(ping_count, size, mtu))
    packets_per_ping = math.ceil(float(size) / float(mtu-20))
    expected_packets = float(ping_count) * packets_per_ping
    check_value_in_range ("TX_OK", rx_count, expected_packets)
    check_value_in_range ("RX_OK", rx_count, expected_packets)

def set_mtu(dut, intf, mtu):
  '''
    Set the given mtu in the interface.
  '''
  st.config(dut, "config interface mtu {} {}".format(intf, mtu))

def verify_mtu(dut, intf, mtu):
  '''
    Verify that the given interface has the same mtu that is given.
  '''
  st.log("verify_mtu for {}:{}:{}".format(dut, intf, mtu))
  #output = st.show(dut, "show interface status | grep {} | awk '{{print $4}}'".format(intf))
  actual_mtu = get_mtu(dut, intf)
  if str(mtu) == actual_mtu:
    return True
  else:
    raise RuntimeError("The interface:{} in dut:{} has wrong mtu:{}, was expecting:{}".format(intf, dut, actual_mtu, mtu))
  raise RuntimeError("The interface:{} doesn't exist in dut:{}".format(intf, dut))

def clear_counter(dut):
  '''
    Clear all counters in the DUT.
  '''
  st.show(dut, "sonic-clear counter")

def get_counters(dut, intf):
  '''
    Get the values for rx/tx/drops for the given interface.
  '''
  st.log("get_counter for {}:{}".format(dut, intf))
  # This needed a fix in the templates.
  output = show_interfaces_counters(dut, interface=intf)
  st.debug ("counters:{}".format(output[0]))
  return (output[0]['rx_ok'], output[0]['tx_ok'])

def check_value_in_range(name, observed, expected, tolerance=0.1):
  min_value = expected * (1.0 - tolerance)
  max_value = expected * (1.0 + tolerance)
  msg = "The value for:{} is not within the expected range:expected:{}, observed:{}, req min:{}, req max:{}".format(name, expected, observed, min_value, max_value)
  st.debug("min_value = {}, max_value={}, observed={}".format(min_value, max_value, observed))
  assert int(min_value) < int(observed), msg
  assert int(max_value) > int(observed), msg

def ping_neighbor(dut, dut2, neigh_intf, af, count, size):
  ip_add = get_interface_ip_address(dut2, neigh_intf, af)[0]['ipaddr']
  ip_add = re.sub(r"/.*", "", ip_add)
  st.debug("get_interface_ip_address output = {}".format(ip_add))
  return st.show(dut, "sudo ping -c {} {} -i 0 -s {} -q".format(count, ip_add, size))

def ping_local(dut, intf, af, count, size):
  ip_add = get_interface_ip_address(dut, intf, family=af)[0]['ipaddr']
  ip_add = re.sub(r"/.*", "", ip_add)
  st.debug("get_interface_ip_address:{}".format(ip_add))
  #return ping(dut, addresses=ip_add, family=af, count=count)
  return st.show(dut, "sudo ping -c {} {} -i 0 -s {} -q".format(count, ip_add, size))

def get_mtu(dut, intf):
  output = interface_status_show(dut, interfaces=intf)
  st.log("output = {}".format(output))
  for line in output:
    if line['interface'] == intf:
      return line['mtu']

def check_orchagent(dut):
  output = get_ps_aux(dut, "orchagent | grep -v grep")
  if output:
    return True
  else:
    return False


