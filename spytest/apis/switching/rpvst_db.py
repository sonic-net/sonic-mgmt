from spytest import st
from spytest.utils import filter_and_select
import json

from apis.common import redis
import apis.system.switch_configuration as sconf_obj
import apis.switching.stp as stp_obj
import apis.switching.vlan as vlan_obj

debug_log_path = r"/var/log/stplog"

g_vlan_id = 100
g_port1 = "Ethernet24"

g_def_fwd_delay = 15
g_def_max_age = 20
g_def_hello_time = 2
g_def_priority = 32768
g_def_intf_priority = 128
g_def_cost = 2000

g_fwd_delay = 20
g_max_age = 25
g_hello_time = 8
g_priority = 4096
g_intf_priority = 200
g_cost = 20000

default_stp_global_cfg = {
   "STP": {
      "GLOBAL": {
         "forward_delay": "15",
         "hello_time": "2",
         "max_age": "20",
         "mode": "rpvst",
         "priority": "32768",
         "rootguard_timeout": "30"
      }
   }
}

def config_spanning_tree_rpvst(dut, skip_verify=True, **kwargs):
   """
   :param dut:
   :param kwargs:
   :param skip_verify: True(Default) / False
   :return:

   Ex: config_spanning_tree_rpvst(1, field='mode', cfg_value='rpvst')
   """

   st.log("Configuring RPVST...")
   rpvst_data = kwargs

   # if STP is already configured on the DUT, just update the given field
   # rest of the fields should not be affected
   current_stp = sconf_obj.get_running_config(dut, "STP")

   if current_stp:
      stp_cfg = default_stp_global_cfg
      # current_value = sconf_obj.get_running_config(dut,"STP","GLOBAL",rpvst_data['field'])

      if rpvst_data['field'] in current_stp['GLOBAL']:
         stp_cfg['STP']['GLOBAL'][rpvst_data['field']] = rpvst_data['cfg_value']

      excluded_keys = rpvst_data['field']
      for key, _ in current_stp['GLOBAL'].items():
         if key not in excluded_keys:
            stp_cfg['STP']['GLOBAL'][key] = current_stp['GLOBAL'][key]

   else:
      stp_cfg = default_stp_global_cfg

   json_cfg = json.dumps(stp_cfg)
   json.loads(json_cfg)

   st.apply_json2(dut, json_cfg)
   return True

def config_spanning_tree_rpvst_intf(dut, skip_verify=True, **kwargs):
   """
   :param dut:
   :param kwargs:
   :param skip_verify: True(Default) / False
   :return:

   Ex: config_spanning_tree_rpvst(1, ifname, field='edge_port', cfg_value='true')
   """

   st.log("Configuring RPVST interface parameters...")
   rpvst_data = kwargs
   stp_cfg = dict()

   # if STP is already configured on the DUT, just update the given field
   # rest of the fields should not be affected
   current_stp = sconf_obj.get_running_config(dut, "STP_PORT")
   stp_cfg['STP_PORT'] = current_stp

   if current_stp:
      if rpvst_data['ifname'] in current_stp:
         #if rpvst_data['field'] in current_stp[rpvst_data['ifname']]:
         #any existing field is updated. New field will get added to the config_db
         stp_cfg['STP_PORT'][rpvst_data['ifname']][rpvst_data['field']] = rpvst_data['cfg_value']
         #else:
         #   st.error("field {} does not exist".format(rpvst_data['field']))
         #   return False
      else:
         st.error("interface {} does not exist".format(rpvst_data['ifname']))
         return False
   else:
      st.error("STP interface configuration does not exist")
      return False

   json_cfg = json.dumps(stp_cfg)
   json.loads(json_cfg)

   st.apply_json2(dut, json_cfg)
   return True


def verify_stp_entry_db(dut, table, vlan = None, ifname = None, **kwargs):
   """
   """
   if table == "_STP_VLAN_INTF_TABLE":
      cmd = "Vlan"+str(vlan)
      string = "{}:{}:{}".format(table, cmd, ifname)
   elif table == "_STP_PORT_TABLE":
      string = "{}:{}".format(table, ifname)
   else:
      print("invalid table")
      return False

   print("string is-")
   print(string)

   command = redis.build(dut, redis.APPL_DB, "hgetall {}".format(string))
   print("command is -", command)

   output = st.show(dut, command)
   print("output is -")
   print(output)
   st.debug(output)

   print("kwargs: ", kwargs)

   for each in kwargs.keys():
      match = {each: kwargs[each]}
      entries = filter_and_select(output, None, match)
      print("match :", match)
      print("entries:", entries)
      if not entries:
         st.log("{} and {} do not match ".format(each, kwargs[each]))
         return False
   return True

def verify_rpvst_global_config(dut):

  if not sconf_obj.verify_running_config(dut, "STP", "GLOBAL", "mode"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP", "GLOBAL", "forward_delay"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP", "GLOBAL", "hello_time"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP", "GLOBAL", "max_age"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP", "GLOBAL", "priority"):
    return False

  return True

def verify_rpvst_vlan_config(dut, vlan_id):
  cmd = "Vlan" + str(vlan_id)

  if not sconf_obj.verify_running_config(dut, "STP_VLAN", cmd, "enable"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_VLAN", cmd, "forward_delay"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_VLAN", cmd, "hello_time"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_VLAN", cmd, "max_age"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_VLAN", cmd, "priority"):
    return False

  return True

def verify_rpvst_intf_config(dut, ifname):

  if not sconf_obj.verify_running_config(dut, "STP_PORT", ifname, "enable"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_PORT", ifname, "bpdu_guard"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_PORT", ifname, "root_guard"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_PORT", ifname, "priority"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_PORT", ifname, "cost"):
    return False

  return True

def verify_rpvst_intf_config_db(dut, ifname):

  if not sconf_obj.verify_running_config(dut, "STP_PORT", ifname, "edge_port", "true"):
    return False

  if not sconf_obj.verify_running_config(dut, "STP_PORT", ifname, "link_type", "point-to-point"):
    return False

  return True

def config_rpvst_global(dut):
  config_spanning_tree_rpvst(dut, field='mode', cfg_value='rpvst')
  config_spanning_tree_rpvst(dut, field='forward_delay', cfg_value=g_fwd_delay)
  config_spanning_tree_rpvst(dut, field='hello_time', cfg_value=g_hello_time)
  config_spanning_tree_rpvst(dut, field='max_age', cfg_value=g_max_age)
  config_spanning_tree_rpvst(dut, field='priority', cfg_value=g_priority)

  return True

def config_rpvst_vlan(dut, mode, vlan_id, new_fwd_delay, new_hello_time, new_max_age, new_priority):

  vlan_obj.create_vlan(dut, g_vlan_id)
  vlan_obj.add_vlan_member(dut, g_vlan_id, port_list=[g_port1], tagging_mode=True)

  stp_obj.config_stp_vlan_param(dut, cfgdictionary={'': [mode, str(vlan_id)]})
  stp_obj.config_stp_vlan_param(dut, cfgdictionary={'forward_delay': [str(vlan_id), str(new_fwd_delay)]})
  stp_obj.config_stp_vlan_param(dut, cfgdictionary={'hello': [str(vlan_id), str(new_hello_time)]})
  stp_obj.config_stp_vlan_param(dut, cfgdictionary={'max_age': [str(vlan_id), str(new_max_age)]})
  stp_obj.config_stp_vlan_param(dut, cfgdictionary={'priority': [str(vlan_id), str(new_priority)]})

  return True

def config_rpvst_intf(dut, mode, ifname, priority, cost):
  stp_obj.config_stp_intf_param(dut, cfgdictionary={'' : [mode, ifname]})
  stp_obj.config_stp_intf_param(dut, cfgdictionary={'bpdu_guard' : ['enable', '-s', ifname]})
  stp_obj.config_stp_intf_param(dut, cfgdictionary={'root_guard' : ['enable', ifname]})
  stp_obj.config_stp_intf_param(dut, cfgdictionary={'uplink_fast' : ['enable', ifname]})
  stp_obj.config_stp_intf_param(dut, cfgdictionary={'priority' : [ifname, str(priority)]})
  stp_obj.config_stp_intf_param(dut, cfgdictionary={'cost' : [ifname, str(cost)]})

  return True

def config_rpvst_intf_db(dut, interface):
  config_spanning_tree_rpvst_intf(dut, field='edge_port', cfg_value='true', ifname = interface)
  config_spanning_tree_rpvst_intf(dut, field='link_type', cfg_value='point-to-point', ifname = interface)
  return True
