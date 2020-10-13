import json
import sys
from spytest import st

def config_port_qos_map(dut,obj_name,interface):
        st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))

        final_data = dict()
        temp_data = dict()
        if not obj_name or not interface:
                st.log("Please provide obj_name like 'AZURE' and interface like 'Ethernet0,Ethernet1'")
                return False
        else:
                cos_specific_dict = {"tc_to_queue_map": "[TC_TO_QUEUE_MAP|" + obj_name + "]", "dscp_to_tc_map": "[DSCP_TO_TC_MAP|" + obj_name + "]" }
                temp_data[interface] = cos_specific_dict
        final_data['PORT_QOS_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
        return True

def config_tc_to_queue_map(dut,obj_name,tc_to_queue_map_dict):
        st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))

        final_data = dict()
        temp_data = dict()
        if not tc_to_queue_map_dict or not obj_name:
                st.log("Please provide traffic class to queue map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
                return False
        else:
                temp_data[obj_name] = tc_to_queue_map_dict
        final_data['TC_TO_QUEUE_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
        return True

def config_dscp_to_tc_map(dut,obj_name,dscp_to_tc_map_dict):
        st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))

        final_data = dict()
        temp_data = dict()
        if not dscp_to_tc_map_dict or not obj_name:
                st.log("Please provide dscp value to traffic priority value map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
                return False
        else:
                temp_data[obj_name] = dscp_to_tc_map_dict
        final_data['DSCP_TO_TC_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
        return True

def config_tc_to_pg_map(dut,obj_name,tc_to_pg_map_dict):
        st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))

        final_data = dict()
        temp_data = dict()
        if not tc_to_pg_map_dict or not obj_name:
                st.log("Please provide traffic class to priority group map dict. For example - {'0':'0', '1':'1', ...} and Object name like 'AZURE'")
                return False
        else:
                temp_data[obj_name] = tc_to_pg_map_dict
        final_data['TC_TO_PRIORITY_GROUP_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json(dut, final_data)
        return True
