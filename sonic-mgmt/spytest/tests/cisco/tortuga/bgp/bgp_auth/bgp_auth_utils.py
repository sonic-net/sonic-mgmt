from spytest import st, tgapi
import yaml
import os
import re

def check_neigh_state(node, peergroup = None, vrf = None, neighbor = ''):
    cmd = 'show bgp neighbor ' + neighbor
    if vrf:
        cmd = 'show bgp vrf ' + vrf + ' neighbor'
    cmd_output = st.vtysh_show(node, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(node, cmd, cmd_output,'show_bgp_neighbor.tmpl')
    st.dut_log(node, parsed_output)
    
    bgp_up = True
    if not parsed_output:
        return False
        
    if peergroup is None:
        for nei in parsed_output:
            if nei['state'] != 'Established':
                bgp_up = False
    else:
        for nei in parsed_output:
            if nei['peergroup'] == peergroup and nei['state'] != 'Established':
                bgp_up = False
            
    return bgp_up

def modify_config_file(config_file,var_dict):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    
    '''
    output_yaml_file = "temp_config.yaml"
    input_yaml_file = config_file
    dir_path = os.path.dirname(os.path.realpath(__file__))+"/"
    result = os.system("cp {0}{1} {0}{2}".format(dir_path,input_yaml_file,output_yaml_file))
    if result != 0:
        st.report_fail("config file copy failed")
    st.wait(2)
    for item, value in var_dict.items():
        if re.match("(D.D.P.)|(D.T.P.)", item):
            find_and_replace(dir_path+output_yaml_file, item, value)
    return dir_path+output_yaml_file

def find_and_replace(file_path, target_string, replacement_string):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    # Iterate through the YAML data recursively
    def replace_string(obj):
        if isinstance(obj, str):
            return obj.replace(target_string, replacement_string)
        elif isinstance(obj, dict):
            return {key: replace_string(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [replace_string(item) for item in obj]
        else:
            return obj
    updated_data = replace_string(data)
    with open(file_path, 'w') as file:
        yaml.dump(updated_data, file)
        
       
def remove_temp_config(updated_config_file):
    os.system("rm {}".format(updated_config_file))