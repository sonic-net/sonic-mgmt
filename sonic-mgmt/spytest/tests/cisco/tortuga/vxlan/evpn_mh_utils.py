from spytest import st
import utilities.utils as utils_obj
import json

def es_peering(dut, peer_ip, esi): 
    peering_state = False
    cmd = 'show evpn es'
    cmd_output = st.vtysh_show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_evpn_es.tmpl')
    
    for es in parsed_output:
        if es['esi'] == esi and 'L' in es['type'] and 'R' in es['type'] and peer_ip in es['vteps'].split(',') and len(es['vteps'].split(',')) == 1 :
            peering_state = True

    return peering_state

def isDF(dut, esi):
    cmd = 'show evpn es'
    isDF = True
    cmd_output = st.vtysh_show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_evpn_es.tmpl')
        
    for es in parsed_output:
        if es['esi'] == esi and 'L' in es['type']:
            if 'N' in es['type']:
                isDF = False
            break                      
    st.log("{} is DF: {}".format(dut, isDF))
    return isDF

def get_df_ndf_node(dut1, dut2, esi):
    node1_isDF = isDF(dut1, esi)
    node2_isDF = isDF(dut2, esi)
    
    df_node = ndf_node = None

    if node1_isDF and not node2_isDF:
        df_node = dut1
        ndf_node = dut2
    elif (not node1_isDF) and node2_isDF:
        df_node = dut2
        ndf_node = dut1
        
    return df_node, ndf_node

def change_fdb_ageout(ageout_time = "600", skip_duts_with = ""):
    # Define the JSON content to be written to the file
    data = [
        {
            "SWITCH_TABLE:switch": {
                "fdb_aging_time": ageout_time
            },
            "OP": "SET"
        }
    ]

    # Specify the filename
    basename = 'ageout.json'
    filename = '/tmp/' + basename

    # Write the JSON content to the file
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

    st.log("File {} has been created with the specified content.".format(filename))
    for dut in st.get_dut_names():
        if "leaf" in dut or (skip_duts_with and not skip_duts_with in dut):
            utils_obj.copy_files_to_dut(dut, [filename], '/home/cisco')
            st.config(dut,"docker cp /home/cisco/ageout.json swss:/",sudo=False, split_cmds=False)
            st.config(dut,"docker exec -it swss swssconfig ageout.json",sudo=False, split_cmds=False)
            st.show(dut, 'sonic-db-dump -n APPL_DB -k *SWITCH_TABLE:switch* -y', skip_tmpl=True, skip_error_check=True)
