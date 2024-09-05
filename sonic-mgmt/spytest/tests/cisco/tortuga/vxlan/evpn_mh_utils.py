from spytest import st

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
