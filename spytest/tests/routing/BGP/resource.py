from spytest.dicts import SpyTestDict


def resource_data(vars):
    data = SpyTestDict()
    ##############################################################################################
    # For N:N topology, define the Leaf Spine mapping as example show below for 1:1 topology.
    ##############################################################################################
    data.leaf_routers = ['leaf1']
    data.spine_routers = ['spine1']

    data.leaf1 = vars.D2
    data.spine1 = vars.D1

    data['l3_max_links_leaf_spine'] = 1
    data['l3_max_tg_links_each_leaf_spine'] = 1

    '''
    ##############################################################################################
    # For N:N topology, define the Leaf Spine mapping as example show below for 2:2 topology.
    ##############################################################################################
    data.leaf_routers = ['leaf1','leaf2']
    data.spine_routers = ['spine1','spine2']
    
    data.spine1 = vars.D1
    data.spine2 = vars.D2
    data.leaf1 = vars.D3
    data.leaf2 = vars.D4
    
    data['l3_max_links_leaf_spine'] = 2
    data['l3_max_tg_links_each_leaf_spine'] = 1
    '''


    ##############################################################################################
    #  Independent variable w.r.t topology
    ##############################################################################################
    data['mac_addres_tg_src_spine'] = '00:00:01:01:00:01'
    data['mac_addres_tg_src_leaf'] = '00:00:02:02:00:01'

    data['ipv4_addres_first_octet'] = '11'
    data['ipv6_addres_first_octet'] = '67fe'
    data['ipv4_nw_addres_first_octet'] = '12'
    data['ipv6_nw_addres_first_octet'] = '6712'
    data['ipv4_static_addres_first_octet'] = '13'
    data['ipv6_static_addres_first_octet'] = '6713'

    data['ipv4_addres_first_octet_tg_spine'] = '192'
    data['ipv6_addres_first_octet_tg_spine'] = '1092'
    data['ipv4_addres_first_octet_tg_leaf'] = '193'
    data['ipv6_addres_first_octet_tg_leaf'] = '1093'

    # starting vlanid for creating ve over phy, or ve over lag
    data['start_vlan_id'] = 11

    # start lag id for portchannel interfaces [For ve over lag or lag phy interfaces]
    data['start_lag_id'] = 11

    ##############################################################################################
    # This is CLOS based Leaf-Spine topology, where all Spine nodes have same AS number
    # and all Leaf nodes have the same AS numbers, this is inline with various deployments.
    ##############################################################################################
    data['spine_as'] = 65001
    # Fixing 4-byte value for leaf_as
    data['leaf_as'] = 650002

    data['spine_tg_as'] = 64001
    data['leaf_tg_as'] = 63001

    return data
