from spytest.dicts import SpyTestDict

data = SpyTestDict()

###Resource file variables
mask4='24'
mask6='64'
ipv4var='ipv4'
ipv6var='ipv6'
addvar='add'
delvar='del'
removevar='remove'
yesvar='yes'
novar='no'
notvar='Not'
disablevar='disabled'
disablevar2='disable'
enablevar='enable'
downvar='down'
upvar='up'
waitvar=5
rest_waitvar=1
stalevar='STALE'

gen_tech_support_flag=True
get_more_debugs_flag=True
#gen_tech_support_flag=False
#get_more_debugs_flag=False

data.tg_rate = '1000'
data.tg_count = '10'
data.convergence_acceptable = '10'

data.ip_1=['11.1.1.1', '11.1.1.10']
data.ip_1_nw=['11.1.1.0', '11.1.1.0'+'/'+mask4]
data.ip_2=['22.1.1.1', '22.1.1.10']
data.ip_2_nw=['22.1.1.0', '22.1.1.0'+'/'+mask4]
data.ip_3=['33.1.1.1', '33.1.1.10']
data.ip_3_nw=['33.1.1.0', '33.1.1.0'+'/'+mask4]
data.ip_4=['44.1.1.1', '44.1.1.10']
data.ip_4_nw=['44.1.1.0', '44.1.1.0'+'/'+mask4]
data.ip_12=['12.1.1.1', '12.1.1.2']
data.ip_13=['13.10.1.1', '13.10.1.3']
data.ip_13_2=['13.30.1.1', '13.30.1.3']
data.ip_14=['14.20.1.1', '14.20.1.4']
data.ip_14_2=['14.40.1.1', '14.40.1.4']
data.ip6_1=['2011:1::1:1', '2011:1::1:10']
data.ip6_1_nw=['2011:1::', '2011:1::'+'/'+mask6]
data.ip6_2=['2022:1::1:1', '2022:1::1:10']
data.ip6_2_nw=['2022:1::', '2022:1::'+'/'+mask6]
data.ip6_3=['2033:1::1:1', '2033:1::1:10']
data.ip6_3_nw=['2033:1::', '2033:1::'+'/'+mask6]
data.ip6_4=['2044:1::1:1', '2044:1::1:10']
data.ip6_4_nw=['2044:1::', '2044:1::'+'/'+mask6]
data.ip6_12=['2012:1::1:1', '2012:1::1:2']
data.ip6_13=['2013:10::1:1', '2013:10::1:3']
data.ip6_13_2=['2013:30::1:1', '2013:30::1:3']
data.ip6_14=['2014:20::1:1', '2014:20::1:4']
data.ip6_14_2=['2014:40::1:1', '2014:40::1:4']
data.mclag3_uip='13.30.1.2'
data.mclag4_uip='14.40.1.2'
data.mclag3_uip6='2013:30::1:2'
data.mclag4_uip6='2014:40::1:2'
data.vid_1='11'
data.vid_2='22'
data.vid_3='33'
data.vid_4='44'
data.vid_12='12'
data.vid_13='30'
data.vid_14='40'
data.vlan_1='Vlan'+data.vid_1
data.vlan_2='Vlan'+data.vid_2
data.vlan_3='Vlan'+data.vid_3
data.vlan_4='Vlan'+data.vid_4
data.vlan_12='Vlan'+data.vid_12
data.vlan_13='Vlan'+data.vid_13
data.vlan_14='Vlan'+data.vid_14
data.keepalive_ips=data.ip_12[:]
data.keepalive_ip6s=data.ip6_12[:]
data.keepalive_vid=data.vid_12
data.keepalive_vlan=data.vlan_12
data.po_peer='PortChannel2'
data.po_domainid='2'
data.mclag1='PortChannel10'
data.mclag1_ips=data.ip_13[:]
data.mclag1_ip6s=data.ip6_13[:]
data.mclag2='PortChannel20'
data.mclag2_ips=data.ip_14[:]
data.mclag2_ip6s=data.ip6_14[:]
data.mclag3='PortChannel30'
data.mclag3_ips=data.ip_13_2[:]
data.mclag3_ip6s=data.ip6_13_2[:]
data.mclag3_vid=data.vid_13
data.mclag3_vlan=data.vlan_13
data.mclag4='PortChannel40'
data.mclag4_ips=data.ip_14_2[:]
data.mclag4_ip6s=data.ip6_14_2[:]
data.mclag4_vid=data.vid_14
data.mclag4_vlan=data.vlan_14
data.mclag_all1=[data.mclag1, data.mclag2]
data.mclag_all2=[data.mclag3, data.mclag4]
data.mclag_all=data.mclag_all1+data.mclag_all2
data.mclag_vid_all=[data.mclag3_vid, data.mclag4_vid]
data.mclag_vlan_all=[data.mclag3_vlan, data.mclag4_vlan]

data.vrrp_vrid='30'
data.vrrp_vip=data.mclag3_ips[0][:-1]+'5'
data.vrrp_pri_m='32'
data.vrrp_pri_b='31'
data.vrrp_m_var='Master'
data.vrrp_b_var='Backup'

data.bgp_localas='100'
data.bgp_remoteas='200'
data.bgp_keepalive='3'
data.bgp_holdtime='9'

data.sag_mac='00:00:ba:ba:12:34'
data.sag_tg_mac='00:00:ca:ca:12:34'
data.sag_gwip=data.mclag3_ips[0][:-1]+'8'
data.sag_gwip6=data.mclag3_ip6s[0][:-1]+'8'
data.sag_dut4_ip=data.mclag3_ips[0][:-1]+'6'
data.sag_dut4_ip6=data.mclag3_ip6s[0][:-1]+'6'
data.sag_mclag3_gwip=data.sag_gwip
data.sag_mclag3_gwip6=data.sag_gwip6
data.sag_mclag4_gwip=data.mclag4_ips[0][:-1]+'8'
data.sag_mclag4_gwip6=data.mclag4_ip6s[0][:-1]+'8'

data.vrf1='Vrf1'

data.lt_name='linktrack_group1'
data.lt_uptime='10'
data.lt_intf_ip=['11.2.1.1', '11.2.1.10']

data.scale_mclag='500'
data.scale_vid='101'
data.scale_vlan='Vlan'+data.scale_vid
data.scale_mask4='16'
# Below to be used with unique-ip and SAG
# [leaf1_vlan_ip, leaf2_vlan_ip(for unique), sag_ip, leaf3_vlan_ip, client_ip]
data.scale_ips=['50.1.1.1', '50.1.1.2', '50.1.1.8', '50.1.1.3', '50.1.1.10']
data.scale_ip6s=['2013:50:1:1::1', '2013:50:1:1::2', '2013:50:1:1::8', '2013:50:1:1::3', '2013:50:1:1::10']
data.scale_ip_c2=data.mclag2_ips[0][:-3]+'2.1'
data.scale_ip6_c2=data.mclag2_ip6s[0][:-3]+'2:1'
data.scale_mac_c2='00:00:ad:da:12:34'
data.scale_mac6_c1='00:00:da:ad:12:34'
data.scale_mac_c1_2='00:00:de:ed:10:00'
data.scale_mac_o2_2='00:00:fe:ed:10:00'
data.scale_arp_c2='3500'
data.scale_ndp_c2=data.scale_arp_c2
data.scale_mac_c2_cnt='7000'
data.scale_mac_rate='3000'
data.scale_temp_vid='44'
data.scale_temp_vlan='Vlan'+data.scale_temp_vid

json_file='mclag_db.json'
frr_file='mclag_frr.conf'
data.cmd_cp_def_conf = 'sudo cp /etc/sonic/config_db.json /etc/sonic/'+json_file
data.cmd_restore_def_conf = 'sudo cp /etc/sonic/'+json_file+' /etc/sonic/config_db.json'
data.cmd_rm_json_conf = 'sudo rm /etc/sonic/'+json_file
data.cmd_cp_def_frr_conf = 'sudo cp /etc/sonic/frr/frr.conf /etc/sonic/frr/'+frr_file
data.cmd_restore_def_frr_conf = 'sudo cp /etc/sonic/frr/'+frr_file+' /etc/sonic/frr/frr.conf'
data.cmd_rm_frr_conf = 'sudo rm /etc/sonic/frr/'+frr_file

data.po_data={}
data.po_data['leaf1'] = {
    'domain_id': data.po_domainid,
    'local_ip': data.keepalive_ips[0],
    'peer_ip': data.keepalive_ips[1],
    'session_status': 'OK',
    'peer_link_inf': data.po_peer,
    'node_role': 'Active',
    'mclag_intfs': 4
}
data.po_data['leaf2'] = {
    'domain_id': data.po_domainid,
    'local_ip': data.keepalive_ips[1],
    'peer_ip': data.keepalive_ips[0],
    'session_status': 'OK',
    'peer_link_inf': data.po_peer,
    'node_role': 'Standby',
    'mclag_intfs': 4
}
data.po_data2={}
data.po_data2['leaf1'] = {
    'domain_id': data.po_domainid,
    'local_ip': data.keepalive_ips[0],
    'peer_ip': data.keepalive_ips[1],
    'session_status': 'OK',
    'peer_link_inf': data.po_peer,
    'node_role': 'Active',
    'mclag_intfs': 2
}
data.po_data2['leaf2'] = {
    'domain_id': data.po_domainid,
    'local_ip': data.keepalive_ips[1],
    'peer_ip': data.keepalive_ips[0],
    'session_status': 'OK',
    'peer_link_inf': data.po_peer,
    'node_role': 'Standby',
    'mclag_intfs': 2
}
data.mclag1_intf_data={}
data.mclag1_intf_data['leaf1'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag1,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'No'
}
data.mclag1_intf_data['leaf2'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag1,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'No'
}
data.mclag2_intf_data={}
data.mclag2_intf_data['leaf1'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag2,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'No'
}
data.mclag2_intf_data['leaf2'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag2,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'No'
}
data.mclag3_intf_data={}
data.mclag3_intf_data['leaf1'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag3,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'No'
}
data.mclag3_intf_data['leaf2'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag3,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'No'
}
data.mclag3_intf_data2={}
data.mclag3_intf_data2['leaf1'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag3,
    'mclag_intf_local_state':'Down',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'Yes'
}
data.mclag3_intf_data2['leaf2'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag3,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Down',
    'isolate_peer_link':'No',
    'traffic_disable':'No'
}
data.mclag4_intf_data={}
data.mclag4_intf_data['leaf1'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag4,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'No'
}
data.mclag4_intf_data['leaf2'] = {
    'domain_id': data.po_domainid,
    'mclag_intf': data.mclag4,
    'mclag_intf_local_state':'Up',
    'mclag_intf_peer_state':'Up',
    'isolate_peer_link':'Yes',
    'traffic_disable':'No'
}
data.mclag3_vlan_data={}
data.mclag3_vlan_data['leaf1'] = {
    'vlan': data.mclag3_vlan,
    'unique_ip': 'Yes'
}
data.mclag3_vlan_data['leaf2'] = {
    'vlan': data.mclag3_vlan,
    'unique_ip': 'Yes'
}
data.mclag4_vlan_data={}
data.mclag4_vlan_data['leaf1'] = {
    'vlan': data.mclag4_vlan,
    'unique_ip': 'Yes'
}
data.mclag4_vlan_data['leaf2'] = {
    'vlan': data.mclag4_vlan,
    'unique_ip': 'Yes'
}
