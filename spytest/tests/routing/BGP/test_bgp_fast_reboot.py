import pytest

from spytest import st, tgapi, SpyTestDict

import apis.system.reboot as reboot_obj
import apis.routing.ip as ip_obj
import apis.routing.bgp as bgp_obj
import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj

data = SpyTestDict()
data.local_ip_addr = "12.12.12.1"
data.neigh_ip_addr = "12.12.12.2"
data.local_ip6_addr = "3241::1"
data.neigh_ip6_addr = "3241::2"
data.router_id_1 = "110.110.110.1"
data.router_id_2 = "120.120.120.1"
data.loopback_1 = "66.66.66.66"
data.loopback_2 = "77.77.77.77"
data.af_ipv4 = "ipv4"
data.af_ipv6 = "ipv6"
data.shell_sonic = "sonic"
data.shell_vtysh = "vtysh"
data.d1t1_ip_addr = "192.168.0.1"
data.t1d1_ip_addr = "192.168.0.2"
data.d1t1_ip_addr_mask = "16"
data.d1t1_ip6_addr = '2001::1'
data.t1d1_ip6_addr = '2001::100'
data.d1t1_ip6_addr_mask = '64'
data.af_ipv4 = "ipv4"
data.af_ipv6 = "ipv6"
data.local_asn = "4294966195"
data.tg_bgp_route_prfix = "157.1.0.0"
data.local_asn4 = "4294966195"
data.remote_asn4 = "65001"
data.ipv6_support = True
data.neighborship_wait = 10

@pytest.fixture(scope="module", autouse=True)
def bgp_fast_reboot_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:1", "D1T1:2")
    if not st.is_feature_supported("bgp-neighbotship-performance", vars.D1):
        data.neighborship_wait = 30

    st.log("Enabling IPv6 mode globally")
    ip_obj.config_ipv6(vars.D1,action='enable')
    ip_obj.config_ipv6(vars.D2,action='enable')

    st.log("Configuring ipv4 addresses on routing interfaces")
    ipv4_ip_address_config()

    st.log("Verifying ipv4 addresses on routing interfaces")
    verify_ipv4_address_config()

    if data.ipv6_support:
        st.log("Configuring ipv6 addresses on routing interfaces")
        ipv6_address_config()
        st.log("Verifying ipv6 addresses on routing interfaces")
        verify_ipv6_address_config()
        st.log("Configuring IPV6 eBGP config between DUT1 and DUT2,iBGP config between DUT1 and TG2")
        ipv6_bgp_config()

    st.log("Configuring IPV4 eBGP config between DUT1 and DUT2,iBGP config between DUT1 and TG1")
    ipv4_bgp_config()

    if data.ipv6_support:
        st.log("Configuring TG2 V6 iBGP config")
        tg_bgpv6_config(vars, data.local_asn4, data.remote_asn4)

    st.log("Configuring TG1 V4 iBGP config")
    tg_bgp_config(vars, data.local_asn4, data.remote_asn4)

    st.log("Verify IPV4 eBGP neighborship between D1 and D2 and iBGP neighborship between D1 and TG1")
    verify_v4_bgp_neigborship()

    if data.ipv6_support:
        st.log("Verify IPV6 eBGP neighborship between D1 and D2 and iBGP neighborship between D1 and TG2")
        verify_v6_bgp_neigborship()

    yield

    bgp_obj.cleanup_router_bgp(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names())

    if data.ipv6_support:
        ip_obj.clear_ip_configuration(st.get_dut_names(), 'ipv6')

    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names())


@pytest.fixture(scope="function", autouse=True)
def bgp_fast_reboot_func_hooks(request):
    yield


def ipv4_ip_address_config():
    st.log("Creating the ipv4 routing interfaces in {}".format(vars.D1))
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1D2P1, data.local_ip_addr, 30, family=data.af_ipv4)

    st.log("Creating the ipv4 routing interfaces in {}".format(vars.D2))
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.neigh_ip_addr, 30, family=data.af_ipv4)

    st.log("Creating the ipv4 routing interfaces on TG1 {}".format(vars.D1T1P1))
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.d1t1_ip_addr,
                                    data.d1t1_ip_addr_mask, family=data.af_ipv4)


def verify_ipv4_address_config():
    st.log("Verify ipv4 address on routing interface  {} in D1".format(vars.D1D2P1))
    if not ip_obj.verify_interface_ip_address(vars.D1, vars.D1D2P1, "{}/30".format(data.local_ip_addr), data.af_ipv4):
        st.report_fail('ip_routing_int_create_fail', vars.D1D2P1)
    else:
        st.log(" IPV4 Addres Config is successful")
    st.log("Verify ipv4 address on routing interface {} in D2".format(vars.D1D2P1))
    if not ip_obj.verify_interface_ip_address(vars.D2, vars.D2D1P1, "{}/30".format(data.neigh_ip_addr), data.af_ipv4):
        st.report_fail('ip_routing_int_create_fail', vars.D2D1P1)
    else:
        st.log(" IPV4 Addres Config is successful")
    st.log("Verify ipv4 address on routing interface {} in D1".format(vars.D1T1P1))
    if not ip_obj.verify_interface_ip_address(vars.D1, vars.D1T1P1,
                                              "{}/{}".format(data.d1t1_ip_addr, data.d1t1_ip_addr_mask),
                                              data.af_ipv4):
        st.report_fail('ip_routing_int_create_fail', vars.D1T1P1)
    else:
        st.log(" IPV4 Addres Config is successful")


def ipv6_address_config():
    st.log("Creating the ipv6 routing interfaces in {}".format(vars.D1D2P1))
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1D2P1, data.local_ip6_addr, 96, family=data.af_ipv6)

    st.log("Creating the ipv6 routing interfaces in {}".format(vars.D2D1P1))
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2D1P1, data.neigh_ip6_addr, 96, family=data.af_ipv6)

    st.log("Creating the ipv6 routing interfaces on TG2 interface {}".format(vars.D1T1P2))
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.d1t1_ip6_addr, data.d1t1_ip6_addr_mask,
                                    family=data.af_ipv6)


def verify_ipv6_address_config():
    st.log("Verify ipv6 address on routing interface  {} in D1".format(vars.D1D2P1))
    if not ip_obj.verify_interface_ip_address(vars.D1, vars.D1D2P1, "{}/96".format(data.local_ip6_addr), data.af_ipv6):
        st.report_fail('ip6_routing_int_create_fail', vars.D1D2P1)
    else:
        st.log(" IPV6 Addres Config is successful")
    st.log("Verify ipv6 address on routing interface  {} in D2".format(vars.D2D1P1))
    if not ip_obj.verify_interface_ip_address(vars.D2, vars.D2D1P1, "{}/96".format(data.neigh_ip6_addr), data.af_ipv6):
        st.report_fail('ip6_routing_int_create_fail', vars.D2D1P1)
    else:
        st.log(" IPV6 Addres Config is successful")
    st.log("Verify ipv6 address on routing interface  {} in D1".format(vars.D1T1P2))
    if not ip_obj.verify_interface_ip_address(vars.D1, vars.D1T1P2,
                                              "{}/{}".format(data.d1t1_ip6_addr, data.d1t1_ip6_addr_mask),
                                              data.af_ipv6):
        st.report_fail('ipv6_routing_int_create_fail', vars.D1T1P2)
    else:
        st.log(" IPV6 Addres Config is successful")


def ipv4_bgp_config():
    st.log("Creating the eBGP ipv4 neighbors in {}".format(vars.D1))
    bgp_obj.create_bgp_router(vars.D1, data.local_asn4, data.router_id_1)
    bgp_obj.config_address_family_redistribute(vars.D1, data.local_asn4, data.af_ipv4, "unicast", "connected")
    bgp_obj.create_bgp_neighbor(dut=vars.D1, local_asn=data.local_asn4, neighbor_ip=data.neigh_ip_addr,
                                remote_asn=data.remote_asn4, family=data.af_ipv4)

    st.log("Creating the eBGP ipv4 neighbors in {}".format(vars.D2))
    bgp_obj.create_bgp_router(vars.D2, data.remote_asn4, data.router_id_2)
    bgp_obj.config_address_family_redistribute(vars.D2, data.remote_asn4, data.af_ipv4, "unicast", "connected")
    bgp_obj.create_bgp_neighbor(dut=vars.D2, local_asn=data.remote_asn4, neighbor_ip=data.local_ip_addr,
                                remote_asn=data.local_asn4, family=data.af_ipv4)

    st.log("Creating the iBGP ipv4 neighbors with TG1 {}".format(vars.D1T1P1))
    bgp_obj.create_bgp_router(vars.D1, data.local_asn4, data.router_id_1)
    bgp_obj.config_address_family_redistribute(vars.D1, data.local_asn4, data.af_ipv4, "unicast", "connected")
    bgp_obj.create_bgp_neighbor(dut=vars.D1, local_asn=data.local_asn4, neighbor_ip=data.t1d1_ip_addr,
                                remote_asn=data.local_asn4, family=data.af_ipv4)


def ipv6_bgp_config():
    st.log("Creating the eBGP ipv6 neighbors in {}".format(vars.D1))
    bgp_obj.create_bgp_router(vars.D1, data.local_asn4, data.router_id_1)
    bgp_obj.config_address_family_redistribute(vars.D1, data.local_asn4, data.af_ipv6, "unicast", "connected")
    bgp_obj.create_bgp_neighbor(dut=vars.D1, local_asn=data.local_asn4, neighbor_ip=data.neigh_ip6_addr,
                                remote_asn=data.remote_asn4, family=data.af_ipv6)
    st.log("Creating the eBGP ipv6 neighbors in {}".format(vars.D2))
    bgp_obj.create_bgp_router(vars.D2, data.remote_asn4, data.router_id_2)
    bgp_obj.config_address_family_redistribute(vars.D2, data.remote_asn4, data.af_ipv6, "unicast", "connected")
    bgp_obj.create_bgp_neighbor(dut=vars.D2, local_asn=data.remote_asn4, neighbor_ip=data.local_ip6_addr,
                                remote_asn=data.local_asn4, family=data.af_ipv6)

    st.log("Creating the iBGP ipv6 neighbors with TG2 {}".format(vars.D1))
    bgp_obj.create_bgp_router(vars.D1, data.local_asn4, data.router_id_1)
    bgp_obj.create_bgp_neighbor(dut=vars.D1, local_asn=data.local_asn4, neighbor_ip='2001::100',
                                remote_asn=data.local_asn4, family=data.af_ipv6)


def tg_bgp_config(vars, local_asn, remote_asn):
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)

    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,
                                 gateway=data.d1t1_ip_addr,
                                 src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    # Configuring BGP device on top of interface.
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', active_connect_enable='1',
                                           local_as=data.local_asn4,
                                           remote_as=data.local_asn4, remote_ip_addr=data.d1t1_ip_addr,
                                           enable_4_byte_as='1')
    st.log("BGPCONF: " + str(bgp_conf))
    # Adding routes to BGP device.
    bgp_route = tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', num_routes='100',
                                                  prefix='172.168.1.0')
    st.log("BGPROUTE: " + str(bgp_route))
    return True


def tg_bgpv6_config(vars, local_asn, remote_asn):
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)
    h1 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.t1d1_ip6_addr, \
                                 ipv6_prefix_length='64', ipv6_gateway=data.d1t1_ip6_addr,
                                 src_mac_addr='00:0a:01:00:00:01', \
                                 arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    st.log("Configuring BGP device on top of interface")
    bgp_conf = tg2.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6', \
                                           active_connect_enable='1', local_as=data.local_asn4, \
                                           remote_as=data.local_asn4, remote_ipv6_addr=data.d1t1_ip6_addr,
                                           enable_4_byte_as='1')
    st.log("BGPCONF: " + str(bgp_conf))
    st.log("Adding routes to BGP device")
    bgp_route = tg2.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6',
                                                  num_routes='100', prefix='1001::0')
    st.log("BGPROUTE: " + str(bgp_route))
    return True


def verify_v4_bgp_neigborship():
    st.wait(data.neighborship_wait, "wait for bgp v4 neighborship")
    st.log("Waiting for the eBGP neighbors to get Established")
    if not bgp_obj.verify_bgp_neighborship(vars.D1, family=data.af_ipv4, shell=data.shell_vtysh,
                                      neighbor=data.neigh_ip_addr, state='Established', asn=data.remote_asn4):
        st.report_fail('bgp_ip_peer_establish_fail', data.neigh_ip_addr)
    else:
        st.log("eBGP peer neigborship is successful")
    if not bgp_obj.verify_bgp_neighborship(vars.D2, family=data.af_ipv4, shell=data.shell_vtysh,
                                      neighbor=data.local_ip_addr, state='Established', asn=data.local_asn4):
        st.report_fail('bgp_ip_peer_establish_fail', data.local_ip_addr)
    else:
        st.log("eBGP V4 peer neigborship is successful")

    st.log("Waiting for the iBGP neighbors to get Established with TG1")
    if not bgp_obj.verify_bgp_neighborship(vars.D1, family=data.af_ipv4, shell=data.shell_vtysh,
                                      neighbor=data.t1d1_ip_addr, state='Established', asn=data.local_asn4):
        st.report_fail('bgp_ip_peer_establish_fail', data.t1d1_ip_addr)
    else:
        st.log("iBGP V4 peer neigborship is successful")

def verify_v6_bgp_neigborship():
    st.wait(data.neighborship_wait, "wait for bgp v6 neighborship")
    st.log("Waiting for the eBGP neighbors to get Established with peer DUT")
    if not bgp_obj.verify_bgp_neighborship(vars.D1, family=data.af_ipv6, shell=data.shell_vtysh,
                                      neighbor=data.neigh_ip6_addr, state='Established', asn=data.remote_asn4):
        st.report_fail('bgp_ip6_peer_establish_fail', data.neigh_ip6_addr)
    else:
        st.log("eBGP V6 peer neigborship is successful")
    if not bgp_obj.verify_bgp_neighborship(vars.D2, family=data.af_ipv6, shell=data.shell_vtysh,
                                      neighbor=data.local_ip6_addr, state='Established', asn=data.local_asn4):
        st.report_fail('bgp_ip6_peer_establish_fail', data.local_ip6_addr)
    else:
        st.log("eBGP V6 peer neigborship is successful")

        st.log("Waiting for the iBGPV6 neighbors to get Established with TG2")
    if not bgp_obj.verify_bgp_neighborship(vars.D1, family=data.af_ipv6, shell=data.shell_vtysh,
                                      neighbor=data.t1d1_ip6_addr, state='Established', asn=data.local_asn4):
        st.report_fail('bgp_ip_peer_establish_fail', data.t1d1_ip6_addr)
    else:
        st.log("iBGP V6 peer neigborship is successful")


@pytest.mark.bgp_fast_reboot
def test_ft_bgp_fast_reboot():
    st.log("Enabling docker routing config mode in D1 and D2")
    bgp_obj.enable_docker_routing_config_mode(vars.D1)
    bgp_obj.enable_docker_routing_config_mode(vars.D2)
    st.log("saving the BGP config in vtysh shell")
    st.log("config save in D1 and D2")
    reboot_obj.config_save([vars.D1, vars.D2])
    st.log("Performing fast reboot")
    st.reboot(vars.D1,"fast")
    st.log("Verifying BGP is established after fast reboot")
    verify_v4_bgp_neigborship()
    if data.ipv6_support:
        st.log("Verifying BGPV6 is  established after fast reboot")
        verify_v6_bgp_neigborship()
    st.report_pass('test_case_passed')

