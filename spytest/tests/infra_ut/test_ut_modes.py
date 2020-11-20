import pytest
from spytest import st

@pytest.fixture(scope="module", autouse=True)
def ut_modes_module_hooks(request):
    #add things at the start of this module
    yield
    #add things at the end of this module"

@pytest.fixture(scope="function", autouse=True)
def ut_modes_func_hooks(request):
    # add things at the start every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case
    yield
    # add things at the end every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

@pytest.mark.vtysh
def test_vtysh():
    vars = st.get_testbed_vars()
    st.vtysh_config(vars.D1, "ip prefix-list test permit 5.5.5.0/24")
    st.vtysh_config(vars.D1, "route-map test permit 1")
    # st.vtysh_config("end")
    st.vtysh_config(vars.D1, "exit")
    st.vtysh_config(vars.D1, "router bgp 1")
    # st.vtysh_show("show running-config")
    # st.vtysh_show("show ip prefix-list")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_modes_check
def test_vtysh_modes_check_1():
    vars = st.get_testbed_vars()
    # Command in Config level - no mode change - with end and exit
    st.vtysh_config(vars.D1, "ip prefix-list test permit 5.5.5.0/24")
    st.vtysh_show(vars.D1, "show ip prefix-list")
    st.vtysh_config(vars.D1, "end")

    st.vtysh_config(vars.D1, "ip prefix-list test permit 5.5.5.0/24")
    st.vtysh_show(vars.D1, "show ip prefix-list")
    st.vtysh_config(vars.D1, "exit")

    st.vtysh_config(vars.D1, "line vty")
    st.vtysh_config(vars.D1, "end")

    st.vtysh_config(vars.D1, "line vty")
    st.vtysh_config(vars.D1, "exit")

    st.report_pass("operation_successful")


@pytest.mark.vtysh_modes_check
def test_vtysh_modes_check_2():
    vars = st.get_testbed_vars()
    # Command in Config level - with mode change - with end and exit
    st.vtysh_config(vars.D1, "route-map test permit 1")
    st.vtysh_show(vars.D1, "show route-map test")
    st.vtysh_config(vars.D1, "exit")

    st.vtysh_config(vars.D1, "route-map test permit 1")
    st.vtysh_show(vars.D1, "show route-map test")
    st.vtysh_config(vars.D1, "end")

    st.report_pass("operation_successful")


@pytest.mark.vtysh_modes_check
def test_vtysh_modes_check_3():
    vars = st.get_testbed_vars()
    # Multiple commands in Config level - with one mode change - with end and exit
    st.vtysh_config(vars.D1, "ip prefix-list test permit 5.5.5.0/24")
    st.vtysh_config(vars.D1, "route-map test permit 1")
    st.vtysh_show(vars.D1, "show ip prefix-list")
    st.vtysh_config(vars.D1, "end")

    st.vtysh_config(vars.D1, "ip prefix-list test permit 5.5.5.0/24")
    st.vtysh_config(vars.D1, "route-map test permit 1")
    st.vtysh_show(vars.D1, "show ip prefix-list")
    st.vtysh_config(vars.D1, "exit")

    st.report_pass("operation_successful")


@pytest.mark.vtysh_modes_check
def test_vtysh_modes_check_4():
    vars = st.get_testbed_vars()
    # Multiple commands in Config level - with multiple mode change - with end and exit
    st.vtysh_config(vars.D1, "router bgp 65100")
    st.vtysh_show(vars.D1, "show ip bgp")
    st.vtysh_config(vars.D1, "end")

    st.vtysh_config(vars.D1, "router bgp 65100")
    st.vtysh_show(vars.D1, "show ip bgp")
    st.vtysh_config(vars.D1, "end")

    st.vtysh_config(vars.D1, "router bgp 65100")
    st.vtysh_config(vars.D1, "address-family ipv4 unicast")
    st.vtysh_config(vars.D1, "bgp dampening")
    st.vtysh_show(vars.D1, "show ip bgp")
    st.vtysh_config(vars.D1, "end")

    st.vtysh_config(vars.D1, "router bgp 65100")
    st.vtysh_config(vars.D1, "address-family ipv4 unicast")
    st.vtysh_config(vars.D1, "bgp dampening")
    st.vtysh_show(vars.D1, "show ip bgp")
    st.vtysh_config(vars.D1, "exit")

    st.report_pass("operation_successful")


@pytest.mark.vtysh_modes_check
def test_vtysh_modes_check_5():
    vars = st.get_testbed_vars()
    # Multiple ends
    st.vtysh_config(vars.D1, "end")
    st.vtysh_config(vars.D1, "end")
    st.vtysh_config(vars.D1, "end")

    # Multiple exists
    st.vtysh_config(vars.D1, "exit")
    st.vtysh_config(vars.D1, "exit")
    st.vtysh_config(vars.D1, "exit")

    st.report_pass("operation_successful")

@pytest.mark.vtysh_modes_check
def test_vtysh_modes_check_6():
    vars = st.get_testbed_vars()
    cmd = "\n".join("""
    router bgp 101
    no neighbor 2001::1:23:1:2 remote-as 101
    address-family ipv6 unicast
    no neighbor 2001::1:23:1:2 activate
    router bgp 101
    """.strip().splitlines())
    st.vtysh_config(vars.D1, cmd)
    st.report_pass("operation_successful")


@pytest.mark.lldp_mode_check
def test_lldp_mode_check_1():
    vars = st.get_testbed_vars()
    # from sonic to lldp mode
    st.show(vars.D1, "show platform summary")
    st.config(vars.D1, "configure lldp status tx-only", type="lldp", conf=True)
    st.show(vars.D1, "show neighbors", type="lldp")
    # from lldp to sonic mode
    st.show(vars.D1, "show platform summary")

    # from lldp to vtysh mode
    st.config(vars.D1, "configure lldp status tx-only", type="lldp", conf=True)
    st.vtysh_config(vars.D1, "router bgp 65100")

    # from vtysh to lldp mode
    st.config(vars.D1, "configure lldp status tx-only", type="lldp", conf=True)

    st.report_pass("operation_successful")


@pytest.mark.mgmt_cli_mode_check
def test_mgmt_cli_mode_check_1():
    vars = st.get_testbed_vars()

    # from sonic to mgmt-cli mode
    st.show(vars.D1, "show ip interfaces")
    st.change_prompt(vars.D1, "mgmt-user")

    # from mgmt-cli to sonic mode
    st.change_prompt(vars.D1, "normal-user")

    # from sonic to mgmt-cli interface mode
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")

    # from sonic to mgmt-cli interface mode with different interface
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet40")

    # from mgmt-cli interface to sonic mode
    st.change_prompt(vars.D1, "normal-user")

    # from mgmt-cli interface mode to mgmt-cli acl mode and commands after mode change
    st.change_prompt(vars.D1, "mgmt-ipv4-acl-config", aclname="MyACL")

    # from sonic to mgmt-cli interface mode with different interface
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet40")

    st.show(vars.D1, "show interfaces status")
    st.report_pass("operation_successful")


@pytest.mark.mgmt_cli_mode_check
def test_mgmt_cli_mode_check_2():
    vars = st.get_testbed_vars()

    # from sonic to mgmt-cli interface mode and commands after mode change
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")
    st.cli_config(vars.D1, "shutdown")
    st.cli_config(vars.D1, "no shutdown")

    # from sonic to mgmt-cli interface mode and commands along with mode change
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet40")
    st.cli_config(vars.D1, "shutdown")
    st.cli_config(vars.D1, "no shutdown")

    # from mgmt-cli interface mode to mgmt-cli acl mode and commands after mode change
    st.change_prompt(vars.D1, "mgmt-ipv4-acl-config", aclname="MyACL")
    st.cli_config(vars.D1, "seq 2 permit udp any any")
    st.cli_config(vars.D1, "no seq 2")

    # from sonic to mgmt-cli interface mode with different interface
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet40")
    st.cli_config(vars.D1, "shutdown")
    st.cli_config(vars.D1, "no shutdown")

    st.show(vars.D1, "show interfaces status")
    st.report_pass("operation_successful")


@pytest.mark.mgmt_cli_mode_check
def test_mgmt_cli_mode_check_3():
    vars = st.get_testbed_vars()

    # from sonic to mgmt-cli interface mode and commands along with mode change
    st.cli_config(vars.D1, "shutdown", "mgmt-intf-config", interface="Ethernet40")
    st.cli_config(vars.D1, "no shutdown")

    # from mgmt-cli interface mode to mgmt-cli acl mode and commands along with mode change
    st.cli_config(vars.D1, "seq 3 permit udp any any", "mgmt-ipv4-acl-config", aclname="MyTestACL")
    st.cli_config(vars.D1, "no seq 3")

    st.cli_config(vars.D1, "shutdown", "mgmt-intf-config", interface="Ethernet4")
    st.cli_config(vars.D1, "no shutdown")

    st.show(vars.D1, "show interfaces status")
    st.report_pass("operation_successful")


@pytest.mark.mgmt_cli_modes_show_check
def test_mgmt_cli_modes_show_check_1():
    vars = st.get_testbed_vars()

    # from sonic to mgmt-cli mode
    st.show(vars.D1, "show ip interfaces")
    st.change_prompt(vars.D1, "mgmt-user")
    st.cli_show(vars.D1, "show interface counters", skip_tmpl=True)

    st.change_prompt(vars.D1, "mgmt-config")
    st.cli_show(vars.D1, "show interface status", skip_tmpl=True)

    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet40")
    st.cli_show(vars.D1, "show interface counters", skip_tmpl=True)

    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")
    st.cli_show(vars.D1, "do show interface status", skip_tmpl=True)

    st.change_prompt(vars.D1, "mgmt-ipv4-acl-config", aclname="MyACL")
    st.cli_show(vars.D1, "show ip access-lists", skip_tmpl=True)

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.mgmt_cli_modes_show_check
def test_mgmt_cli_modes_show_check_2():
    vars = st.get_testbed_vars()

    st.show(vars.D1, "show platform summary")
    st.cli_show(vars.D1, "show interface counters", "mgmt-user", skip_tmpl=True)
    st.cli_show(vars.D1, "show interface status", "mgmt-config", skip_tmpl=True)
    st.cli_show(vars.D1, "show interface counters", "mgmt-intf-config", interface="Ethernet40", skip_tmpl=True)
    st.cli_show(vars.D1, "do show interface status", "mgmt-intf-config", interface="Ethernet4", skip_tmpl=True)
    st.cli_show(vars.D1, "show ip access-lists", "mgmt-ipv4-acl-config", aclname="MyACL", skip_tmpl=True)

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_prompt_modes_check
def test_vtysh_prompt_modes_check_1():
    vars = st.get_testbed_vars()

    st.change_prompt(vars.D1, "normal-user")

    # from vtysh mode to normal user and back to normal user
    st.change_prompt(vars.D1, "vtysh-user")
    st.change_prompt(vars.D1, "normal-user")

    # from sonic to vtysh config mode and back to normal user
    st.change_prompt(vars.D1, "vtysh-config")
    st.change_prompt(vars.D1, "normal-user")

    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet40")
    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet4")
    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet40")
    st.change_prompt(vars.D1, "vtysh-user")

    # from sonic to vtysh router config mode and back to normal user
    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.change_prompt(vars.D1, "vtysh-router-af-config", addr_family="ipv4", modifier="unicast")
    st.change_prompt(vars.D1, "vtysh-router-config", router="rip")
    st.change_prompt(vars.D1, "vtysh-user")
    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.change_prompt(vars.D1, "vtysh-router-af-config", addr_family="ipv4", modifier="unicast")
    st.change_prompt(vars.D1, "vtysh-router-config", router="rip")

    # using vtysh_show and back to normal user
    st.vtysh_show(vars.D1, "show ip prefix-list", skip_tmpl=True)
    st.change_prompt(vars.D1, "normal-user")

    st.show(vars.D1, "show interfaces status")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_prompt_modes_check
def test_vtysh_prompt_modes_check_2():
    vars = st.get_testbed_vars()

    st.change_prompt(vars.D1, "normal-user")

    # from vtysh mode to normal user and back to normal user
    list_of_modes = ["vtysh-user", "vtysh-config", "vtysh-bfd-config", "vtysh-line-vty-config"]
    for tomode in list_of_modes:
        st.change_prompt(vars.D1, tomode)
        st.change_prompt(vars.D1, "normal-user")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_prompt_modes_check
def test_vtysh_prompt_modes_check_3():
    vars = st.get_testbed_vars()

    st.change_prompt(vars.D1, "normal-user")

    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet40")
    st.cli_config(vars.D1, "no shutdown")

    st.change_prompt(vars.D1, "vtysh-bfd-peer-config", peer_ip="1.2.3.4")
    st.change_prompt(vars.D1, "vtysh-key-chain-config", key_chain="1.2.3.4")
    st.change_prompt(vars.D1, "vtysh-key-chain-Identifier-config", key_id="1")
    st.change_prompt(vars.D1, "vtysh-l2vpn-config", l2vpn_name="testl2vpn")
    st.change_prompt(vars.D1, "vtysh-nhgroup-config", group_name="testnhgroup")
    st.change_prompt(vars.D1, "vtysh-pbr-map-config", map_name="testpbrmap", seq_id="1")
    st.change_prompt(vars.D1, "vtysh-pseudowire-config", interface="Ethernet4")
    st.change_prompt(vars.D1, "vtysh-route-map-config", tag_name="testroutemap", action="deny", seq_num="1")

    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.cli_config(vars.D1, "aggregate-address 1.2.3.4/24")

    st.change_prompt(vars.D1, "vtysh-router-config", router="rip")
    st.cli_config(vars.D1, "allow-ecmp")

    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.cli_config(vars.D1, "aggregate-address 1.2.3.4/24")

    st.change_prompt(vars.D1, "vtysh-router-af-config", addr_family="ipv4", modifier="unicast")
    st.cli_config(vars.D1, "bgp dampening")

    st.change_prompt(vars.D1, "vtysh-router-config", router="rip")
    st.cli_config(vars.D1, "allow-ecmp")

    st.change_prompt(vars.D1, "vtysh-router-af-config", router="bgp", instance="1", addr_family="ipv4", modifier="unicast")
    st.cli_config(vars.D1, "bgp dampening")

    st.change_prompt(vars.D1, "vtysh-router-config", router="rip")
    st.cli_config(vars.D1, "allow-ecmp")

    st.change_prompt(vars.D1, "vtysh-router-af-config", router="bgp", instance="1", addr_family="ipv4", modifier="unicast")
    st.cli_config(vars.D1, "bgp dampening")

    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.cli_config(vars.D1, "aggregate-address 1.2.3.4/24")

    st.change_prompt(vars.D1, "vtysh-vrf-config", vrf_name="testvrfname")
    st.cli_config(vars.D1, "ip protocol any route-map test")

    st.change_prompt(vars.D1, "normal-user")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_prompt_modes_check
def test_vtysh_prompt_modes_check_4():
    vars = st.get_testbed_vars()

    st.change_prompt(vars.D1, "normal-user")

    st.cli_config(vars.D1, "no shutdown", "vtysh-intf-config", interface="Ethernet40")
    st.cli_config(vars.D1, "receive-interval 10", "vtysh-bfd-peer-config", peer_ip="1.2.3.4")
    st.cli_config(vars.D1, "list", "vtysh-key-chain-config", key_chain="testkeychain")
    st.cli_config(vars.D1, "key-string teststring", "vtysh-key-chain-Identifier-config", key_id="1")
    st.cli_config(vars.D1, "vc type ethernet", "vtysh-l2vpn-config", l2vpn_name="testl2vpn")
    st.cli_config(vars.D1, "nexthop 1.2.3.4", "vtysh-nhgroup-config", group_name="testnhgroup")
    st.cli_config(vars.D1, "set nexthop 1.2.3.4", "vtysh-pbr-map-config", map_name="testpbrmap", seq_id="1")
    st.cli_config(vars.D1, "neighbor 1.2.3.4", "vtysh-pseudowire-config", interface="Ethernet4")
    st.cli_config(vars.D1, "set community none", "vtysh-route-map-config", tag_name="testroutemap", action="deny", seq_num="1")

    st.cli_config(vars.D1, "aggregate-address 1.2.3.4/24", "vtysh-router-config", router="bgp", instance="1")
    st.cli_config(vars.D1, "allow-ecmp", "vtysh-router-config", router="rip")
    st.cli_config(vars.D1, "aggregate-address 1.2.3.4/24", "vtysh-router-config", router="bgp", instance="1")
    st.cli_config(vars.D1, "bgp dampening", "vtysh-router-af-config", addr_family="ipv4", modifier="unicast")
    st.cli_config(vars.D1, "allow-ecmp", "vtysh-router-config", router="rip")
    st.cli_config(vars.D1, "bgp dampening", "vtysh-router-af-config", router="bgp", instance="1", addr_family="ipv4", modifier="unicast")
    st.cli_config(vars.D1, "aggregate-address 1.2.3.4/24", "vtysh-router-config", router="bgp", instance="1")

    st.cli_config(vars.D1, "ip protocol any route-map test", "vtysh-vrf-config", vrf_name="testvrfname")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_prompt_modes_check
def test_vtysh_prompt_modes_check_5():
    vars = st.get_testbed_vars()

    st.change_prompt(vars.D1, "normal-user")

    st.cli_config(vars.D1, "list", "vtysh-intf-config", interface="Ethernet40")
    st.cli_config(vars.D1, "list", "vtysh-bfd-peer-config", peer_ip="1.2.3.4")
    st.cli_config(vars.D1, "list", "vtysh-key-chain-config", key_chain="testkeychain")
    st.cli_config(vars.D1, "list", "vtysh-key-chain-Identifier-config", key_id="1")
    st.cli_config(vars.D1, "list", "vtysh-l2vpn-config", l2vpn_name="testl2vpn")
    st.cli_config(vars.D1, "list", "vtysh-nhgroup-config", group_name="testnhgroup")
    st.cli_config(vars.D1, "list", "vtysh-pbr-map-config", map_name="testpbrmap", seq_id="1")
    st.cli_config(vars.D1, "list", "vtysh-pseudowire-config", interface="Ethernet4")
    st.cli_config(vars.D1, "list", "vtysh-route-map-config", tag_name="testroutemap", action="deny", seq_num="1")
    st.cli_config(vars.D1, "list", "vtysh-router-config", router="bgp", instance="1")
    st.cli_config(vars.D1, "list", "vtysh-router-af-config", addr_family="ipv4", modifier="unicast")
    st.cli_config(vars.D1, "list", "vtysh-router-config", router="rip")
    st.cli_config(vars.D1, "list", "vtysh-vrf-config", vrf_name="testvrfname")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_prompt_modes_check_negative
def test_vtysh_prompt_modes_check_6():
    vars = st.get_testbed_vars()

    st.change_prompt(vars.D1, "normal-user")

    st.change_prompt(vars.D1, "vtysh-intf-config")
    st.change_prompt(vars.D1, "vtysh-router-config")
    st.change_prompt(vars.D1, "vtysh-router-af-config")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_prompt_modes_show_check
def test_vtysh_prompt_modes_show_check_1():
    vars = st.get_testbed_vars()

    st.show(vars.D1, "show platform summary")

    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet40")
    st.cli_show(vars.D1, "show ip route")

    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet4")
    st.cli_show(vars.D1, "do show ip route", skip_tmpl=True)

    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.cli_show(vars.D1, "show route-map", skip_tmpl=True)

    st.change_prompt(vars.D1, "normal-user")
    st.cli_show(vars.D1, "show ip route")

    st.change_prompt(vars.D1, "vtysh-user")
    st.cli_show(vars.D1, "show ip route")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_prompt_modes_show_check
def test_vtysh_prompt_modes_show_check_2():
    vars = st.get_testbed_vars()

    st.show(vars.D1, "show platform summary")

    st.cli_show(vars.D1, "show ip route", "vtysh-intf-config", interface="Ethernet40")
    st.cli_show(vars.D1, "do show ip route", "vtysh-intf-config", interface="Ethernet4", skip_tmpl=True)
    st.cli_show(vars.D1, "show route-map", "vtysh-router-config", router="bgp", instance="1", skip_tmpl=True)
    st.cli_show(vars.D1, "show ip route", "normal-user")
    st.cli_show(vars.D1, "show route-map", "vtysh-router-config", router="bgp", instance="1", skip_tmpl=True)
    st.cli_show(vars.D1, "show ip route", "normal-user")
    st.cli_show(vars.D1, "show route-map", "vtysh-router-config", router="bgp", instance="1", skip_tmpl=True)
    st.cli_show(vars.D1, "show ip route", "normal-user")
    st.cli_show(vars.D1, "show ip route", "vtysh-user")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_mgmt_prompt_modes_check
def test_vtysh_mgmt_prompt_modes_check_1():
    vars = st.get_testbed_vars()

    st.show(vars.D1, "show platform summary")

    st.change_prompt(vars.D1, "vtysh-user")
    st.change_prompt(vars.D1, "mgmt-user")
    st.change_prompt(vars.D1, "vtysh-user")
    st.change_prompt(vars.D1, "normal-user")
    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet40")
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")
    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet40")
    st.change_prompt(vars.D1, "normal-user")
    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.change_prompt(vars.D1, "mgmt-ipv4-acl-config", aclname="MyACL")
    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")


@pytest.mark.vtysh_mgmt_prompt_modes_check
def test_vtysh_mgmt_prompt_modes_check_2():
    vars = st.get_testbed_vars()

    st.show(vars.D1, "show platform summary")

    st.change_prompt(vars.D1, "vtysh-user")
    st.cli_show(vars.D1, "show ip route")
    st.change_prompt(vars.D1, "mgmt-user")
    st.cli_show(vars.D1, "show interface counters", skip_tmpl=True)
    st.change_prompt(vars.D1, "vtysh-user")
    st.cli_show(vars.D1, "show ip route")

    st.change_prompt(vars.D1, "normal-user")

    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet40")
    st.cli_config(vars.D1, "shutdown")
    st.cli_config(vars.D1, "no shutdown")
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")
    st.cli_config(vars.D1, "shutdown")
    st.cli_config(vars.D1, "no shutdown")
    st.cli_show(vars.D1, "show interface counters", skip_tmpl=True)
    st.change_prompt(vars.D1, "vtysh-intf-config", interface="Ethernet40")
    st.cli_config(vars.D1, "shutdown")
    st.cli_config(vars.D1, "no shutdown")

    st.change_prompt(vars.D1, "normal-user")

    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.cli_config(vars.D1, "aggregate-address 1.2.3.4/24")
    st.change_prompt(vars.D1, "mgmt-ipv4-acl-config", aclname="MyACL")
    st.cli_config(vars.D1, "seq 2 permit udp any any")
    st.cli_config(vars.D1, "no seq 2")
    st.cli_show(vars.D1, "show interface counters", skip_tmpl=True)
    st.change_prompt(vars.D1, "vtysh-router-config", router="bgp", instance="1")
    st.cli_config(vars.D1, "aggregate-address 1.2.3.4/24")

    st.show(vars.D1, "show vlan config")
    st.report_pass("operation_successful")

@pytest.mark.all_modes_check
def test_all_modes_check_1():
    vars = st.get_testbed_vars()

    # from sonic to mgmt-cli mode
    st.show(vars.D1, "show ip interfaces")
    st.change_prompt(vars.D1, "mgmt-user")
    st.cli_show(vars.D1, "show interface status", skip_tmpl=True)

    # from mgmt-cli to sonic mode
    st.change_prompt(vars.D1, "normal-user")

    # from sonic to mgmt-cli interface mode
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")

    # from sonic to mgmt-cli interface mode with different interface
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet40")
    st.cli_show(vars.D1, "show interface status", skip_tmpl=True)
    st.cli_show(vars.D1, "show interface status | no-more ", skip_tmpl=True)

    # from mgmt-cli interface to sonic mode
    st.change_prompt(vars.D1, "normal-user")

    # from mgmt-cli interface mode to mgmt-cli acl mode and commands after mode change
    st.change_prompt(vars.D1, "mgmt-ipv4-acl-config", aclname="MyACL")

    # from sonic to mgmt-cli interface mode with different interface
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet40")

    # from mgmt-cli Config to various different modes and vice versa
    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")
    st.show(vars.D1, "show neighbors", type="lldp")

    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")
    st.vtysh_show(vars.D1, "show ip bgp")

    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")
    st.vtysh_config(vars.D1, "do show ip bgp")

    st.change_prompt(vars.D1, "mgmt-intf-config", interface="Ethernet4")
    st.show(vars.D1, "show interfaces status")

    # from mgmt-cli normal mode to various different modes and vice versa
    st.change_prompt(vars.D1, "mgmt-user")
    st.show(vars.D1, "show neighbors", type="lldp")

    st.change_prompt(vars.D1, "mgmt-user")
    st.vtysh_show(vars.D1, "show ip bgp")

    st.change_prompt(vars.D1, "mgmt-user")
    st.vtysh_config(vars.D1, "do show ip bgp")

    st.change_prompt(vars.D1, "mgmt-user")
    st.show(vars.D1, "show interfaces status")

    # from lldp mode to remaining modes and vice versa
    st.show(vars.D1, "show neighbors", type="lldp")
    st.vtysh_show(vars.D1, "show ip bgp")

    st.show(vars.D1, "show neighbors", type="lldp")
    st.vtysh_config(vars.D1, "do show ip bgp")

    st.show(vars.D1, "show neighbors", type="lldp")
    st.show(vars.D1, "show interfaces status")

    # from vtysh config mode to remaining modes and vice versa
    st.vtysh_config(vars.D1, "do show ip bgp")
    st.vtysh_show(vars.D1, "show ip route")

    st.vtysh_config(vars.D1, "do show ip bgp")
    st.show(vars.D1, "show interfaces status")

    # from vtysh mode to remaining modes and vice versa
    st.vtysh_show(vars.D1, "show ip bgp")
    st.show(vars.D1, "show interfaces status")

    st.report_pass("operation_successful")

@pytest.mark.udld_check
def test_all_udld_check():
    vars = st.get_testbed_vars()

    # from sonic to mgmt-cli mode
    st.show(vars.D1, "show ip interfaces")
    st.show(vars.D1, "show interface status", skip_tmpl=True, type="klish")

    st.config(vars.D1, "interface Ethernet 4", type="klish")
    st.config(vars.D1, "udld enable", type="klish")
    st.config(vars.D1, "exit", type="klish")
    st.config(vars.D1, "interface Ethernet 40", type="klish")
    st.config(vars.D1, "udld enable", type="klish")
    st.config(vars.D1, "exit", type="klish")

    st.show(vars.D1, "show ip interfaces")

    st.report_pass("operation_successful")

@pytest.mark.test_klish_tam
def test_klish_tam():
    vars = st.get_testbed_vars()

    st.config(vars.D1, "tam", type="klish")
    st.config(vars.D1, "int-ifa-ts", type="klish")
    st.show(vars.D1, "show interface status", type="click")

    st.config(vars.D1, "tam", type="klish")
    st.config(vars.D1, "int-ifa-ts", type="klish")
    st.show(vars.D1, "show interface brief", type="vtysh", skip_tmpl=True)

    st.config(vars.D1, "tam", type="klish")
    st.config(vars.D1, "int-ifa-ts", type="klish")
    st.show(vars.D1, "show neighbors", type="lldp", skip_tmpl=True)

    st.config(vars.D1, "tam", type="klish")
    st.config(vars.D1, "int-ifa-ts", type="klish")
    st.config(vars.D1, "configure med policy application voice", type="lldp")

    st.config(vars.D1, "tam", type="klish")
    st.config(vars.D1, "int-ifa-ts", type="klish")
    st.config(vars.D1, "pseudowire dummy", type="vtysh")

    st.config(vars.D1, "tam", type="klish")
    st.config(vars.D1, "int-ifa-ts", type="klish")
    st.show(vars.D1, "show interface status", type="click")

    st.report_pass("operation_successful")

@pytest.mark.test_vtysh_intf_pim
def test_vtysh_intf_pim():
    vars = st.get_testbed_vars()

    st.config(vars.D1, "interface Vlan101\nip pim hello 20\nexit", type="vtysh")
    st.config(vars.D1, "interface Vlan101\nip pim hello 15\nexit", type="vtysh")
    st.show(vars.D1, "show interface brief", type="vtysh", skip_tmpl=True)

    st.report_pass("operation_successful")

@pytest.mark.stop_bgp_and_enter
def test_stop_bgp_and_enter():
    vars = st.get_testbed_vars()

    st.config(vars.D1, "sudo systemctl stop bgp")
    st.show(vars.D1, "show interface brief", type="vtysh", skip_tmpl=True)
    st.show(vars.D1, "show vlan config", type="click", skip_tmpl=True)

    st.report_pass("operation_successful")

@pytest.mark.stop_mgmt_and_enter
def test_stop_mgmt_and_enter():
    vars = st.get_testbed_vars()

    st.config(vars.D1, "sudo systemctl stop mgmt-framework")
    st.show(vars.D1, "show interface status", type="klish", skip_tmpl=True)
    st.show(vars.D1, "show vlan config", type="click", skip_tmpl=True)

    st.report_pass("operation_successful")

@pytest.mark.wrong_vtysh_cmd
def test_wrong_vtysh_cmd_2():
    vars = st.get_testbed_vars()

    st.config(vars.D1, "router bgp\nexit\nexit", type="vtysh", skip_error_check=True)
    st.show(vars.D1, "testetst\nexit", skip_error_check=True, skip_tmpl=True)

    st.report_pass("operation_successful")

@pytest.mark.wrong_vtysh_cmd
def test_wrong_vtysh_cmd():
    vars = st.get_testbed_vars()

    st.config(vars.D1, "router bgp\nexit\nexit", type="vtysh", skip_error_check=True)

    st.report_pass("operation_successful")

