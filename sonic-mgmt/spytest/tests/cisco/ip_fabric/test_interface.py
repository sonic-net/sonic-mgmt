import pytest
import json
import apis.system.interface as intf_obj
import apis.routing.ip as ping_obj
from spytest import st
from time import sleep

data = dict()


def setup_module():
    global vars, data
    vars = st.ensure_min_topology("D1")
    # Value in the dict below should be same as base profile.
    data.update({
        "vlan_id": 20,
        "mtu": 9000,
        "sd1_ip": "10.1.0.1",
        "mask": "24",
        "sd2_ip": "10.1.0.2",
        "sd1_ipv6": "2001::10:1:0:1",
        "sd2_ipv6": "2001::10:1:0:2",
        "loopback_ip": "7.7.7.7",
        "loopback_ipv6": "2004::7",
        "dhcp_ipv4": "20.1.0.1",
        "dhcp_ipv6": "2008::20:1:0:1",
        "ipv6_mask": "120"
    })


def verify_v4_ping(ip_add=None,mtu=64):
    if ip_add is None:
        ip_add = data["sd2_ip"]
    st.log("Verify connectivity from DUT")
    if not ping_obj.ping(vars.D1, ip_add, packetsize=mtu):
        st.report_fail("Ping_to_peer_device_is_not_successful", ip_add)


def verify_v6_ping(ipv6_add=None,mtu=64):
    if ipv6_add is None:
        ipv6_add = data["sd2_ipv6"]
    st.log("Verify connectivity from DUT")
    if not ping_obj.ping(vars.D1, ipv6_add, family='ipv6', packetsize=mtu):
        st.report_fail("Ping_to_peer_device_is_not_successful", ipv6_add)


def teardown_module():
    intf_obj.interface_properties_set(vars.D1, vars.D1D2P1, "mtu",
                                      data["mtu"])

"""
Configuration for test case is pre loaded on dut before starting the run.
Both config_db and frr configuration files are captured in
spytest/testbeds/ip_fabric folder
"""

@pytest.mark.drop_2
def test_svi_with_ipv4_ipv6():
    """
    Configure ipv4 and ipv6 addresss on vlan as part of base profile
    """

    verify_v4_ping()
    verify_v6_ping()
    st.report_pass("test_case_passed")


@pytest.mark.drop_2
def test_l2_interface_mtu():
    """
    Test configuring mtu on l2 interface
    Change mtu value to 9000
    """
    st.log(f"Configure MTU to {data['mtu']} on ")
    intf_obj.interface_properties_set(vars.D1, vars.D1D2P1, "mtu",
                                      data['mtu'])
    intf_obj.interface_properties_set(vars.D2, vars.D2D1P1, "mtu",
                                      data['mtu'])
    output = st.config(vars.D1, f"ifconfig {vars.D1D2P1}")
    if f"mtu {data['mtu']}" not in output:
        st.report_fail("Failed to modify mtu value on the Ethernet0")

    verify_v4_ping(mtu=data['mtu'])
    verify_v6_ping(mtu=data['mtu'])
    st.report_pass("test_case_passed")


@pytest.mark.drop_2
def test_vlan_mtu():
    """
    Test configuring mtu on vlan interface
    Change mtu value to 9000
    """
    st.log(f"Configure MTU to {data['mtu']} on vlan {data['vlan_id']}")
    st.config(vars.D1, f"ifconfig Vlan{data['vlan_id']} mtu {data['mtu']}")
    st.config(vars.D2, f"ifconfig Vlan{data['vlan_id']} mtu {data['mtu']}")
    output = st.config(vars.D1, f"ifconfig Vlan{data['vlan_id']}")
    if f"mtu {data['mtu']}" not in output:
        st.report_fail(f"Failed to modify mtu value on Vlan {data['vlan_id']}")
    verify_v4_ping(mtu=data['mtu'])
    verify_v6_ping(mtu=data['mtu'])
    st.report_pass("test_case_passed")


@pytest.mark.drop_2
def test_vlan_helper_address():
    """
    Verfiy ip helper address on the vlan is configured
    """
    output = st.show(vars.D1, "show dhcp_relay ipv4 helper", skip_tmpl=True)
    if not data['dhcp_ipv4'] in output:
        st.report_fail(f"IPv4 Helper addres not found on vlan {data['vlan_id']}")

    output = st.show(vars.D1, "show dhcp_relay ipv6 destination", skip_tmpl=True)
    if data['dhcp_ipv6'] not in output:
        st.report_fail(f"IPv6 Helper addres not found on vlan {data['vlan_id']}")

    st.report_pass("test_case_passed")


@pytest.mark.drop_2
def test_configure_loopback():
    """
    Verify IPv4 and IPv6 addresses on loopback interfaces
    """

    output = st.config(vars.D1, "ifconfig Loopback0")
    if data['loopback_ip'] not in output:
        st.report_fail("Ipv4 address not configured on Loopback0")
    if data['loopback_ipv6'] not in output:
        st.report_fail("Ipv6 address not configured on Loopback0")

    verify_v4_ping(data["loopback_ip"])
    verify_v6_ping(data["loopback_ipv6"])

    st.report_pass("test_case_passed")


@pytest.mark.drop_2
def test_mac_aging_time():
    """
    Verify mac aging timer is getting modified
    """
    st.log("Check default time for mac aging")
    output = st.show(vars.D1, "show mac aging-time", skip_tmpl=True)

    if "Aging time for switch is 600 seconds" not in output:
        st.report_fail("Mac aging default time should be 600")

    st.log("Configure mac aging time to 60 secs")
    swss_output = st.config(vars.D1, "docker exec swss bash -c 'cat /etc/swss/config.d/switch.json'", remove_prompt=True)
    swss_data = json.loads(swss_output)

    show_mac = st.show(vars.D1, "show mac")
    num_of_mac = show_mac[-1]['total']
    swss_data[0]['SWITCH_TABLE:switch']['fdb_aging_time'] = "60"

    def update_fdb():
        with open("/tmp/switch.json", "w") as fd:
            json.dump(swss_data, fd, indent=4)
            fd.write("\n")

        st.upload_file_to_dut(vars.D1, "/tmp/switch.json", "/tmp/switch.json")
        st.config(vars.D1, "docker cp /tmp/switch.json swss:/etc/swss/config.d/switch.json")
        st.config(vars.D1, "docker exec swss bash -c swssconfig /etc/swss/config.d/switch.json")
        sleep(5)

    update_fdb()
    st.log("Check time for mac aging is changed to 60")
    output = st.show(vars.D1, "show mac aging-time", skip_tmpl=True)

    st.log("Sleeping for 60 secs to let fdb entry get flushed")
    sleep(65)
    show_mac = st.show(vars.D1, "show mac")
    num_of_mac_flushed = show_mac[-1]['total']

    st.log("Mac entries were flushed successfully")

    if "Aging time for switch is 60 seconds" not in output:
        st.report_fail("Mac aging default time should be changed to 60")

    st.log("Configure mac aging time to 1800 secs")
    swss_data[0]['SWITCH_TABLE:switch']['fdb_aging_time'] = "1800"
    update_fdb()
    output = st.show(vars.D1, "show mac aging-time", skip_tmpl=True)
    if "Aging time for switch is 1800 seconds" not in output:
        st.report_fail("Mac aging default time should be changed to 1800")

    # Resetting to aging time to 600 secs as default
    swss_data[0]['SWITCH_TABLE:switch']['fdb_aging_time'] = "600"
    update_fdb()
    if not num_of_mac_flushed < num_of_mac:
        st.report_fail("Mac entries were not flushed")
    st.report_pass("test_case_passed")
