import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
from dhcpv4_relay_utils import check_dhcp4relay_support
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import tortuga_common_utils as common_obj
import apis.system.reboot as reboot_obj
import utilities.utils as utils_obj
import ipaddress

DHCP_SERVER_FILE = "kea-dhcp4.conf"
DHCP_SERVER_GEN_FILE = "dhcp_conf_gen.py"
DHCP_SCALE_FILE = "relay_config_generation.py"
DHCP_SERVER_GEN_FILE_PATH = os.path.dirname(os.path.realpath(__file__)) +  '/' + DHCP_SERVER_GEN_FILE
DHCP_SCALE_FILE_PATH = os.path.dirname(os.path.realpath(__file__)) +  '/' + DHCP_SCALE_FILE
SPYTEST_HELPER_FILE = "spytest-helper.py"
SPYTEST_HELPER_FILE_PATH = os.path.dirname(os.path.realpath(__file__)) + '/../../../../spytest/remote/' + SPYTEST_HELPER_FILE

# Hardware: full relay VLAN count. SIM (VXR): reduced count (per-VLAN DHCP monitors).
DHCP_RELAY_SCALE_FULL = 800
DHCP_RELAY_SCALE_REDUCED_SIM = 100

dhcprelay_startvlan = 21
dhcpserver_vlan = 20
dhcpserver_ipv4 = "192.160.20.100"

def get_dhcp_relay_scale(dut):
    """
    SIM (VXR): DHCP_RELAY_SCALE_REDUCED_SIM VLANs (per-VLAN relay monitor load).
    Hardware: DHCP_RELAY_SCALE_FULL VLANs.

    The same value is used for Kea prep, relay_config_generation.py
    --dhcp-relay-scale, and client verification.
    """
    if vxlan_obj.check_hw_or_sim(dut) == "sim":
        st.log(
            "SIM: DHCP relay scale {} VLANs".format(DHCP_RELAY_SCALE_REDUCED_SIM)
        )
        return DHCP_RELAY_SCALE_REDUCED_SIM
    st.log("HW: DHCP relay scale {} VLANs".format(DHCP_RELAY_SCALE_FULL))
    return DHCP_RELAY_SCALE_FULL


def download_image(dut, url, filename):
    st.log("Downloading image from {} ...".format(url))

    # Run curl using st.show() so spytest captures logs
    curl_cmd = "curl -O {}".format(url)
    st.show(dut, curl_cmd, skip_tmpl=True)

    # Verify file exists
    ls_cmd = "ls -l {}".format(filename)
    ls_out = st.show(dut, ls_cmd, skip_tmpl=True)

    return ls_out  # return raw output to caller

def prepare_server_config(
    node, file_path, dest_file_path=None, relay_start_vlan=None, relay_end_exclusive=None
):
    if relay_start_vlan is None:
        relay_start_vlan = dhcprelay_startvlan
    if relay_end_exclusive is None:
        relay_end_exclusive = relay_start_vlan + DHCP_RELAY_SCALE_FULL
    utils_obj.copy_files_to_dut(node, [file_path], dest_file_path)
    st.config(
        node,
        "python3 dhcp_conf_gen.py --iface Vlan{} --start {} --end {} --outfile {}".format(
            dhcpserver_vlan, relay_start_vlan, relay_end_exclusive - 1, DHCP_SERVER_FILE
        ),
    )

def configure_dhcp_server(dut, vlan_id, server_ip, conf_file="kea-dhcp4.conf"):
    """
    Configures VLAN, assigns IP, runs DHCP server container, copies config,
    and starts kea-dhcp4. Uses only st.config.
    """
    vars = st.get_testbed_vars()
    vlan_iface = "Vlan{}".format(vlan_id)

    st.log("Configuring VLAN and DHCP server...")

    st.config(dut, "config vlan add {}".format(vlan_id))
    st.config(dut, "config vlan member add {} {}".format(vlan_id, vars.D1D3P1))
    st.config(dut, "config interface ip add {} {}/24".format(vlan_iface, server_ip))

    # Start Docker container
    st.config(dut,
        "docker run -d --privileged --name dhcp_server --network host docker-dhcp-server:latest"
    )

    # Copy DHCP config into container
    st.config(dut, "docker cp {} dhcp_server:/home".format(DHCP_SERVER_FILE))

    # Backup old config in container
    st.config(dut, "docker exec dhcp_server cp /etc/kea/kea-dhcp4.conf /root")

    # Replace with new config
    st.config(dut, "docker exec dhcp_server cp /home/{} /etc/kea/kea-dhcp4.conf".format(DHCP_SERVER_FILE))

    # Restart Kea DHCP4
    st.config(dut,
        'docker exec dhcp_server sh -c "nohup kea-dhcp4 -c /etc/kea/kea-dhcp4.conf > /var/log/kea-dhcp4.log 2>&1 &"'
    )

    st.log("DHCP server configuration completed.")

def verify_dhcp_socket(dut, dhcp_ip="192.160.20.100"):
    """
    Verifies that DHCP server (kea-dhcp4) is listening on UDP port 67.
    Uses only st.show.
    Returns True if found, False otherwise.
    """
    st.log("Checking DHCP server socket on UDP/67...")

    cmd = "sudo netstat -tulnp | grep :67"
    output = st.show(dut, cmd, skip_tmpl=True)

    if output and dhcp_ip in output:
        st.log("Success: DHCP server is running on {}:67".format(dhcp_ip))
        return True
    else:
        st.log("Failure: DHCP server is NOT listening on {}:67".format(dhcp_ip))
        return False

def apply_json_config(node, file_path, scale, intf, dest_file_path=None, relay=None):
    vars = st.get_testbed_vars()
    utils_obj.copy_files_to_dut(node, [file_path], dest_file_path)
    if relay:
        st.config(node,
                "python3 relay_config_generation.py --dhcp-relay-scale {} "
                "--relay-client-interface {} --relay "
                "--relay-server-interface {}".format(scale, intf, vars.D3D1P1))
    else:
        st.config(node,
                "python3 relay_config_generation.py --dhcp-relay-scale {} "
                "--relay-client-interface {}".format(scale, intf))
    st.config(node, "config load vlan_config_specific.json -y")

def verify_dhcp_acquired_ip(ip_output, vlan_id):
    """
    Validates DHCP-assigned IP for a given VLAN:
    - VLAN entry exists in `show ip interface` output
    - Extract IP/mask field
    - Check if IP belongs to the expected subnet: 192.160.<vlan_id>.0/24
    """

    lines = ip_output.splitlines()
    vlan_str = "Vlan{}".format(vlan_id)

    for line in lines:
        if vlan_str in line:
            parts = line.split()

            if len(parts) < 3:
                return False, "{}: Missing IP field".format(vlan_str)

            # Example: "192.160.21.66/24"
            ip_with_mask = parts[1]

            try:
                ip_iface = ipaddress.ip_interface(ip_with_mask)
            except:
                return False, "{}: Invalid IP format {}".format(vlan_str, ip_with_mask)

            second_octet = 160 + (vlan_id // 256)
            third_octet = vlan_id % 256
            expected_network_str = u"192.{}.{}.0/24".format(second_octet, third_octet)
            expected_network = ipaddress.ip_network(expected_network_str)

            if ip_iface.network != expected_network:
                return False, "{}: Wrong subnet {}, expected {}".format(
                    vlan_str, ip_iface.network, expected_network
                )

            return True, "{}: IP {} OK".format(vlan_str, ip_with_mask)

    return False, "{}: Interface not found in output".format(vlan_str)

def run_dhclient_and_verify(node, start_vlan, end_vlan):
    for vlan_id in range(start_vlan, end_vlan):
        st.config(node, "sudo dhclient -v Vlan{}".format(vlan_id))
    st.wait(10)
    ip_out = st.show(node, "show ip int", skip_tmpl=True)
    for vlan_id in range(start_vlan, end_vlan):
        result, msg = verify_dhcp_acquired_ip(ip_out, vlan_id)
        st.log(msg)
        if not result:
            return False
    return True

######################################################################
##  DHCP_RELAY IPV4 SCALING:
######################################################################
##
##  HOST0/dhcp_client ------- SD3/Leaf0 ------- HOST1/dhcp_server
##                    VLAN(21..20+N)    VLAN20         192.160.20.100
##                    N=DHCP_RELAY_SCALE_FULL on HW; N=DHCP_RELAY_SCALE_REDUCED_SIM on SIM
##                                    192.160.20.1/24
##                           RELAY_AGENT
##
######################################################################

def test_dhcp_relay_ipv4_scaling():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    if not check_dhcp4relay_support(vars.D3):
        st.log("Skipping: dhcp4relay new design not supported - gracefully passing.")
        return st.report_pass("test_case_passed", "dhcp4relay new design is not there. so gracefully passing")

    dhcp_relay_scale = get_dhcp_relay_scale(nodes["leaf0"])
    dhcprelay_endvlan = dhcprelay_startvlan + dhcp_relay_scale

    for dut in st.get_dut_names():
        output = st.config(dut, "show vlan brief")
        st.log(output)
        st.wait(3)

    dest_file_path = "~"
    st.config(vars.D3, "cp /etc/sonic/config_db.json /etc/sonic/bkp_config_db.json")
    st.config(vars.D2, "cp /etc/sonic/config_db.json /etc/sonic/bkp_config_db.json")

    try:
        # downloading dhcp_server image to dut
        st.banner("Download dhcp_server image")
        url = "http://172.29.93.10/sonic-images/202405c_dhcp_server_011225/docker-dhcp-server.gz"
        file_name = "docker-dhcp-server.gz"

        ls_out = download_image(nodes['spine0'], url, file_name)

        if file_name in ls_out:
            st.log("Image downloaded successfully")
        else:
            st.log("Image download failed")
            return st.report_fail("test_case_failed", "Image download failed")

        # Installing dhcp_server image
        st.banner("Installing dhcp_server image")

        install_cmd = "docker load < {}".format(file_name)
        output = st.config(nodes['spine0'], install_cmd, skip_error_check=True)

        if "Loaded image" in output:
            st.log("Image installed successfully")
        else:
            st.log("Image installation failed")
            return st.report_fail("test_case_failed", "Image installation failed")

        # Configuring server node
        st.banner("Config dhcp server node")
        prepare_server_config(
            nodes["spine0"],
            DHCP_SERVER_GEN_FILE_PATH,
            dest_file_path,
            relay_start_vlan=dhcprelay_startvlan,
            relay_end_exclusive=dhcprelay_endvlan,
        )
    
        configure_dhcp_server(nodes['spine0'], dhcpserver_vlan, dhcpserver_ipv4, DHCP_SERVER_FILE)
        st.wait(5)
        server_res = verify_dhcp_socket(nodes['spine0'], dhcpserver_ipv4)
        if server_res:
            st.log("dhcp_server configured properly")
        else:
            return st.report_fail("test_case_failed", "dhcp_server is not ready")

        # Configuring relay and client nodes
        st.banner("Config DHCP Scale Config")

        # Configuring relay node
        apply_json_config(
            nodes["leaf0"], DHCP_SCALE_FILE_PATH, dhcp_relay_scale, vars.D3D2P1, dest_file_path, "relay"
        )
        reboot_obj.config_save(nodes['leaf0'])
        status = reboot_obj.config_reload(nodes['leaf0'])
        if status:
            st.banner("config reload cmd success!")
        else:
            st.banner("config reload cmd failed!")
            return st.report_fail("test_case_failed", "config reload failed")

        # Configuring client node
        apply_json_config(nodes["spine1"], DHCP_SCALE_FILE_PATH, dhcp_relay_scale, vars.D2D3P1, dest_file_path)
        reboot_obj.config_save(nodes['spine1'])
        status = reboot_obj.config_reload(nodes['spine1'])
        if status:
            st.banner("config reload cmd success!")
        else:
            st.banner("config reload cmd failed!")
            return st.report_fail("test_case_failed", "config reload failed")
        st.wait(50)

        # Acquring ip and validating.
        result = run_dhclient_and_verify(nodes['spine1'], dhcprelay_startvlan, dhcprelay_endvlan)
        if result:
            st.report_pass("test_case_passed", "test_dhcp_relay_ipv4_scaling passed")
        else:
            return st.report_fail("test_case_failed", "test_dhcp_relay_ipv4_scaling failed")

    finally:
        # Cleaning up dhcp_server node
        st.config(nodes['spine0'], "sudo docker stop dhcp_server", skip_error_check=True)
        st.config(nodes['spine0'], "sudo docker rm dhcp_server", skip_error_check=True)
        st.config(nodes['spine0'], "sudo docker rmi docker-dhcp-server:latest", skip_error_check=True)
        st.config(nodes['spine0'], "config interface ip remove Vlan{} {}/24".format(dhcpserver_vlan, dhcpserver_ipv4), skip_error_check=True)
        st.config(nodes['spine0'], "config vlan member del {} {}".format(dhcpserver_vlan, vars.D1D3P1), skip_error_check=True)
        st.config(nodes['spine0'], "config vlan del {}".format(dhcpserver_vlan), skip_error_check=True)
        st.config(nodes['spine0'], "rm {} {} docker-dhcp-server.gz".format(DHCP_SERVER_GEN_FILE, DHCP_SERVER_FILE), skip_error_check=True)

        # Cleaning up relay node
        st.config(vars.D3, "rm {} vlan_config_specific.json".format(DHCP_SCALE_FILE), skip_error_check=True)
        st.config(vars.D3, "cp /etc/sonic/bkp_config_db.json /etc/sonic/config_db.json", skip_error_check=True)
        reboot_obj.config_reload(nodes['leaf0'])

        # Cleanig up client node
        st.config(vars.D2, "rm {} vlan_config_specific.json".format(DHCP_SCALE_FILE), skip_error_check=True)
        st.config(vars.D2, "cp /etc/sonic/bkp_config_db.json /etc/sonic/config_db.json", skip_error_check=True)
        reboot_obj.config_reload(nodes['spine1'])
