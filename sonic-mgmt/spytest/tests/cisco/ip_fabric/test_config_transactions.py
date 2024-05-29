from spytest import st
from spytest.dicts import SpyTestDict
from time import sleep
from os import path
from apis.security.tacacs import show_tacacs, filter_and_select, set_tacacs_server
from apis.qos import acl as acl_obj


CWD = path.dirname(__file__)
data = SpyTestDict()


def setup_module():
    global vars
    vars = st.ensure_min_topology("D1")
    data.update({
        "tacacs_ip": "172.168.10.10",
        "acl_table": "TEST_CONFIG",
        "acl_rule": "10-TEST",
        "python_tools": "frr-pythontools_8.5.1-0~ubuntu18.04.1_all.deb",
        "tools_server": "http://10.29.158.43",
        "rmap_v4": "TO_BGP_PEER_V4_NEW",
        "rmap_v6": "TO_BGP_PEER_V6_NEW"
    })


def test_config_replace_configdb():
    DUT_RUNN_CONFIGDB = "/tmp/running_config.json"
    DUT_NEW_CONFIGDB = "/tmp/new_config.json"
    DUT_ACL_CONFIG = "/tmp/acl.json"

    st.upload_file_to_dut(vars.D1, f"{CWD}/config_files/acl_config.json",
                          f"{DUT_ACL_CONFIG}")
    st.config(vars.D1, "config load {DUT_ACL_CONFIG} -y")

    st.log("Save running configuration to a file")
    st.config(vars.D1, f"config save {DUT_RUNN_CONFIGDB} -y")
    st.config(vars.D1, f"jq 'del(.ACL_RULE)' {DUT_RUNN_CONFIGDB} > {DUT_NEW_CONFIGDB}")

    st.config(vars.D1, f"config replace {DUT_NEW_CONFIGDB}")
    output = acl_obj.show_acl_table(vars.D1, "TEST_CONFIG")
    if not output:
        st.report_fail("ACL table not present. Failed to replace configuration")
    output = acl_obj.show_acl_rule(vars.D1, data["acl_table"], data["acl_rule"])
    if output:
        st.report_fail("ACL Rule still present. Failed to replace configuration")

    st.report_pass("test_case_passed")


def test_config_replace_frr():
    """
    Test replacing configuration file for frr. Using frr-pythontools utility
    to achieve config replacement
    """

    DUT_FRR_RUNN_CONF = "/tmp/running_config.frr"
    DUT_FRR_NEW_CONF = "/tmp/new_config.frr"

    st.log("Save running configuation to a file")
    st.config(vars.D1, f"vtysh -c 'show running' > {DUT_FRR_RUNN_CONF}")
    st.config(vars.D1, f"vtysh -c 'show running' > {DUT_FRR_NEW_CONF}")

    st.log("Modify BGP AS number in the file. Replacing file will create BGP session with new AS number")
    st.config(vars.D1, rf"sed -i -e 's/router bgp \([0-9]\+\)/router bgp 4000/g' {DUT_FRR_NEW_CONF}")

    st.log("Remove top 3 lines from running config output which gives error while replacing config")
    st.config(vars.D1, f"sed -i -e '1,3d' {DUT_FRR_NEW_CONF}")
    st.config(vars.D1, f"sed -i -e '1,3d' {DUT_FRR_RUNN_CONF}")

    st.config(vars.D1, f"docker cp {DUT_FRR_NEW_CONF} bgp:/frr.conf")

    st.log("Download and install frr-pythontools on bgp docker container")
    st.config(vars.D1, f"sudo ip vrf exec mgmt curl {data['tools_server']}/{data['python_tools']} -O")

    st.config(vars.D1, f"docker cp {data['python_tools']} bgp:/")
    st.config(vars.D1, f"docker exec bgp bash -c 'dpkg -i {data['python_tools']}'")

    st.config(vars.D1, "docker exec bgp bash -c '/usr/lib/frr/frr-reload.py --reload frr.conf'")

    output = st.show(vars.D1, "show ip bgp sum", skip_tmpl=True)
    if "AS number 4000" not in output:
        st.report_fail("BGP AS number has not been changed. Replacing with new configuration failed")

    st.log("Loading old configuration back on device")
    st.config(vars.D1, f"docker cp {DUT_FRR_RUNN_CONF} bgp:/frr.conf")
    st.config(vars.D1, "docker exec bgp bash -c '/usr/lib/frr/frr-reload.py --reload frr.conf'")
    output = st.show(vars.D1, "show ip bgp sum", skip_tmpl=True)
    if "AS number 4000" in output:
        st.report_fail("BGP AS number still shows as 4000. Replacing with old configuration failed")

    st.report_pass("test_case_passed")


def test_config_load_configdb():
    """
    Test loading configuration from a json file to config db.
    Configurting dummy TACACS server using config file
    """

    DUT_TACACS_CONF = "/tmp/tacacs_config.json"
    st.upload_file_to_dut(vars.D1, f"{CWD}/config_files/tacacs_config.json",
                          f"{DUT_TACACS_CONF}")
    st.config(vars.D1, f"config load {DUT_TACACS_CONF} -y")
    output = show_tacacs(vars.D1)
    if output and "servers" in output:
        output = output['servers']
        if not filter_and_select(output, ['address'], {"address": data["tacacs_ip"]}):
            st.report_fail("Provided and configured address values are not matching.")

    set_tacacs_server(vars.D1, 'delete', data["tacacs_ip"])
    st.report_pass("test_case_passed")


def test_config_load_frr():
    """
    Test loading configuration from a file to running configuration in frr.
    Test will configure route-maps to frr
    """
    DUT_FRR_CONF = "/tmp/route_map.frr"
    DOCKER_FRR_CONF = "frr.conf"
    with open(f"{CWD}/config_files/route_map.frr", "r") as fd:
        st.log("Loading following route-map configuration to DUT:\n")
        st.log(fd.read())

    st.upload_file_to_dut(vars.D1, f"{CWD}/config_files/route_map.frr",
                          f"{DUT_FRR_CONF}")
    st.config(vars.D1, f"docker cp {DUT_FRR_CONF} bgp:/{DOCKER_FRR_CONF}")
    st.vtysh(vars.D1, f"copy {DOCKER_FRR_CONF} running-config")
    output = st.config(vars.D1, "vtysh -c 'show run' | grep route-map")
    if data["rmap_v4"] not in output or data["rmap_v6"] not in output:
        st.report_fail("Route maps were not configured on frr device")

    st.log("Remove configure route maps")
    DUT_FRR_CONF = "/tmp/route_map.frr"
    DOCKER_FRR_CONF = "frr.conf"
    with open(f"{CWD}/config_files/no_route_map.frr", "r") as fd:
        st.log("Loading following route-map configuration to DUT:\n")
        st.log(fd.read())

    st.upload_file_to_dut(vars.D1, f"{CWD}/config_files/no_route_map.frr",
                          f"{DUT_FRR_CONF}")
    st.config(vars.D1, f"docker cp {DUT_FRR_CONF} bgp:/{DOCKER_FRR_CONF}")
    st.vtysh(vars.D1, f"copy {DOCKER_FRR_CONF} running-config")
    output = st.config(vars.D1, "vtysh -c 'show run' | grep route-map")
    if data["rmap_v4"] in output or data["rmap_v6"] in output:
        st.report_fail("Route maps were still configured on frr device")
    st.report_pass("test_case_passed")
