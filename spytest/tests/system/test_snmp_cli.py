import pytest
import json

from spytest import st, tgapi, SpyTestDict, poll_wait
from spytest import cutils, mutils

import apis.system.snmp as snmp_obj
import apis.system.basic as basic_obj
import apis.routing.ip as ipfeature
import apis.system.interface as intf_obj
from apis.system.connection import connect_to_device, ssh_disconnect
from apis.system.connection import execute_command
import apis.system.reboot as reboot
from apis.system.gnmi import gnmi_get, gnmi_set
import apis.system.interface as intfapi
from apis.system.management_vrf import config as mvrfconfig
import apis.routing.ip as ip
import apis.system.rest as rest_obj

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def snmp_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1T1:2")
    initialize_variables()
    snmp_pre_config()
    snmp_trap_pre_config()
    snmp_cli_config()
    snmp_cli_config_verify()

    yield
    snmp_cli_unconfig()
    snmp_trap_post_config()


@pytest.fixture(scope="function", autouse=True)
def snmp_func_hooks(request):
    global ipaddress
    ipaddress = st.get_mgmt_ip(vars.D1)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    if st.get_func_name(request) in ["test_ft_snmp_rest_v2_v3_inform_trap_mgmtvrf",
                                      "test_ft_snmp_gnmi_v2_v3_inform_trap_mgmtvrf"]:
        mvrfconfig(vars.D1, cli_type=data.cli_type)
    else:
        pass
    yield
    if st.get_func_name(request) in ["test_ft_snmp_rest_v2_v3_inform_trap_mgmtvrf",
                                      "test_ft_snmp_gnmi_v2_v3_inform_trap_mgmtvrf"]:
        st.rest_delete(vars.D1, path=data.udp_url)
        st.rest_delete(vars.D1, path=data.tag_url)
        st.rest_delete(vars.D1, path=data.param_url)
        mvrfconfig(vars.D1, no_form=True, cli_type=data.cli_type)
    elif st.get_func_name(request) == 'test_ft_snmp_cli_v2_udp_intf_trap':
        if not intf_obj.config_ifname_type(vars.D1, config=data.revert_mode, cli_type=data.cli_type):
            st.report_fail("msg", "Failed to configure interface naming mode")
    else:
        pass


def initialize_variables():
    data.clear()
    data.ro_community = 'test_123'
    data.location = 'hyderabad'
    data.contact = "Admin"
    data.mgmt_int = 'eth0'
    data.v1_community = 'Sonic'
    data.v2_community = cutils.random_string(slen=14)
    data.group_name = cutils.random_string(slen=15)
    data.v3_view = cutils.random_string(slen=6)
    data.host = mutils.ensure_service_params(vars.D1, "snmptrap", "ip")
    data.traps_version = "v1"
    data.group_snmp_version = "v3"
    data.oid_tree = "1"
    data.v3_user1 = cutils.random_username(slen=10)
    data.v3_user2 = cutils.random_username(slen=11)
    data.v3_user3 = cutils.random_username(slen=12)
    data.v3_user4 = cutils.random_username(slen=13)
    data.v3_user5 = cutils.random_username(slen=14)
    data.v3_user6 = cutils.random_username(slen=14)
    data.v3_user7 = cutils.random_username(slen=14)
    data.v3_user8 = cutils.random_username(slen=14)
    data.auth_protocol = ["md5", "sha"]
    data.auth_password = cutils.random_string(slen=10)
    data.sha_auth_password = cutils.random_string(slen=10)
    data.md5_auth_password = cutils.random_string(slen=10)
    data.aes_priv_password = cutils.random_string(slen=10)
    data.des_priv_password = cutils.random_string(slen=10)
    data.sha_auth_encrypted_password = ""
    data.md5_auth_encrypted_password = ""
    data.sha_aes_priv_encrypted_password = ""
    data.sha_des_priv_encrypted_password = ""
    data.md5_aes_priv_encrypted_password = ""
    data.md5_des_priv_encrypted_password = ""
    data.priv_protocol = ["DES", "AES-128"]
    data.verify_priv_protocol = ["des", "aes-128", "aes"]
    data.verify_security_levl = ["no-auth-no-priv", "auth-no-priv", "auth-priv"]
    data.priv_password = cutils.random_string(slen=10)
    data.auth_privacy_encrypted = "enable"
    data.filter_cli = "-One"
    data.vlan = str(cutils.random_vlan_list()[0])
    data.source_mac = "00:0a:01:00:00:01"
    data.filter = '-Oqv'
    data.oid_engine_id = "1.3.6.1.6.3.10.2.1.1.0"
    data.user_inform = "sonic_user"
    data.cli_type = "klish"
    data.rest_community = "sonic_rest"
    data.gnmi_community = "sonic_gnmi"
    data.snmpv3_support = True
    data.udp_port = 12345
    data.encyption = True
    data.klish_snmp_delay = 25
    data.snmp_server_delay = 10
    data.wait_time = 30
    data.link_status_delay = 5
    data.intf_ip = "1.2.2.1"
    data.tg_ip = "1.2.2.2"
    data.mask=24
    data.udp_url = "/restconf/data/ietf-snmp:snmp/target=targetEntry1/udp"
    data.tag_url = "/restconf/data/ietf-snmp:snmp/target=targetEntry1/tag"
    data.param_url = "/restconf/data/ietf-snmp:snmp/target-params=targetEntry1"


def snmp_pre_config():
    """
    SNMP pre config
    """
    global ipaddress, snmp_engine_id, restart_snmp_traps
    ipaddress_list = basic_obj.get_ifconfig_inet(vars.D1, data.mgmt_int)
    st.log("Checking Ip address of the Device ")
    if not ipaddress_list:
        st.report_env_fail("ip_verification_fail")
    ipaddress = ipaddress_list[0]
    st.log("Device ip address - {}".format(ipaddress))
    if not ipfeature.ping(vars.D1, ipaddress, family='ipv4', external=True):
        st.error("Ping reachability is failed between SNMP server and Device.")
    restart_snmp_traps = "snmptrapd -A -f -n -m ALL -M /etc/snmp/mibs/ -c snmptrapd.conf -Lf /var/log/snmptrap.log"
    # To get SNMP engine ID of the switch.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "community": {"name": data.v1_community, "no_form": False}})
    st.wait(data.klish_snmp_delay)
    if not snmp_obj.poll_for_snmp(vars.D1, data.wait_time, 1, ipaddress=ipaddress,
                                  oid=data.oid_engine_id, community_name=data.v1_community, version="2"):
        st.log("Post SNMP config , snmp is not working")
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_engine_id,
                                                  community_name=data.v1_community, filter=data.filter_cli,
                                                  version="2", timeout=5)
    if get_snmp_output:
        snmp_engine_id = get_snmp_output[0]
        snmp_engine_id = snmp_engine_id.replace(".1.3.6.1.6.3.10.2.1.1.0 = Hex-STRING:", "").replace(" ", "")
    else:
        snmp_engine_id = "UNKNOWN"

    st.log("Engine ID of the switch is:{}".format(snmp_engine_id))
    if data.encyption:
        # Key generation of MD5 and DES
        st.log("Authentication password of MD5 is:{}".format(data.md5_auth_password))
        st.log("Privacy password of DES is :{}".format(data.des_priv_password))
        st.log("Authentication password of SHA is:{}".format(data.sha_auth_password))
        st.log("Privacy password of AES is:{}".format(data.aes_priv_password))
        st.log("Generating keys for Authentication password of MD5 and Privacy password of DES")
        auth_priv_keys = snmp_obj.get_auth_priv_keys(auth_type=data.auth_protocol[0], auth_password=data.md5_auth_password,
                                                     engine_id=snmp_engine_id, priv_type=data.verify_priv_protocol[0],
                                                     priv_password=data.des_priv_password)
        st.log("Authentication-MD5 and Privacy-DES keys:{}".format(auth_priv_keys))
        auth_key_1 = auth_priv_keys[0]
        priv_key_1 = auth_priv_keys[1]
        data.md5_auth_encrypted_password = auth_key_1.replace("authKey: 0x", "")
        data.md5_des_priv_encrypted_password = priv_key_1.replace("privKey: 0x", "")
        st.log("Authentication key of MD5 is:{}".format(data.md5_auth_encrypted_password))
        st.log("Privacy key of MD5-DES is :{}".format(data.md5_des_priv_encrypted_password))

        # Key generation of MD5 and AES
        st.log("Generating keys for Authentication password of MD5 and Privacy password of AES")
        auth_priv_keys = snmp_obj.get_auth_priv_keys(auth_type=data.auth_protocol[0], auth_password=data.md5_auth_password,
                                                     engine_id=snmp_engine_id, priv_type=data.verify_priv_protocol[2],
                                                     priv_password=data.aes_priv_password)
        st.log("Authentication-MD5 and Privacy-AES keys:{}".format(auth_priv_keys))
        #auth_key_2 = auth_priv_keys[0]
        priv_key_2 = auth_priv_keys[1]
        data.md5_aes_priv_encrypted_password = priv_key_2.replace("privKey: 0x", "")
        st.log("Authentication key of MD5 is:{}".format(data.md5_auth_encrypted_password))
        st.log("Privacy key of MD5-AES is :{}".format(data.md5_aes_priv_encrypted_password))

        # Key generation of SHA and DES
        st.log("Generating keys for Authentication password of SHA and Privacy password of DES")
        auth_priv_keys = snmp_obj.get_auth_priv_keys(auth_type=data.auth_protocol[1], auth_password=data.sha_auth_password,
                                                     engine_id=snmp_engine_id, priv_type=data.verify_priv_protocol[0],
                                                     priv_password=data.des_priv_password)
        st.log("Authentication-SHA and Privacy-DES keys:{}".format(auth_priv_keys))
        auth_key_1 = auth_priv_keys[0]
        priv_key_1 = auth_priv_keys[1]
        data.sha_auth_encrypted_password = auth_key_1.replace("authKey: 0x", "")
        data.sha_des_priv_encrypted_password = priv_key_1.replace("privKey: 0x", "")
        st.log("Authentication key of SHA is:{}".format(data.sha_auth_encrypted_password))
        st.log("Privacy key of SHA-DES is :{}".format(data.sha_des_priv_encrypted_password))

        # Key generation of SHA and AES
        st.log("Generating keys for Authentication password of SHA and Privacy password of AES")
        auth_priv_keys = snmp_obj.get_auth_priv_keys(auth_type=data.auth_protocol[1], auth_password=data.sha_auth_password,
                                                     engine_id=snmp_engine_id, priv_type=data.verify_priv_protocol[2],
                                                     priv_password=data.aes_priv_password)
        st.log("Authentication-SHA and Privacy-AES keys:{}".format(auth_priv_keys))
        #auth_key_2 = auth_priv_keys[0]
        priv_key_2 = auth_priv_keys[1]
        data.sha_aes_priv_encrypted_password = priv_key_2.replace("privKey: 0x", "")
        st.log("Authentication key of SHA is:{}".format(data.sha_auth_encrypted_password))
        st.log("Privacy key of SHA-AES is :{}".format(data.sha_aes_priv_encrypted_password))

    #TG port handler
    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg2, data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    data.tg = data.tg1


def snmp_cli_config():
    """
    To config SNMP community for v1,v2 and v3 parameters such as view, group, user, traps,host using klish CLI commands.
    """
    st.log("Getting ifindex for the interface provided in the testbed")
    global ifAdminStatus_oid, ifAdminStatus_link_up_status, ifAdminStatus_link_down_status,\
        ifAdminStatus_link_up_trap_status, ifAdminStatus_link_down_trap_status, ifDescr_oid
    interface = st.get_other_names(vars.D1, [vars.D1T1P1])[0] if '/' in vars.D1T1P1 else vars.D1T1P1
    st.debug("port is: {}".format(interface))
    index = int(interface.replace("Ethernet", "")) + 1
    ifAdminStatus_oid = "1.3.6.1.2.1.2.2.1.7."+str(index)
    ifDescr_oid = "1.3.6.1.2.1.2.2.1.2.{}"
    ifAdminStatus_link_up_status = ".{} = INTEGER: 1".format(ifAdminStatus_oid)
    ifAdminStatus_link_down_status = ".{} = INTEGER: 2".format(ifAdminStatus_oid)
    ifAdminStatus_link_down_trap_status = "ifAdminStatus.{} = INTEGER: down".format(index)
    ifAdminStatus_link_up_trap_status = "ifAdminStatus.{} = INTEGER: up".format(index)
    st.log("Configuring SNMP parameters such as community, view, group, users and trap host")
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type,
                              "globals": {"contact": [data.contact, True], "location": [data.location, True],
                                          }, "traps": "enable"})
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "community": {"name": data.v2_community, "no_form": False}})
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type,
                              "view": {"name": data.v3_view, "oid": data.oid_tree, "option": "included",
                                       "no_form": False}})
    if data.snmpv3_support:
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type,
                                  "groups": {"name": data.group_name, "version": {"type": data.group_snmp_version,
                                                                                  "options": "noauth"},
                                             "operations": {"read_view": data.v3_view, "write_view": data.v3_view,
                                                            "notify_view": data.v3_view}, "no_form": False}})
        if data.encyption:
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type,
                                      "user": {"name": data.v3_user5, "group": data.group_name,
                                               "encrypted": data.auth_privacy_encrypted,
                                               "auth": data.auth_protocol[1],
                                               "auth_pwd": data.sha_auth_encrypted_password, "priv": data.priv_protocol[0],
                                               "priv_pwd": data.sha_des_priv_encrypted_password, "no_form": False}})
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user1, "group": data.group_name,
                                                                      "no_form": False}})
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user2, "group": data.group_name,
                                                                      "auth": data.auth_protocol[0],
                                                                      "auth_pwd": data.auth_password,
                                                                      "no_form": False}})
        if data.encyption:
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user3, "encrypted": "enable",
                                                                          "group": data.group_name,
                                      "auth": data.auth_protocol[1], "auth_pwd": data.sha_auth_encrypted_password,
                                      "no_form": False}})
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user4, "group": data.group_name,
                                  "auth": data.auth_protocol[0], "auth_pwd": data.auth_password,
                                  "priv": data.priv_protocol[1], "priv_pwd": data.priv_password, "no_form": False}})
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.user_inform,
                                                                      "group": data.group_name, "no_form": False}})
        if data.encyption:
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type,
                                      "user": {"name": data.v3_user6, "group": data.group_name,
                                               "encrypted": data.auth_privacy_encrypted,
                                               "auth": data.auth_protocol[0],
                                               "auth_pwd": data.md5_auth_encrypted_password, "priv": data.priv_protocol[0],
                                               "priv_pwd": data.md5_des_priv_encrypted_password, "no_form": False}})
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type,
                                      "user": {"name": data.v3_user7, "group": data.group_name,
                                               "encrypted": data.auth_privacy_encrypted,
                                               "auth": data.auth_protocol[0],
                                               "auth_pwd": data.md5_auth_encrypted_password, "priv": data.priv_protocol[1],
                                               "priv_pwd": data.md5_aes_priv_encrypted_password, "no_form": False}})
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type,
                                      "user": {"name": data.v3_user8, "group": data.group_name,
                                               "encrypted": data.auth_privacy_encrypted,
                                               "auth": data.auth_protocol[1],
                                               "auth_pwd": data.sha_auth_encrypted_password, "priv": data.priv_protocol[1],
                                               "priv_pwd": data.sha_aes_priv_encrypted_password, "no_form": False}})

    st.log("Getting the configuring SNMP parameters such as contact info, location,traps, engine id")
    snmp_obj.show(vars.D1, cli_type=data.cli_type)

    st.log("Getting configured SNMP parameters such as community, view, group, user and trap host")
    snmp_module = ["community", "group", "view", "user", "host"]
    for mode in snmp_module:
        snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type=mode)
        st.log(snmp_output)

def snmp_cli_config_verify():
    """
    To verify the configured SNMP parameters such as community, view, group, user, traps and host details using
    klish cli commands
    """
    st.log("Verifying configured SNMP parameters such as contact info, location,traps, engine id")
    filter_data = {"traps": "enable", "location": data.location, "contact": data.contact}
    if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="server", data=filter_data):
        st.report_fail("snmp_parameters_config_unsuccessful", data.contact, data.location, "traps")

    st.log("Verifying Configured SNMPv1 community details")
    filter_data = {"community": data.v1_community, "group": "None"}
    if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="community", data=filter_data):
        st.report_fail("snmp_config_unsuccessful", "Community", data.v1_community)

    st.log("Verifying Configured SNMPv2 community details")
    filter_data = {"community": data.v2_community, "group": "None"}
    if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="community", data=filter_data):
        st.report_fail("snmp_config_unsuccessful", "Community", data.v2_community)
    if data.snmpv3_support:
        st.log("Verifying Configured SNMPv3 view details")
        filter_data = {"view_name": data.v3_view, "view_oid": data.oid_tree, "view_type": "included"}
        if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="view", data=filter_data):
            st.report_fail("snmp_config_unsuccessful", "View Name", data.v3_view)

        st.log("Verifying Configured SNMPv3 group details")
        filter_data = {"grp_name": data.group_name, "grp_model": data.group_snmp_version,
                       "grp_security": "no-auth-no-priv",
                       "grp_read_view": data.v3_view, "grp_write_view": data.v3_view, "grp_notify_view": data.v3_view}
        if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="group", data=filter_data):
            st.report_fail("snmp_config_unsuccessful", "Group Name", data.group_name)

        st.log("Verifying Configured SNMPv3 user-1 details")
        filter_data = {"user_name": data.v3_user1, "usr_grp_name": data.group_name}
        if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
            st.report_fail("snmp_config_unsuccessful", "User Name", data.v3_user1)

        st.log("Verifying Configured SNMPv3 user-2 details")
        filter_data = {"user_name": data.v3_user2, "usr_grp_name": data.group_name,
                       "usr_authentication": data.auth_protocol[0]}
        if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
            st.report_fail("snmp_config_unsuccessful", "User Name", data.v3_user2)
        if data.encyption:
            st.log("Verifying Configured SNMPv3 user-3 details")
            filter_data = {"user_name": data.v3_user3, "usr_grp_name": data.group_name,
                           "usr_authentication": data.auth_protocol[1]}
            if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
                st.report_fail("snmp_config_unsuccessful", "User Name", data.v3_user3)

        st.log("Verifying Configured SNMPv3 user-4 details")
        filter_data = {"user_name": data.v3_user4, "usr_grp_name": data.group_name,
                       "usr_authentication": data.auth_protocol[0],
                       "usr_privacy": data.verify_priv_protocol[1]}
        if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
            st.report_fail("snmp_config_unsuccessful", "User Name", data.v3_user4)
        if data.encyption:
            st.log("Verifying Configured SNMPv3 user-5 details")
            filter_data = {"user_name": data.v3_user5, "usr_grp_name": data.group_name,
                           "usr_authentication": data.auth_protocol[1],
                           "usr_privacy": data.verify_priv_protocol[0]}
            if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
                st.report_fail("snmp_config_unsuccessful", "User Name", data.v3_user5)

            st.log("Verifying Configured SNMPv3 informs user details")
            filter_data = {"user_name": data.user_inform, "usr_grp_name": data.group_name}
            if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
                st.report_fail("snmp_config_unsuccessful", "User Name", data.user_inform)

            st.log("Verifying Configured SNMPv3 user-6 details")
            filter_data = {"user_name": data.v3_user6, "usr_grp_name": data.group_name,
                           "usr_authentication": data.auth_protocol[0],
                           "usr_privacy": data.verify_priv_protocol[0]}
            if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
                st.report_fail("snmp_config_unsuccessful", "User Name", data.v3_user6)

            st.log("Verifying Configured SNMPv3 user-7 details")
            filter_data = {"user_name": data.v3_user7, "usr_grp_name": data.group_name,
                           "usr_authentication": data.auth_protocol[0],
                           "usr_privacy": data.verify_priv_protocol[1]}
            if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
                st.report_fail("snmp_config_unsuccessful", "User Name", data.v3_user7)

            st.log("Verifying Configured SNMPv3 user-8 details")
            filter_data = {"user_name": data.v3_user8, "usr_grp_name": data.group_name,
                           "usr_authentication": data.auth_protocol[1],
                           "usr_privacy": data.verify_priv_protocol[1]}
            if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="user", data=filter_data):
                st.report_fail("snmp_config_unsuccessful", "User Name", data.v3_user8)


def snmp_cli_unconfig():
    """
    To unconfig SNMP v1,v2 and v3 config using klish CLI commands.
    """

    st.log("Un-configuring SNMP V1, V2 and V3 parameters")
    if data.snmpv3_support:
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user1, "no_form": True}})
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user2, "no_form": True}})
        if data.encyption:
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user3, "no_form": True}})
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user4, "no_form": True}})
        if data.encyption:
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user5, "no_form": True}})
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user6, "no_form": True}})
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user7, "no_form": True}})
            snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.v3_user8, "no_form": True}})
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "user": {"name": data.user_inform, "no_form": True}})
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type,
                              "globals": {"contact": [data.contact, False], "location": [data.location, False],
                                          },
                              "traps": "disable", "community": {"name": data.v1_community, "no_form": True}})
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "community": {"name": data.v2_community, "no_form": True}})
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "community": {"name": data.rest_community, "no_form": True}})
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "community": {"name": data.gnmi_community, "no_form": True}})
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "view": {"name": data.v3_view, "oid": data.oid_tree,
                                                                  "no_form": True}})
    if data.snmpv3_support:
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "groups": {"name": data.group_name,
                                                                        "version": {"type": data.group_snmp_version,
                                                                                    "options": "noauth"},
                                                                        "no_form": True}})
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
    st.log("Getting the configuring SNMP parameters such as contact info, location,traps, engine id")
    snmp_obj.show(vars.D1, cli_type=data.cli_type)

    st.log("Getting configured SNMP parameters such as community, view, group, user and trap host")
    snmp_module = ["community", "group", "view", "user", "host"]
    for mode in snmp_module:
        snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type=mode)
        st.log(snmp_output)

    # Remove trap user from snmp host receiver to avoid duplicate entries in server and restart server.
    basic_obj.delete_line_using_specific_string(ssh_conn_obj, snmp_engine_id, "/etc/snmp/snmptrapd.conf", "server")
    basic_obj.service_operations(ssh_conn_obj, "snmptrapd", "restart", "server")
    st.log("Verifying SNMP service status after trap v3 is unconfigured on host")
    if not poll_wait(basic_obj.verify_service_status, 90, ssh_conn_obj, 'snmptrapd', "server"):
        st.report_fail("snmp_service_not_up")
    # Create separate session to set snmptraps path on server because prompt will be stopped new line
    ip = mutils.ensure_service_params(vars.D1, "snmptrap", "ip")
    username = mutils.ensure_service_params(vars.D1, "snmptrap", "username")
    password = mutils.ensure_service_params(vars.D1, "snmptrap", "password")
    # Connect to the linux machine and check
    ssh_conn_obj1 = connect_to_device(ip, username, password)
    if not ssh_conn_obj1:
        st.report_tc_fail("ssh_connection_failed", ip)
    execute_command(ssh_conn_obj1, restart_snmp_traps)
    ssh_disconnect(ssh_conn_obj1)
    if not poll_wait(snmptrapd_checking, 90):
        st.report_fail("snmptrapd_not_running")


def snmp_trap_pre_config():
    global capture_file, ssh_conn_obj, snmp_engine_id
    ip = mutils.ensure_service_params(vars.D1, "snmptrap", "ip")
    username = mutils.ensure_service_params(vars.D1, "snmptrap", "username")
    password = mutils.ensure_service_params(vars.D1, "snmptrap", "password")
    path = mutils.ensure_service_params(vars.D1, "snmptrap", "path")

    # Connect to the linux machine and check
    ssh_conn_obj = connect_to_device(ip, username, password)
    if not ssh_conn_obj:
        st.report_tc_fail("ssh_connection_failed", ip)

    # start capture on the linux machine
    capture_file = path


def snmp_trap_post_config():
    clear_cmd = "echo > {}".format(capture_file)
    st.log("Clearing the snmptrap log with command '{}'".format(clear_cmd))
    execute_command(ssh_conn_obj, clear_cmd)


def snmptrapd_checking():
    retval = False

    # check and start the snmptrap on the given server.
    ps_cmd = "ps -ealf | grep snmptrapd | grep -v grep"
    st.log("Checking for snmptrap process existence with command '{}'".format(ps_cmd))
    output = execute_command(ssh_conn_obj, ps_cmd)
    ps_lines = "\n".join(output.split("\n")[:-1])

    if "snmptrapd" in ps_lines:
        retval = True

    return retval


def device_eth0_ip_addr():
    """
    To get the ip address of device after reboot.
    """
    ipaddress = st.get_mgmt_ip(vars.D1)
    st.log("Device ip address - {}".format(ipaddress))
    if not ipfeature.ping(vars.D1, ipaddress, family='ipv4', external=True):
        st.error("Ping reachability is failed between SNMP server and Device.")

def perform_rest_call(op, device, url, data=None):
    op = op.lower()
    retval = {}
    for _ in range(1,4):
        try:
            if op == "read":
                retval = st.rest_read(device, path=url)
            if op == "create":
                retval = st.rest_create(device, path=url, data=data)
            if op == "update":
                retval = st.rest_update(device, path=url, data=data)
            if op == "delete":
                retval = st.rest_delete(device, path=url)
            break
        except Exception as e:
            st.error(e)
    return retval

def verify_intf_description(index, description):
    get_snmp_output = snmp_obj.walk_snmp_operation(connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                       oid=ifDescr_oid.format(index), timeout=5,
                                                       version="2", community_name=data.v2_community)
    st.debug("SNMP Output: {}".format(get_snmp_output))
    intf_name = get_snmp_output[0].split(":")[-1].strip()
    if not description in intf_name:
        st.error("interface name: {} not found in SNMP Walk".format(description))
        return False
    return True

def check_for_trap(ssh_conn_obj, read_cmd, res, trap):
    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]
    result = any(res in x for x in trap_lines)
    if not result:
        return False
    result = any(trap in x for x in trap_lines)
    if not result:
        return False
    return True



@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv2_cli
def test_ft_snmp_cli_v2():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify that able to perform SNMPv2 get,bulkwalk and walk operations.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.log("Verify that able to perform SNMPv2 get,bulkwalk and walk operations")
    result = 0
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    st.wait(data.snmp_server_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1, expected_output=ifAdminStatus_link_down_status,
                                                        ipaddress=ipaddress, oid=ifAdminStatus_oid,
                                                        community_name=data.v2_community, filter=data.filter_cli,
                                                        version="2", timeout=5)
    st.log("Link status by using SNMPv2 from the SNMP output:{}".format(get_snmp_output[0]))
    if not get_snmp_output[0] == ifAdminStatus_link_down_status:
        st.log(" Link status by using SNMPv2 get operation is not matching")
        st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    st.wait(data.link_status_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1, expected_output=ifAdminStatus_link_up_status,
                                                         ipaddress=ipaddress, oid=ifAdminStatus_oid,
                                                         community_name=data.v2_community, filter=data.filter_cli,
                                                         version="2", timeout=5)
    st.log("Link status by using SNMPv2 from the SNMP output: {} ".format(get_snmp_output[0]))
    if not get_snmp_output[0] == ifAdminStatus_link_up_status:
        st.log(" Link status by using SNMPv2 walk operation is not matching")
        st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    st.wait(data.link_status_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1, expected_output=ifAdminStatus_link_down_status,
                                                        ipaddress=ipaddress, oid=ifAdminStatus_oid,
                                                        community_name=data.v2_community, filter=data.filter_cli,
                                                        version="2", bulk_walk="snmpbulkwalk", timeout=5)
    for match in get_snmp_output:
        if ifAdminStatus_link_down_status in match:
            result = 1
            break
    if result == 0:
        st.log(" Link status by using SNMPv2 bulkwalk operation is not matching")
        st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
    elif result == 1:
        pass
    else:
        st.log("Invalid result for SNMPv2 bulkwalk operation")
        st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    st.wait(data.link_status_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    st.log("Verification of SNMPv2 get,bulkwalk and walk operations are successful")
    st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_cli
def test_ft_snmp_cli_v3_user():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify v3 access to switch and perform SNMP get and walk operations when user is configured without
    authentication and privacy protocols.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v3 access to switch and perform SNMP get and walk operations when user "
              "is configured and authentication & privacy protocols are not configured.")
    if data.snmpv3_support:
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1,
                                                            expected_output=ifAdminStatus_link_down_status,
                                                            connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                            oid=ifAdminStatus_oid, security_lvl="noAuthNoPriv",
                                                            filter=data.filter_cli, version="3", usr_name=data.v3_user1,
                                                            timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_down_status:
            st.log(" Link status by using SNMPv3 user without auth and privacy get operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1,
                                                             expected_output=ifAdminStatus_link_up_status,
                                                             connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                             oid=ifAdminStatus_oid, security_lvl="noAuthNoPriv",
                                                             filter=data.filter_cli, version="3",
                                                             usr_name=data.v3_user1, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_up_status:
            st.log(" Link status by using SNMPv3 user without auth and privacy walk operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.log("Verification of v3 access to switch with SNMPv3 user is successful")
        st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_cli
def test_ft_snmp_cli_v3_user_auth():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify v3 access to switch and perform SNMP get and walk operations when user is configured with authentication
    protocols and without privacy protocols.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v3 access to switch and perform SNMP get and walk operations when user "
              "is configured and authentication type is MD5.")
    if data.snmpv3_support:
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1,
                                                            expected_output=ifAdminStatus_link_down_status,
                                                            connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                            oid=ifAdminStatus_oid, security_lvl="authNoPriv",
                                                            filter=data.filter_cli, version="3", usr_name=data.v3_user2,
                                                            auth_type=data.auth_protocol[0],
                                                            auth_pwd=data.auth_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_down_status:
            st.log(" Link status by using SNMPv3 user with auth and without privacy get operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1,
                                                             expected_output=ifAdminStatus_link_up_status,
                                                             connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                             oid=ifAdminStatus_oid, security_lvl="authNoPriv",
                                                             filter=data.filter_cli, version="3",
                                                             usr_name=data.v3_user2, auth_type=data.auth_protocol[0],
                                                             auth_pwd=data.auth_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_up_status:
            st.log(" Link status by using SNMPv3 user with auth and without privacy walk operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.log("Verification of v3 access to switch with SNMPv3 user and authentication type-MD5 is successful")
        st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli_encrypt_rest_gnmi
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_cli
def test_ft_snmp_cli_v3_user_auth_encrypt():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify v3 access to switch and perform SNMP get and walk operations when user is configured with authentication
    encryption password and without privacy protocols.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v3 access to switch and perform SNMP get and walk operations when user "
              "is configured and authentication encryption type is SHA.")
    if data.snmpv3_support:
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1,
                                                            expected_output=ifAdminStatus_link_down_status,
                                                            connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                            oid=ifAdminStatus_oid, security_lvl="authNoPriv",
                                                            filter=data.filter_cli, version="3", usr_name=data.v3_user3,
                                                            auth_type=data.auth_protocol[1],
                                                            auth_pwd=data.sha_auth_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_down_status:
            st.log(" Link status by using SNMPv3 user with auth encrypt and without "
                   "privacy get operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1,
                                                             expected_output=ifAdminStatus_link_up_status,
                                                             connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                             oid=ifAdminStatus_oid, security_lvl="authNoPriv",
                                                             filter=data.filter_cli, version="3",
                                                             usr_name=data.v3_user3, auth_type=data.auth_protocol[1],
                                                             auth_pwd=data.sha_auth_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_up_status:
            st.log(" Link status by using SNMPv3 user with auth encrypt and "
                   "without privacy walk operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.log("Verification of v3 access to switch with SNMPv3 user and authentication encryption "
               "type-SHA is successful")
        st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_cli
def test_ft_snmp_cli_v3_user_auth_privacy():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify v3 access to switch and perform SNMP get and walk operations when user is configured with authentication
    protocols and privacy protocols.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v3 access to switch and perform SNMP get and walk operations when user "
              "is configured and authentication type is MD5 and privacy type is AES.")
    if data.snmpv3_support:
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1,
                                                            expected_output=ifAdminStatus_link_down_status,
                                                            connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                            oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                            filter=data.filter_cli, version="3", usr_name=data.v3_user4,
                                                            auth_type=data.auth_protocol[0],
                                                            auth_pwd=data.auth_password,
                                                            privacy_type=data.verify_priv_protocol[2],
                                                            privacy_pwd=data.priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_down_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy get operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1,
                                                             expected_output=ifAdminStatus_link_up_status,
                                                             connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                             oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                             filter=data.filter_cli, version="3",
                                                             usr_name=data.v3_user4, auth_type=data.auth_protocol[0],
                                                             auth_pwd=data.auth_password,
                                                             privacy_type=data.verify_priv_protocol[2],
                                                             privacy_pwd=data.priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_up_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy walk operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.log("Verification of v3 access to switch with SNMPv3 user and authentication type-MD5 "
               "and privacy type-AES is successful")
        st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli_encrypt_rest_gnmi
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_cli
def test_ft_snmp_cli_v3_user_auth_privacy_encrypt():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify v3 access to switch and perform SNMP get and walk operations when user is configured with authentication
    encryption password and privacy encryption password.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v3 access to switch and perform SNMP get and walk operations when user "
              "is configured and authentication encryption type is SHA and privacy encryption type is DES.")
    if data.snmpv3_support:
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1,
                                                            expected_output=ifAdminStatus_link_down_status,
                                                            connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                            oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                            filter=data.filter_cli, version="3", usr_name=data.v3_user5,
                                                            auth_type=data.auth_protocol[1],
                                                            auth_pwd=data.sha_auth_password,
                                                            privacy_type=data.verify_priv_protocol[0],
                                                            privacy_pwd=data.des_priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_down_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy encrypt get operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1,
                                                             expected_output=ifAdminStatus_link_up_status,
                                                             connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                             oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                             filter=data.filter_cli, version="3",
                                                             usr_name=data.v3_user5, auth_type=data.auth_protocol[1],
                                                             auth_pwd=data.sha_auth_password,
                                                             privacy_type=data.verify_priv_protocol[0],
                                                             privacy_pwd=data.des_priv_password,
                                                             timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_up_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy encrypt walk operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.log("Verification of v3 access to switch with SNMPv3 user and authentication encryption "
               "type-SHA and privacy encryption type-DES is successful")
        st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv2_trap_cli
def test_ft_snmp_cli_v2_inform_trap():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify that trap and inform when trap/inform is configured through CLI with V2 version.
    """
    st.banner("Verify that trap and inform when trap/inform is configured through CLI with SNMPv2 version.")
    check_flag = snmptrapd_checking()
    if not check_flag:
        st.report_fail("snmptrapd_not_running")
    clear_cmd = "echo " " > {}".format(capture_file)
    execute_command(ssh_conn_obj, clear_cmd)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    st.wait(data.link_status_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    # Configure SNMP Traps with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host,
                                                                  "community": {"name": data.v2_community,
                                                                                "traps": "v2c"}, "no_form": False}})
    snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
    st.log(snmp_output)
    # Wait to effect configuration change until restart is attempted
    st.wait(data.klish_snmp_delay)
    # trigger trap on DUT
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    # Wait to check the traps before un-configuration of traps.
    st.wait(data.snmp_server_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    # get data from capture
    read_cmd = "cat {}".format(capture_file)

    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]
    result_1 = "TRAP2, SNMP v2c, community {}".format(data.v2_community)
    result = any(result_1 in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmptrap_not_generated", "invalid SNMP version and type")
    result = any(ifAdminStatus_link_down_trap_status in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmptrap_not_generated", "linkDown")

    # Un-configure SNMP Traps with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
    # Configure SNMP Informs with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host,
                                                                  "community": {"name": data.v2_community,
                                                                                "informs": "True"}, "no_form": False}})
    snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
    st.log(snmp_output)
    # Wait to effect configuration change until restart is attempted
    st.wait(data.klish_snmp_delay)
    # trigger trap on DUT
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    # Wait to check the traps before un-configuration of informs.
    st.wait(data.snmp_server_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    # get data from capture
    read_cmd = "cat {}".format(capture_file)

    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]
    result_1 = "INFORM, SNMP v2c, community {}".format(data.v2_community)
    result = any(result_1 in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmptrap_not_generated", "invalid SNMP version and type")
    result = any(ifAdminStatus_link_up_trap_status in x for x in trap_lines)
    # Un-configure SNMP informs with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
    if result == 0:
        st.report_fail("snmptrap_not_generated", "linkUp")
    else:
        st.log("Verification of SNMPv2 trap and inform is successful")
        st.report_pass("snmp_trap_informs_status", "SNMPv2c traps and informs", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_trap_cli
def test_ft_snmp_cli_v3_inform_trap():
    """
        Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
        Verify that trap and inform when trap/inform is configured through CLI with V3 version.
        """
    st.banner("Verify that trap and inform when trap/inform is configured through CLI with SNMPv3 version.")
    if data.snmpv3_support:
        check_flag = snmptrapd_checking()
        if not check_flag:
            st.report_fail("snmptrapd_not_running")
        clear_cmd = "echo " " > {}".format(capture_file)
        execute_command(ssh_conn_obj, clear_cmd)
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        # Configure SNMP Traps with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host,
                                                                      "user": {"name": data.v3_user1,
                                                                               "traps": "noauth"}, "no_form": False}})
        snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
        st.log(snmp_output)
        # Add trap user in SNMP server to allow traps for v3 user
        enable_v3_trap_user_on_server = "echo -ne \"createUser -e 0x{} {}\">>/etc/snmp/snmptrapd.conf". \
            format(snmp_engine_id, data.v3_user1)
        execute_command(ssh_conn_obj, enable_v3_trap_user_on_server)
        basic_obj.service_operations(ssh_conn_obj, "snmptrapd", "restart", "server")
        st.log("Verifying SNMP service status after trap v3 is configured on host")
        if not poll_wait(basic_obj.verify_service_status, 90, ssh_conn_obj, 'snmptrapd', "server"):
            st.report_fail("snmp_service_not_up")

        # Create separate session to set snmptraps path on server because prompt will be stopped new line
        ip = mutils.ensure_service_params(vars.D1, "snmptrap", "ip")
        username = mutils.ensure_service_params(vars.D1, "snmptrap", "username")
        password = mutils.ensure_service_params(vars.D1, "snmptrap", "password")

        # Connect to the linux machine and check
        ssh_conn_obj1 = connect_to_device(ip, username, password)
        if not ssh_conn_obj1:
            st.report_tc_fail("ssh_connection_failed", ip)
        execute_command(ssh_conn_obj1, restart_snmp_traps)
        ssh_disconnect(ssh_conn_obj1)
        if not poll_wait(snmptrapd_checking, 90):
            st.report_fail("snmptrapd_not_running")
        # Server is taking some time to receive traps after docker restart.
        st.wait(data.klish_snmp_delay)
        # trigger trap on DUT
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        # Wait to check the traps before un-configuration.
        st.wait(data.snmp_server_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        # get data from capture
        read_cmd = "cat {}".format(capture_file)
        result_1 = "TRAP2, SNMP v3, user {}".format(data.v3_user1)
        result = poll_wait(check_for_trap, 20, ssh_conn_obj, read_cmd, result_1, ifAdminStatus_link_down_trap_status)
        if not result:
            st.report_fail("snmptrap_not_generated", "linkDown")
        # Un-configure SNMP Traps with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
        # Configure SNMP Informs with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host,
                                                                      "user": {"name": data.user_inform,
                                                                               "informs": "noauth"},
                                                                      "no_form": False}})
        snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
        st.log(snmp_output)
        if data.snmpv3_support:
            filter_data = {"target_address": data.host, "target_type": "inform",
                           "target_community_user": data.user_inform,
                           "target_version_security": data.verify_security_levl[0]}
            if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="host", data=filter_data):
                st.report_fail("snmp_config_unsuccessful", "informs host", data.host)
        # Wait to effect configuration change until restart is attempted
        st.wait(data.klish_snmp_delay)
        # trigger trap on DUT
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        # Wait to check the traps before un-configuration of informs.
        st.wait(data.snmp_server_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        # get data from capture
        read_cmd = "cat {}".format(capture_file)
        result_1 = "INFORM, SNMP v3, user {}".format(data.user_inform)
        result = poll_wait(check_for_trap, 20, ssh_conn_obj, read_cmd, result_1, ifAdminStatus_link_up_trap_status)
        # Remove trap user from snmp host receiver to avoid duplicate entries in server and restart server.
        basic_obj.delete_line_using_specific_string(ssh_conn_obj, snmp_engine_id, "/etc/snmp/snmptrapd.conf", "server")
        basic_obj.service_operations(ssh_conn_obj, "snmptrapd", "restart", "server")
        st.log("Verifying SNMP service status after trap v3 is unconfigured on host")
        if not poll_wait(basic_obj.verify_service_status, 90, ssh_conn_obj, 'snmptrapd', "server"):
            st.report_fail("snmp_service_not_up")
        # Create separate session to set snmptraps path on server because prompt will be stopped new line
        ip = mutils.ensure_service_params(vars.D1, "snmptrap", "ip")
        username = mutils.ensure_service_params(vars.D1, "snmptrap", "username")
        password = mutils.ensure_service_params(vars.D1, "snmptrap", "password")
        # Connect to the linux machine and check
        ssh_conn_obj1 = connect_to_device(ip, username, password)
        if not ssh_conn_obj1:
            st.report_tc_fail("ssh_connection_failed", ip)
        execute_command(ssh_conn_obj1, restart_snmp_traps)
        ssh_disconnect(ssh_conn_obj1)
        # Un-configure SNMP informs with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
        if not poll_wait(snmptrapd_checking, 90):
            st.report_fail("snmptrapd_not_running")
        if result == 0:
            st.report_fail("snmptrap_not_generated", "linkUp")
        else:
            st.log("Verification of SNMPv3 trap and inform is successful")
            st.report_pass("snmp_trap_informs_status", "SNMPv3 traps and informs", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmp_cli_fast_reboot
def test_ft_snmp_cli_fast_reboot():
    """
    Author : Surendra Kumar Vella (surendrakumar.vella@broadcom.com)
    Verify that SNMP configuration is retained after fast-reboot.
    Reference Test Bed : D1 --- Mgmt Network
    """

    st.banner("Verify that SNMP configuration is retained after fast-reboot.")
    st.log("performing Config save")
    reboot.config_save(vars.D1)
    st.log("Performing fast-reboot")
    st.reboot(vars.D1, 'fast')
    # Get the ip address of the switch after reboot
    device_eth0_ip_addr()
    st.log("Verifying whether SNMP CLI config is retained after fast-reboot")
    snmp_cli_config_verify()
    st.log("Verification of SNMP configuration is retained after fast-reboot is successful")
    st.report_pass("snmp_cli_config_verified")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmp_cli_access_invalid_credentials
def test_ft_snmp_cli_access_invalid_credentials():
    """
    Author: Surendra Kumar Vella (surendrakumar.vella@broadcom.com)
    Verify the switch access when trying to contact the switch with invalid community and users.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify the switch access when trying to contact the switch with invalid users.")
    if data.snmpv3_support:
        st.log("Performing SNMPv3 get operation with invalid username")
        get_snmp_output = snmp_obj.get_snmp_operation(connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                      oid=ifAdminStatus_oid, security_lvl="noAuthNoPriv",
                                                      filter=data.filter_cli, version="3", usr_name="dummy", timeout=5)
        if "Unknown user name" not in get_snmp_output[1]:
            st.report_fail("snmp_invalid_case_status", "v3", "get", "user", "successful")

        st.log("Performing SNMPv3 walk operation with valid username and invalid authentication password")
        get_snmp_output = snmp_obj.walk_snmp_operation(connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                       oid=ifAdminStatus_oid, security_lvl="authNoPriv",
                                                       filter=data.filter_cli, version="3", usr_name=data.v3_user2,
                                                       auth_type=data.auth_protocol[0], auth_pwd="dummypassword",
                                                       timeout=5)
        if "Authentication failure (incorrect password, community or key)" not in get_snmp_output[1]:
            st.report_fail("snmp_invalid_case_status", "v3", "walk", "auth password", "successful")

        st.log("Performing SNMPv3 get operation with valid username and invalid privacy password")
        get_snmp_output = snmp_obj.get_snmp_operation(connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                      oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                      filter=data.filter_cli, version="3", usr_name=data.v3_user4,
                                                      auth_type=data.auth_protocol[0],
                                                      auth_pwd=data.auth_password,
                                                      privacy_type=data.verify_priv_protocol[0],
                                                      privacy_pwd="dummyprivacy", timeout=5)
        if "No Response" not in get_snmp_output[1]:
            st.report_fail("snmp_invalid_case_status", "v3", "get", "priv password", "successful")
        st.log("Verification of switch access invalid users is successful")
        st.report_pass("snmp_operation_invalid_credentials_status")


@pytest.mark.snmp_cli_encrypt_rest_gnmi
@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmp_cli_rest
def test_ft_snmpv2_cli_config_via_rest():
    """
    Author: Surendra Kumar Vella (surendrakumar.vella@broadcom.com)
    Verify the ability to configure SNMPv2 parameters using REST.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v2 access to switch and perform SNMP get operation when community is configured using REST.")
    data.rest_path = "/restconf/data/ietf-snmp:snmp"
    data.rest_input = {"ietf-snmp:snmp": {"community": [{"index": data.rest_community}]}}
    config_output = st.rest_modify(vars.D1, data.rest_path, data.rest_input)
    st.log(config_output)
    if config_output and config_output["status"] != 204:
        st.report_fail("snmp_community_invalid_error_code", config_output["status"], data.rest_community)

    get_output = st.rest_read(vars.D1, data.rest_path)
    st.log(get_output)
    if get_output and get_output["status"] != 200:
        st.report_fail("snmp_config_unsuccessful", "Community", data.rest_community)
    # Wait to effect configuration change until restart is attempted
    st.wait(data.klish_snmp_delay)
    # snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="community")
    # st.log(snmp_output)
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    st.wait(data.snmp_server_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    count = 1
    increment = 12
    while True:
        get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=ifAdminStatus_oid,
                                                      community_name="Sonic", filter=data.filter_cli,
                                                      version="2", timeout=5, report=False)
        st.log("Link status by using SNMPv2 from the SNMP output: {} ".format(get_snmp_output))
        if get_snmp_output and (get_snmp_output[0] == ifAdminStatus_link_down_status):
            break
        else:
            st.log(" Link status by using SNMPv2 get operation is not matching")
            count += 1
        if count > increment:
            st.log("Max {} tries Exceeded. Exiting..".format(increment))
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.wait(5)
    st.log("Verification of v2 access with community which was created using REST is successful")
    st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli_encrypt_rest_gnmi
@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmp_cli_gnmi
def test_ft_snmpv2_cli_config_via_gnmi():
    """
    Author: Surendra Kumar Vella (surendrakumar.vella@broadcom.com)
    Verify the ability to configure SNMPv2 parameters using gNMI.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v2 access to switch and perform SNMP get operation when community is configured using gNMI.")
    data.gnmi_xpath = "/ietf-snmp:snmp/community"
    data.gnmi_input = {"ietf-snmp:community": [{"index": data.gnmi_community}]}
    gnmi_set_output = gnmi_set(vars.D1, xpath=data.gnmi_xpath, json_content=data.gnmi_input)
    st.debug(gnmi_set_output)
    if not gnmi_set_output:
        st.report_fail('snmp_community_config_gnmi_unsuccessful', "set", data.gnmi_community)
    if not "op: UPDATE" in gnmi_set_output:
        st.report_fail('snmp_community_config_gnmi_unsuccessful', "set", data.gnmi_community)

    gnmi_get_output = gnmi_get(vars.D1, xpath=data.gnmi_xpath)
    st.log(gnmi_get_output)
    if not gnmi_get_output:
        st.report_fail('snmp_community_config_gnmi_unsuccessful', "get", data.gnmi_community)
    if "ietf-snmp:community" not in gnmi_get_output:
        st.report_fail('snmp_community_config_gnmi_unsuccessful', "get", data.gnmi_community)
    # Wait to effect configuration change until restart is attempted
    st.wait(data.klish_snmp_delay)
    # snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="community")
    # st.log(snmp_output)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    st.wait(data.snmp_server_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    count = 1
    increment = 12
    while True:
        get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=ifAdminStatus_oid,
                                                      community_name="Sonic", filter=data.filter_cli,
                                                      version="2", timeout=5, report=False)
        st.log("Link status by using SNMPv2 from the SNMP output: {} ".format(get_snmp_output))
        if get_snmp_output and (get_snmp_output[0] == ifAdminStatus_link_up_status):
            break
        else:
            st.log(" Link status by using SNMPv2 get operation is not matching")
            count += 1
        if count > increment:
            st.log("Max {} tries Exceeded. Exiting..".format(increment))
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.wait(5)
    st.log("Verification of v2 access with community which was created using gNMI is successful")
    st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli_encrypt_rest_gnmi
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_cli
def test_ft_snmp_cli_v3_user_auth_privacy_encrypt_1():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify v3 access to switch and perform SNMP get and walk operations when user is configured with authentication
    encryption password(MD5) and privacy encryption password(DES).
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v3 access to switch and perform SNMP get and walk operations when user "
              "is configured and authentication encryption type is MD5 and privacy encryption type is DES.")
    if data.snmpv3_support:
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1,
                                                            expected_output=ifAdminStatus_link_down_status,
                                                            connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                            oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                            filter=data.filter_cli, version="3", usr_name=data.v3_user6,
                                                            auth_type=data.auth_protocol[0],
                                                            auth_pwd=data.md5_auth_password,
                                                            privacy_type=data.verify_priv_protocol[0],
                                                            privacy_pwd=data.des_priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_down_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy encrypt get operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1,
                                                             expected_output=ifAdminStatus_link_up_status,
                                                             connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                             oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                             filter=data.filter_cli, version="3",
                                                             usr_name=data.v3_user6, auth_type=data.auth_protocol[0],
                                                             auth_pwd=data.md5_auth_password,
                                                             privacy_type=data.verify_priv_protocol[0],
                                                             privacy_pwd=data.des_priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_up_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy encrypt walk operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.log("Verification of v3 access to switch with SNMPv3 user and authentication encryption type-MD5 "
               "and privacy encryption type-DES is successful")
        st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli_encrypt_rest_gnmi
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_cli
def test_ft_snmp_cli_v3_user_auth_privacy_encrypt_2():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify v3 access to switch and perform SNMP get and walk operations when user is configured with authentication
    encryption password(md5) and privacy encryption password(AES-128).
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v3 access to switch and perform SNMP get and walk operations when user "
              "is configured and authentication encryption type is MD5 and privacy encryption type is AES.")
    if data.snmpv3_support:
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1,
                                                            expected_output=ifAdminStatus_link_down_status,
                                                            connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                            oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                            filter=data.filter_cli, version="3", usr_name=data.v3_user7,
                                                            auth_type=data.auth_protocol[0],
                                                            auth_pwd=data.md5_auth_password,
                                                            privacy_type=data.verify_priv_protocol[2],
                                                            privacy_pwd=data.aes_priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_down_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy encrypt get operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1,
                                                             expected_output=ifAdminStatus_link_up_status,
                                                             connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                             oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                             filter=data.filter_cli, version="3",
                                                             usr_name=data.v3_user7, auth_type=data.auth_protocol[0],
                                                             auth_pwd=data.md5_auth_password,
                                                             privacy_type=data.verify_priv_protocol[2],
                                                             privacy_pwd=data.aes_priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_up_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy encrypt walk operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.log("Verification of v3 access to switch with SNMPv3 user and authentication encryption type-MD5 "
               "and privacy encryption type-AES is successful")
        st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli_encrypt_rest_gnmi
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_cli
def test_ft_snmp_cli_v3_user_auth_privacy_encrypt_3():
    """
    Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
    Verify v3 access to switch and perform SNMP get and walk operations when user is configured with authentication
    encryption password(SHA) and privacy encryption password(AES-128).
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.banner("Verify v3 access to switch and perform SNMP set,get and walk operations when user "
              "is configured with authentication-SHA encryption password and privacy-AES encryption password.")
    if data.snmpv3_support:
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1,
                                                            expected_output=ifAdminStatus_link_down_status,
                                                            connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                            oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                            filter=data.filter_cli, version="3", usr_name=data.v3_user8,
                                                            auth_type=data.auth_protocol[1],
                                                            auth_pwd=data.sha_auth_password,
                                                            privacy_type=data.verify_priv_protocol[2],
                                                            privacy_pwd=data.aes_priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_down_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy encrypt get operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1,
                                                             expected_output=ifAdminStatus_link_up_status,
                                                             connection_obj=ssh_conn_obj, ipaddress=ipaddress,
                                                             oid=ifAdminStatus_oid, security_lvl="authPriv",
                                                             filter=data.filter_cli, version="3",
                                                             usr_name=data.v3_user8, auth_type=data.auth_protocol[1],
                                                             auth_pwd=data.sha_auth_password,
                                                             privacy_type=data.verify_priv_protocol[2],
                                                             privacy_pwd=data.aes_priv_password, timeout=5)
        st.log("Link status by using SNMPv3 from the SNMP output: {} ".format(get_snmp_output[1]))
        if not get_snmp_output[1] == ifAdminStatus_link_up_status:
            st.log(" Link status by using SNMPv3 user with auth and privacy encrypt walk operation is not matching")
            st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
        st.log("Verification of authentication-SHA encryption password and privacy-AES encryption "
               "password is successful")
        st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmp_cli_agent_address
def test_ft_snmp_cli_config_agent_addr_ipv4_udp_port():
    """
        Author : Santosh Votarikari(santosh.votarikari@broadcom.com)
        Verify the ability to perform SNMPv2 get and walk operation using IPv4 agent address configured with
        non-default UDP port number.
    """
    st.banner(
        "Verify the ability to perform SNMPv2 get and walk operation using IPv4 agent address configured "
        "with default and non-default UDP port numbers")
    st.log("Configuring snmp agent address with default udp port")
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "agent_address": {"agent-addr": ipaddress, "no_form": False}})
    st.log("Wait to effect configuration change until restart is attempted")
    st.wait(data.klish_snmp_delay)
    st.log("Getting the configuring SNMP parameter agent address")
    snmp_obj.show(vars.D1, cli_type=data.cli_type)
    st.log("Performing interface shutdown")
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    st.wait(data.link_status_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    st.log("Verifying SNMPGET operation on shutdown interface")
    get_snmp_output = snmp_obj.poll_for_snmp_get_output(vars.D1, 5, 1, expected_output=ifAdminStatus_link_down_status,
                                                        ipaddress=ipaddress, oid=ifAdminStatus_oid,
                                                        community_name=data.v2_community, filter=data.filter_cli,
                                                        version="2", timeout=5)
    st.log("Link status by using SNMPv2 from the SNMP output: {} ".format(get_snmp_output[0]))
    if not get_snmp_output[0] == ifAdminStatus_link_down_status:
        st.log("Link status by using SNMPv2 walk operation is not matching after agent address is "
               "configured with default udp port")
        st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
    st.log("un-configure snmp agent address with default udp port")
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "agent_address": {"agent-addr": ipaddress, "no_form": True}})
    st.log("Getting the configuring SNMP parameter agent address")
    snmp_obj.show(vars.D1, cli_type=data.cli_type)
    st.log("Configuring snmp agent address with non-default udp port")
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "agent_address": {"agent-addr": ipaddress,
                                                                           "udp-port": data.udp_port,
                                                                           "no_form": False}})
    st.log("Wait to effect configuration change until restart is attempted")
    st.wait(data.klish_snmp_delay)
    st.log("Getting the configuring SNMP parameter agent address")
    snmp_obj.show(vars.D1, cli_type=data.cli_type)
    st.log("Performing interface no-shutdown")
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    st.wait(data.link_status_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    st.log("Verifying SNMPWALK operation on no-shutdown interface")
    get_snmp_output = snmp_obj.poll_for_snmp_walk_output(vars.D1, 5, 1, expected_output=ifAdminStatus_link_up_status,
                                                         ipaddress=ipaddress, oid=ifAdminStatus_oid,
                                                         community_name=data.v2_community, filter=data.filter_cli,
                                                         version="2", snmp_port=data.udp_port, timeout=5)
    st.log("Link status by using SNMPv2 from the SNMP output: {} ".format(get_snmp_output[0]))
    if not get_snmp_output[0] == ifAdminStatus_link_up_status:
        st.log("Link status by using SNMPv2 walk operation is not matching after agent address is "
               "configured with non-default udp port")
        st.report_fail("snmp_output_status", "ifAdminStatus_oid", "Failed")
    st.log("Verifying configured snmp-server details such location, contact, traps and agent-addresses")
    filter_data = {"traps": "enable", "location": data.location, "contact": data.contact,
                   "agents": [{"agent_ip_address": ipaddress, "agent_udp_port": data.udp_port}]}
    if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="server", data=filter_data):
        st.report_fail("snmp_agent_address_config_verify_unsuccessful", ipaddress, data.udp_port)
    st.log("Verification of IPv4 agent address with default and non-default UDP port numbers is successful")
    st.log("un-configure snmp agent address with non-default udp port")
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "agent_address": {"agent-addr": ipaddress,
                                                                           "udp-port": data.udp_port,
                                                                           "no_form": True}})
    st.report_pass("snmp_output_status", "ifAdminStatus_oid", "Passed")


@pytest.mark.snmp_trap_mvrf
@pytest.mark.snmpv2_trap_mgmtvrf
def test_ft_snmp_cli_v2_inform_trap_mgmtvrf():
    """
    Verify that trap and inform when trap/inform is configured through CLI with V2 version over MGMT VRF.
    """
    st.banner("Verify that trap and inform when trap/inform is configured through CLI with SNMPv2 version.")
    mvrfconfig(vars.D1, cli_type=data.cli_type)

    check_flag = snmptrapd_checking()
    if not check_flag:
        st.report_fail("snmptrapd_not_running")
    clear_cmd = "echo " " > {}".format(capture_file)
    execute_command(ssh_conn_obj, clear_cmd)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    st.wait(data.link_status_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    # Configure SNMP Traps with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host,
                                                                  "community": {"name": data.v2_community,
                                                                                "traps": "v2c", "interface": "mgmt"},
                                                                  "no_form": False}})
    snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
    st.log(snmp_output)
    # Wait to effect configuration change until restart is attempted
    st.wait(data.klish_snmp_delay)
    # trigger trap on DUT
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    # Wait to check the traps before un-configuration of traps.
    st.wait(data.snmp_server_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    # get data from capture
    read_cmd = "cat {}".format(capture_file)

    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]
    result_1 = "TRAP2, SNMP v2c, community {}".format(data.v2_community)
    result = any(result_1 in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmptrap_not_generated", "invalid SNMP version and type")
    result = any(ifAdminStatus_link_down_trap_status in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmptrap_not_generated", "linkDown")

    # Un-configure SNMP Traps with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
    # Configure SNMP Informs with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host,
                                                                  "community": {"name": data.v2_community,
                                                                                "informs": "True", "interface": "mgmt"},
                                                                  "no_form": False}})
    snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
    st.log(snmp_output)
    # Wait to effect configuration change until restart is attempted
    st.wait(data.klish_snmp_delay)
    # trigger trap on DUT
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    # Wait to check the traps before un-configuration of informs.
    st.wait(data.snmp_server_delay)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    # get data from capture
    read_cmd = "cat {}".format(capture_file)

    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]
    result_1 = "INFORM, SNMP v2c, community {}".format(data.v2_community)
    result = any(result_1 in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmptrap_not_generated", "invalid SNMP version and type")
    result = any(ifAdminStatus_link_up_trap_status in x for x in trap_lines)
    # Un-configure SNMP informs with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
    if result == 0:
        mvrfconfig(vars.D1, no_form=True, cli_type=data.cli_type)
        st.report_fail("snmptrap_not_generated", "linkUp")
    else:
        mvrfconfig(vars.D1, no_form=True, cli_type=data.cli_type)
        st.log("Verification of SNMPv2 trap and inform over Management VRF is successful")
        st.report_pass("snmp_trap_informs_status", "SNMPv2c traps and informs", "Passed")


@pytest.mark.snmp_trap_mvrf
@pytest.mark.snmpv3_trap_mvrf
def test_ft_snmp_cli_v3_inform_trap_mgmtvrf():
    """
        Verify that trap and inform when trap/inform is configured through CLI with V3 version.
        """
    st.banner("Verify that trap and inform when trap/inform is configured through CLI with SNMPv3 version.")
    st.log("Enable Management VRF")
    mvrfconfig(vars.D1, cli_type=data.cli_type)
    if data.snmpv3_support:
        check_flag = snmptrapd_checking()
        if not check_flag:
            st.report_fail("snmptrapd_not_running")
        clear_cmd = "echo " " > {}".format(capture_file)
        execute_command(ssh_conn_obj, clear_cmd)
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        # Configure SNMP Traps with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host,
                                                                      "user": {"name": data.v3_user1,
                                                                               "traps": "noauth", "interface": "mgmt"},
                                                                      "no_form": False}})
        snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
        st.log(snmp_output)
        # Add trap user in SNMP server to allow traps for v3 user
        enable_v3_trap_user_on_server = "echo -ne \"createUser -e 0x{} {}\">>/etc/snmp/snmptrapd.conf". \
            format(snmp_engine_id, data.v3_user1)
        execute_command(ssh_conn_obj, enable_v3_trap_user_on_server)
        basic_obj.service_operations(ssh_conn_obj, "snmptrapd", "restart", "server")
        st.log("Verifying SNMP service status after trap v3 is configured on host")
        if not poll_wait(basic_obj.verify_service_status, 90, ssh_conn_obj, 'snmptrapd', "server"):
            st.report_fail("snmp_service_not_up")
        # Create separate session to set snmptraps path on server because prompt will be stopped new line
        ip = mutils.ensure_service_params(vars.D1, "snmptrap", "ip")
        username = mutils.ensure_service_params(vars.D1, "snmptrap", "username")
        password = mutils.ensure_service_params(vars.D1, "snmptrap", "password")

        # Connect to the linux machine and check
        ssh_conn_obj1 = connect_to_device(ip, username, password)
        if not ssh_conn_obj1:
            st.report_tc_fail("ssh_connection_failed", ip)
        execute_command(ssh_conn_obj1, restart_snmp_traps)
        ssh_disconnect(ssh_conn_obj1)
        if not poll_wait(snmptrapd_checking, 90):
            st.report_fail("snmptrapd_not_running")
        # Server is taking some time to receive traps after docker restart.
        st.wait(data.klish_snmp_delay)
        # trigger trap on DUT
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        # Wait to check the traps before un-configuration.
        st.wait(data.snmp_server_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        # get data from capture
        read_cmd = "cat {}".format(capture_file)
        result_1 = "TRAP2, SNMP v3, user {}".format(data.v3_user1)
        result = poll_wait(check_for_trap, 20, ssh_conn_obj, read_cmd, result_1, ifAdminStatus_link_down_trap_status)
        if not result:
            st.report_fail("snmptrap_not_generated", "linkDown")
        # Un-configure SNMP Traps with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
        # Configure SNMP Informs with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host,
                                                                      "user": {"name": data.user_inform,
                                                                               "informs": "noauth",
                                                                               "interface": "mgmt"},
                                                                      "no_form": False}})
        snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
        st.log(snmp_output)
        if data.snmpv3_support:
            filter_data = {"target_address": data.host, "target_type": "inform",
                           "target_community_user": data.user_inform,
                           "target_version_security": data.verify_security_levl[0]}
            if not snmp_obj.verify(vars.D1, cli_type=data.cli_type, snmp_type="host", data=filter_data):
                st.report_fail("snmp_config_unsuccessful", "informs host", data.host)
        # Wait to effect configuration change until restart is attempted
        st.wait(data.klish_snmp_delay)
        # trigger trap on DUT
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        # Wait to check the traps before un-configuration of informs.
        st.wait(data.snmp_server_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        # get data from capture
        read_cmd = "cat {}".format(capture_file)
        result_1 = "INFORM, SNMP v3, user {}".format(data.user_inform)
        result = poll_wait(check_for_trap, 20, ssh_conn_obj, read_cmd, result_1, ifAdminStatus_link_up_trap_status)
        # Remove trap user from snmp host receiver to avoid duplicate entries in server and restart server.
        basic_obj.delete_line_using_specific_string(ssh_conn_obj, snmp_engine_id, "/etc/snmp/snmptrapd.conf", "server")
        basic_obj.service_operations(ssh_conn_obj, "snmptrapd", "restart", "server")
        st.log("Verifying SNMP service status after trap v3 is unconfigured on host")
        if not poll_wait(basic_obj.verify_service_status, 90, ssh_conn_obj, 'snmptrapd', "server"):
            st.report_fail("snmp_service_not_up")
        # Create separate session to set snmptraps path on server because prompt will be stopped new line
        ip = mutils.ensure_service_params(vars.D1, "snmptrap", "ip")
        username = mutils.ensure_service_params(vars.D1, "snmptrap", "username")
        password = mutils.ensure_service_params(vars.D1, "snmptrap", "password")
        # Connect to the linux machine and check
        ssh_conn_obj1 = connect_to_device(ip, username, password)
        if not ssh_conn_obj1:
            st.report_tc_fail("ssh_connection_failed", ip)
        execute_command(ssh_conn_obj1, restart_snmp_traps)
        ssh_disconnect(ssh_conn_obj1)
        # Un-configure SNMP informs with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.host, "no_form": True}})
        if not poll_wait(snmptrapd_checking, 90):
            st.report_fail("snmptrapd_not_running")
        if not result:
            mvrfconfig(vars.D1, no_form=True, cli_type=data.cli_type)
            st.report_fail("snmptrap_not_generated", "linkUp")
        else:
            mvrfconfig(vars.D1, no_form=True, cli_type=data.cli_type)
            st.log("Verification of SNMPv3 trap and inform over Management VRF is successful")
            st.report_pass("snmp_trap_informs_status", "SNMPv3 traps and informs", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv2_trap_cli
def test_ft_snmp_cli_v2_udp_intf_trap():
    """
    Author : Prasad Darnasi(prasad.darnasi@broadcom.com)
    Verify that trap configured through non default UDP port and interface option works fine with V2 version.
    """
    st.banner("Verify that trap configured with non default udp port and interface through CLI with SNMPv2 version.")
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    st.wait(data.link_status_delay)
    intf_details = intfapi.interface_status_show(vars.D1, cli_type=data.cli_type)
    key, mode = ['interface','standard'] if '/' in vars.D1T1P1 else ['altname', 'native']
    intf_naming_config = 'yes' if mode == 'native' else 'no'
    data.revert_mode = 'no' if intf_naming_config == 'yes' else 'yes'
    if intf_details:
        breakout_port_info = ''
        nonbreakout_port_info = ''
        for intf_detail in intf_details:
            if len(intf_detail[key].split("/")) == 3:
                breakout_port_info = intf_detail
                st.debug("Breakout port info found: {}".format(breakout_port_info))
                break
        for intf_detail in intf_details:
            if len(intf_detail[key].split("/")) == 2:
                nonbreakout_port_info = intf_detail
                st.debug("Non-breakout port info found: {}".format(nonbreakout_port_info))
                break
    if not breakout_port_info:
        st.report_fail("msg", "breakout port info is not found")
    if mode == 'native':
        breakout_port_index = int(breakout_port_info['interface'].replace("Ethernet", "")) + 1
    else:
        breakout_port_index = int(st.get_other_names(vars.D1, [breakout_port_info['interface']])[0].replace("Ethernet", "")) + 1
    if not poll_wait(verify_intf_description, 20, breakout_port_index, breakout_port_info['interface']):
        st.report_fail("msg", "interface name: {} not found in SNMP Walk".format(breakout_port_info['interface']))

    if nonbreakout_port_info:
        if mode == 'native':
            index = int(nonbreakout_port_info['interface'].replace("Ethernet", "")) + 1
        else:
            index = int(st.get_other_names(vars.D1, [nonbreakout_port_info['interface']])[0].replace("Ethernet", "")) + 1
        if not poll_wait(verify_intf_description, 20, index, nonbreakout_port_info['interface']):
            st.report_fail("msg", "interface name: {} not found in SNMP Walk".format(nonbreakout_port_info['interface']))
    if not intf_obj.config_ifname_type(vars.D1, config=intf_naming_config, cli_type=data.cli_type):
        st.report_fail("msg", "Failed to configure interface naming mode")
    intfapi.interface_status_show(vars.D1, cli_type=data.cli_type)
    if not poll_wait(verify_intf_description, 20, breakout_port_index, breakout_port_info['altname']):
        st.report_fail("msg", "interface name: {} not found in SNMP Walk".format(breakout_port_info['altname']))

    if nonbreakout_port_info:
        if mode == 'native':
            index = int(nonbreakout_port_info['interface'].replace("Ethernet", "")) + 1
        else:
            index = int(st.get_other_names(vars.D1, [nonbreakout_port_info['interface']])[0].replace("Ethernet", "")) + 1
        if not poll_wait(verify_intf_description, 20, index, nonbreakout_port_info['altname']):
            st.report_fail("msg", "interface name: {} not found in SNMP Walk".format(breakout_port_info['altname']))
    if not intf_obj.config_ifname_type(vars.D1, config=data.revert_mode, cli_type=data.cli_type):
        st.report_fail("msg", "Failed to configure interface naming mode")
    # Configure SNMP Traps with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.tg_ip,
                                                                  "community": {"name": data.v2_community,
                                                                                "traps": "v2c", "port": data.udp_port,
                                                                                "interface": vars.D1T1P2},
                                                                  "no_form": False}})
    snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
    st.log(snmp_output)
    ip.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.intf_ip, data.mask)
    h1 = data.tg2.tg_interface_config(port_handle=data.tg_ph_2, mode='config', intf_ip_addr=data.tg_ip,
                                      gateway=data.intf_ip, arp_send_req='1')
    data.tg1.tg_packet_control(port_handle=data.tg_ph_2, action='start')
    # Wait to effect configuration change until restart is attempted
    st.wait(data.klish_snmp_delay)
    # trigger trap on DUT
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    # Wait to check the traps before un-configuration of traps.
    st.wait(data.snmp_server_delay)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
    intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
    st.wait(data.snmp_server_delay)
    data.tg1.tg_packet_control(port_handle=data.tg_ph_2, action='stop')
    # get data from capture
    pkts_captured = data.tg2.tg_packet_stats(port_handle=data.tg_ph_2, format='var', output_type='hex')
    capture_result = tgapi.validate_packet_capture(tg_type=data.tg1.tg_type, pkt_dict=pkts_captured, offset_list=[36],
                                             value_list=['3039'])

    # Un-configure SNMP Traps with version-2.
    snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.tg_ip, "no_form": True}})
    snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
    st.log(snmp_output)
    data.tg2.tg_interface_config(port_handle=data.tg_ph_2, handle=h1['handle'], mode='destroy')
    ip.delete_ip_interface(vars.D1, vars.D1T1P2, data.intf_ip, data.mask)
    if capture_result == 0:
        st.report_fail("snmptrap_not_generated", "linkDown and linkup")
    else:
        st.log("Verification of SNMPv2 trap and inform is successful")
        st.report_pass("snmp_trap_informs_status", "SNMPv2c traps and informs", "Passed")


@pytest.mark.snmp_cli
@pytest.mark.snmp_cli_test_cases
@pytest.mark.snmpv3_trap_cli
def test_ft_snmp_cli_v3_udp_intf_trap():
    """
    Author : Prasad Darnasi(prasad.darnasi@broadcom.com)
    Verify that trap configured through non default UDP port and interface option works fine with V3 version.
        """
    st.banner("Verify that trap configured with non default udp port and interface through CLI with SNMPv3 version.")
    if data.snmpv3_support:
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        st.wait(data.link_status_delay)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        # Configure SNMP Traps with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.tg_ip,
                                                                      "user": {"name": data.v3_user1,
                                                                               "traps": "noauth", "port": data.udp_port,
                                                                               "interface": vars.D1T1P2},
                                                                      "no_form": False}})
        snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
        st.log(snmp_output)

        ip.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.intf_ip, data.mask)
        h1 = data.tg1.tg_interface_config(port_handle=data.tg_ph_2, mode='config', intf_ip_addr=data.tg_ip,
                                          gateway=data.intf_ip, arp_send_req='1')
        data.tg1.tg_packet_control(port_handle=data.tg_ph_2, action='start')
        # Wait to effect configuration change until restart is attempted
        st.wait(data.klish_snmp_delay)
        # trigger trap on DUT
        intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
        # Wait to check the traps before un-configuration of traps.
        st.wait(data.snmp_server_delay)
        intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)
        intfapi.interface_status_show(vars.D1, vars.D1T1P1, cli_type=data.cli_type)
        st.wait(data.snmp_server_delay)
        data.tg1.tg_packet_control(port_handle=data.tg_ph_2, action='stop')
        # get data from capture
        pkts_captured = data.tg2.tg_packet_stats(port_handle=data.tg_ph_2, format='var', output_type='hex')
        capture_result = tgapi.validate_packet_capture(tg_type=data.tg1.tg_type, pkt_dict=pkts_captured, offset_list=[36],
                                                 value_list=['3039'])

        # Un-configure SNMP Traps with version-3.
        snmp_obj.config(vars.D1, {"cli_type": data.cli_type, "host": {"address": data.tg_ip, "no_form": True}})
        snmp_output = snmp_obj.show(vars.D1, cli_type=data.cli_type, snmp_type="host")
        st.log(snmp_output)
        data.tg2.tg_interface_config(port_handle=data.tg_ph_2, handle=h1['handle'], mode='destroy')
        ip.delete_ip_interface(vars.D1, vars.D1T1P2, data.intf_ip, data.mask)
        if capture_result == 0:
            st.report_fail("snmptrap_not_generated", "linkDown and linkup")
        else:
            st.log("Verification of SNMPv3 trap with non default UDP and interface is successful")
            st.report_pass("snmp_trap_informs_status", "SNMPv3 traps and informs", "Passed")


def test_ft_snmp_rest_v2_v3_inform_trap_mgmtvrf():
    """
    Verify that trap and inform when trap/inform is configured through REST with V2,V3 version over MGMT VRF
    """
    result = 1
    udp_data = json.loads("""
    {
    "ietf-snmp:target": [
    {
      "name": "targetEntry1",
      "udp": {
        "ip": "10.59.143.179",
        "port": 162
      }
    }
    ]}
    """)
    trap_data = json.loads("""
    {
    "ietf-snmp:target": [
    {
      "name": "targetEntry1",
      "tag": [
        "trapNotify", "mgmt"
      ]
    }
    ]
    }
    """)
    inform_data = json.loads("""
     {
     "ietf-snmp:target": [
     {
     "name": "targetEntry1",
     "tag": ["trapNotify", "mgmt"]
     }
     ]
     }
     """)
    param_data = json.loads("""
    {
    "ietf-snmp:target-params": [
    {
    "name": "targetEntry1",
    "v2c": {
    "security-name": "6aYnMn9BSwDmcQ"
    }
    }
    ]
    }
    """)
    v3_param_data = json.loads("""
    {
    "ietf-snmp:target-params": [
    {
    "name": "targetEntry1",
    "v2c": {
    "security-name": "authpriv"
    },
    "usm": {
    "security-level": "no-auth-no-priv",
    "user-name": "u18aq3d2os"
    }
    }
    ]
    }
    """)
    
    rest_udp_tag_url = "/restconf/data/ietf-snmp:snmp/target"
    rest_param_url = "/restconf/data/ietf-snmp:snmp/target-params"
    credentials = st.get_credentials(vars.D1)
    st.rest_init(vars.D1, credentials[0], credentials[1], credentials[2])
    # udp_status = st.rest_update(vars.D1, path=data.udp_url, data=udp_data)["status"]
    udp_status = perform_rest_call("update", vars.D1, rest_udp_tag_url, udp_data).get("status", None)
    # trap_status = st.rest_update(vars.D1, path=data.tag_url, data=trap_data)["status"]
    trap_status = perform_rest_call("update", vars.D1, rest_udp_tag_url, trap_data).get("status", None)
    # param_status = st.rest_update(vars.D1, path=data.param_url, data=param_data)["status"]
    param_status = perform_rest_call("update", vars.D1, rest_param_url, param_data).get("status", None)
    if not rest_obj.rest_status(udp_status):
        st.error("UDP PUT failed")
        result = 0
    if not rest_obj.rest_status(trap_status):
        st.error("TAG PUT failed")
        result = 0
    if not rest_obj.rest_status(param_status):
        st.error("Target-params PUT failed")
        result = 0
    # get_udp = st.rest_read(vars.D1, path=data.udp_url)
    get_udp = perform_rest_call("read", vars.D1, data.udp_url)
    # get_trap = st.rest_read(vars.D1, path=data.tag_url)
    get_trap = perform_rest_call("read", vars.D1, data.tag_url)
    # get_param = st.rest_read(vars.D1, path=data.param_url)
    get_param = perform_rest_call("read", vars.D1, data.param_url)
    if not rest_obj.rest_status(get_udp.get("status", None)):
        st.error("UDP GET failed")
        result = 0
    if not rest_obj.rest_status(get_trap.get("status", None)):
        st.error("TAG GET failed")
        result = 0
    if not rest_obj.rest_status(get_param.get("status", None)):
        st.error("Target-params GET failed")
        result = 0
    if result and get_udp.get("output") and get_trap.get("output") and get_param.get("output"):
        if not (get_udp["output"]["ietf-snmp:udp"]["ip"] == udp_data["ietf-snmp:target"][0]["udp"]["ip"] and
                get_udp["output"]["ietf-snmp:udp"]["port"] == udp_data["ietf-snmp:target"][0]["udp"]["port"]):
            st.error("UDP REST configuration failed")
            result = 0
        if not (set(trap_data["ietf-snmp:target"][0]["tag"])).issubset(set(get_trap["output"]["ietf-snmp:tag"])):
            st.error("TAG REST configuration failed")
            result = 0
        if not (get_param["output"]["ietf-snmp:target-params"][0]["name"] == param_data["ietf-snmp:target-params"][0][
            "name"] and get_param["output"]["ietf-snmp:target-params"][0]["v2c"]["security-name"] ==
                param_data["ietf-snmp:target-params"][0]["v2c"]["security-name"]):
            st.error("param REST configuration failed")
            result = 0
    else:
        st.error("snmp GET failed")
        result = 0
    # del_tag = st.rest_delete(vars.D1, path=data.tag_url)["status"]
    del_tag = perform_rest_call("delete", vars.D1, data.tag_url).get("status", None)
    # del_udp = st.rest_delete(vars.D1, path=data.udp_url)["status"]
    del_udp = perform_rest_call("delete", vars.D1, data.udp_url).get("status", None)
    # del_param = st.rest_delete(vars.D1, path=data.param_url)["status"]
    del_param = perform_rest_call("delete", vars.D1, data.param_url).get("status", None)
    if not rest_obj.rest_status(del_tag):
        st.error("TAG DELETE failed")
        result = 0
    if not rest_obj.rest_status(del_udp):
        st.error("udp DELETE failed")
        result = 0
    if not rest_obj.rest_status(del_param):
        st.error("param DELETE failed")
        result = 0
    # inform_status = st.rest_update(vars.D1, path=data.tag_url, data=inform_data)["status"]
    inform_status = perform_rest_call("update", vars.D1, rest_udp_tag_url, inform_data).get("status", None)
    # v3_param_status = st.rest_update(vars.D1, path=data.param_url, data=v3_param_data)["status"]
    v3_param_status = perform_rest_call("update", vars.D1, rest_param_url, v3_param_data).get("status", None)
    if not rest_obj.rest_status(inform_status):
        st.error("TAG PUT failed")
        result = 0
    if not rest_obj.rest_status(v3_param_status):
        st.error("param PUT failed")
        result = 0
    # get_inform = st.rest_read(vars.D1, path=data.tag_url)
    get_inform = perform_rest_call("read", vars.D1, data.tag_url)
    # get_v3_param = st.rest_read(vars.D1, path=data.param_url)
    get_v3_param = perform_rest_call("read", vars.D1, data.param_url)
    if not rest_obj.rest_status(get_inform.get("status")):
        st.error("TAG GET failed")
        result = 0
    if not rest_obj.rest_status(get_v3_param.get("status")):
        st.error("Param GET failed")
        result = 0
    if (get_inform.get("output") and get_inform.get("status") and get_v3_param.get("status")):
        if not set(set(inform_data["ietf-snmp:target"][0]["tag"])).issubset(get_inform["output"]["ietf-snmp:tag"]):
            st.error("TAG REST configuration failed")
            result = 0
        if "name" in get_v3_param["output"]["ietf-snmp:target-params"][0] and "v2c" in get_v3_param["output"]["ietf-snmp:target-params"][0] and "usm" in get_v3_param["output"]["ietf-snmp:target-params"][0]:
            if not (v3_param_data["ietf-snmp:target-params"][0]["name"] == get_v3_param["output"]["ietf-snmp:target-params"][0]["name"] and
                    v3_param_data["ietf-snmp:target-params"][0]["v2c"]["security-name"] == get_v3_param["output"]["ietf-snmp:target-params"][0]["v2c"]["security-name"] and
                    v3_param_data["ietf-snmp:target-params"][0]["usm"]["security-level"] == get_v3_param["output"]["ietf-snmp:target-params"][0]["usm"]["security-level"] and
                    v3_param_data["ietf-snmp:target-params"][0]["usm"]["user-name"] == get_v3_param["output"]["ietf-snmp:target-params"][0]["usm"]["user-name"]):
                st.error("param REST configuration failed")
                result = 0
        else:
            st.error("param REST configuration failed")
            result = 0
    else:
        st.error("snmp GET failed")
        result = 0
    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_ft_snmp_gnmi_v2_v3_inform_trap_mgmtvrf():
    """
    Verify that trap and inform when trap/inform is configured through gnmi with V2,V3 version over MGMT VRF
    """
    gnmi_udp_url = "/ietf-snmp:snmp/target[name=targetEntry1]/udp/"
    gnmi_set_udp_tag_url = "/ietf-snmp:snmp/target"
    gnmi_tag_url = "/ietf-snmp:snmp/target[name=targetEntry1]/tag/"
    gnmi_param_url = "/ietf-snmp:snmp/target-params[name=targetEntry1]/"
    gnmi_set_param_url = "/ietf-snmp:snmp/target-params"
    result = 1
    udp_data = json.loads("""
    {
    "ietf-snmp:target": [
    {
      "name": "targetEntry1",
      "udp": {
        "ip": "10.59.143.179",
        "port": 162
      }
    }
    ]}
    """)
    trap_data = json.loads("""
    {
    "ietf-snmp:target": [
    {
      "name": "targetEntry1",
      "tag": [
        "trapNotify", "mgmt"
      ]
    }
    ]
    }
    """)
    inform_data = json.loads("""
     {
     "ietf-snmp:target": [
     {
     "name": "targetEntry1",
     "tag": ["trapNotify", "mgmt"]
     }
     ]
     }
     """)
    param_data = json.loads("""
    {
    "ietf-snmp:target-params": [
    {
    "name": "targetEntry1",
    "v2c": {
    "security-name": "6aYnMn9BSwDmcQ"
    }
    }
    ]
    }
    """)
    v3_param_data = json.loads("""
    {
    "ietf-snmp:target-params": [
    {
    "name": "targetEntry1",
    "v2c": {
    "security-name": "authpriv"
    },
    "usm": {
    "security-level": "no-auth-no-priv",
    "user-name": "u18aq3d2os"
    }
    }
    ]
    }
    """)
    
    
    gnmi_udp_set = gnmi_set(dut=vars.D1, xpath=gnmi_set_udp_tag_url, json_content=udp_data)
    gnmi_tag_set = gnmi_set(dut=vars.D1, xpath=gnmi_set_udp_tag_url, json_content=trap_data)
    gnmi_param_set = gnmi_set(dut=vars.D1, xpath=gnmi_set_param_url, json_content=param_data)
    gnmi_udp_get = gnmi_get(dut=vars.D1, xpath=gnmi_udp_url)
    gnmi_tag_get = gnmi_get(dut=vars.D1, xpath=gnmi_tag_url)
    gnmi_param_get = gnmi_get(dut=vars.D1, xpath=gnmi_param_url)
    st.debug("gnmi_udp_get: {}".format(gnmi_udp_get))
    st.debug("gnmi_tag_get: {}".format(gnmi_tag_get))
    st.debug("gnmi_param_get: {}".format(gnmi_param_get))
    if "op: UPDATE" not in (gnmi_udp_set or gnmi_tag_set or gnmi_param_set):
        st.error("gnmi set failed")
        result = 0
    if not (gnmi_udp_get and gnmi_tag_get and gnmi_param_get):
        st.error("gnmi get failed")
        result = 0
    if not (gnmi_udp_get["ietf-snmp:udp"]["ip"] == udp_data["ietf-snmp:target"][0]["udp"]["ip"] and
            gnmi_udp_get["ietf-snmp:udp"]["port"] == udp_data["ietf-snmp:target"][0]["udp"]["port"]):
        st.error("UDP gnmi configuration failed")
        result = 0
    if not (set(trap_data["ietf-snmp:target"][0]["tag"])).issubset(set(gnmi_tag_get["ietf-snmp:tag"])):
        st.error("TAG gnmi configuration failed")
        result = 0
    if not (gnmi_param_get["ietf-snmp:target-params"][0]["name"] == param_data["ietf-snmp:target-params"][0]["name"]
            and gnmi_param_get["ietf-snmp:target-params"][0]["v2c"]["security-name"] ==
            param_data["ietf-snmp:target-params"][0]["v2c"]["security-name"]):
        st.error("param gnmi configuration failed")
        result = 0

    #Un config snmp udp, tag and
    st.rest_delete(vars.D1, path=data.tag_url)
    st.rest_delete(vars.D1, path=data.udp_url)
    st.rest_delete(vars.D1, path=data.param_url)
    gnmi_tag_set = gnmi_set(dut=vars.D1, xpath=gnmi_set_udp_tag_url, json_content=inform_data)
    gnmi_param_set = gnmi_set(dut=vars.D1, xpath=gnmi_set_param_url, json_content=v3_param_data)
    gnmi_tag_get = gnmi_get(dut=vars.D1, xpath=gnmi_tag_url)
    gnmi_param_get = gnmi_get(dut=vars.D1, xpath=gnmi_param_url)
    st.debug("gnmi_tag_get : {}".format(gnmi_tag_get))
    st.debug("gnmi_param_get : {}".format(gnmi_param_get))
    if "op: UPDATE" not in (gnmi_tag_set or gnmi_param_set):
        st.error("gnmi set failed")
        result = 0
    if not (gnmi_tag_get and gnmi_param_get):
        st.error("gnmi get failed")
        result = 0
    if not set(set(inform_data["ietf-snmp:target"][0]["tag"])).issubset(gnmi_tag_get["ietf-snmp:tag"]):
        st.error("TAG REST configuration failed")
        result = 0
    if not (v3_param_data["ietf-snmp:target-params"][0]["name"] ==
            gnmi_param_get["ietf-snmp:target-params"][0]["name"] and
            v3_param_data["ietf-snmp:target-params"][0]["v2c"]["security-name"] ==
            gnmi_param_get["ietf-snmp:target-params"][0]["v2c"]["security-name"] and
            v3_param_data["ietf-snmp:target-params"][0]["usm"]["security-level"] ==
            gnmi_param_get["ietf-snmp:target-params"][0]["usm"]["security-level"] and
            v3_param_data["ietf-snmp:target-params"][0]["usm"]["user-name"] ==
            gnmi_param_get["ietf-snmp:target-params"][0]["usm"]["user-name"]):
        st.error("param REST configuration failed")
        result = 0
    if result:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")
