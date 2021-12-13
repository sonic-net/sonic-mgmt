#! /usr/bin/env python

import json

from tempfile import mkstemp
from helpers import *
from common import *
import strip

sonic_local_ports = set()

def is_version_2019_higher():
    return '201811' not in init_data["version"]


def get_pfc_time():
    ret = 0
    pfc_wd = config_db_data_orig.get("PFC_WD", {})
    for n, val in pfc_wd.items():
        ret = int(val.get("detection_time", 0))
        if ret:
            break

    if not ret:
        log_info("PFC_WD is not running")

    return ret


def get_vlan_sub_interface():
    global tor_data, sonic_local_ports

    ret = []

    port = list(sonic_local_ports)[0] + ".10"
    port_ip = port + "|" + tor_data["ip"]["local"] + "/31"
    port_ip6 = port + "|" + tor_data["ipv6"]["local"] + "/126"

    ret.append({
        "VLAN_SUB_INTERFACE": {
            port: {
                "admin_status": "up"
            },
            port_ip: {},
            port_ip6: {} }
        })
    log_debug("clet: get_vlan_sub_interface: {}".format(str(ret)))
    return ret


def get_port_channel():
    global tor_data

    ret = []
    pc_name = tor_data["portChannel"]
    if not pc_name:
        log_debug("No portchannel added, as no portchannel info found for ports: {}".
                format(str(tor_data["links"])))
        return ret

    ret.append( {
        "PORTCHANNEL": {
            pc_name: {
                "admin_status": "up",
                "min_links": "1",
                "mtu": "9100",
                "members": list(sonic_local_ports)
            }
        }
    })

    pc_mem = {}
    for port in sonic_local_ports:
        pc_mem["{}|{}".format(pc_name, port)] = {}
       
    ret.append({ "PORTCHANNEL_MEMBER": pc_mem })

    pc_intf = {}
    if tor_data["ip"]["local"]:
        pc_intf["{}|{}/31".format(pc_name, tor_data["ip"]["local"])] = {}
    if tor_data["ipv6"]["local"]:
        pc_intf["{}|{}/126".format(pc_name, tor_data["ipv6"]["local"])] = {}
    if pc_intf:
        if is_version_2019_higher():
            pc_intf[pc_name] = {}
        ret.append({ "PORTCHANNEL_INTERFACE": pc_intf })

    log_debug("clet: portchannel: {}".format(str(ret)))
    return ret


def update_port():
    port_data = tor_data["links"][0]
    sonic_port = port_data["local"]["sonic_name"]
    remote_port = port_data["remote"]

    return [ { "PORT": { sonic_port: { "description": "{}:{}".format(
        tor_data["name"]["remote"], remote_port) }}} ]


def add_interface():

    if tor_data["portChannel"]:
        return []

    sonic_port = tor_data["links"][0]["local"]["sonic_name"]

    key_ip = "{}|{}/31".format(sonic_port, tor_data["ip"]["local"])
    key_ipv6 = "{}|{}/126".format(sonic_port, tor_data["ipv6"]["local"])

    return [ { "INTERFACE": { key_ip: {}, key_ipv6:{}, sonic_port: {} } } ]


def get_acl():
    acl_table = {}
    acl_table["EVERFLOW"] = config_db_data_orig["ACL_TABLE"]["EVERFLOW"]
    acl_table["EVERFLOWV6"] = config_db_data_orig["ACL_TABLE"]["EVERFLOWV6"]

    
    lst_ports = set(acl_table["EVERFLOW"]["ports"])
    lst_v6_ports = set(acl_table["EVERFLOWV6"]["ports"])
            
    add_ports = []
    if tor_data["portChannel"]:
        add_ports.append(tor_data["portChannel"])
    else:
        add_ports = list(sonic_local_ports)


    for port in add_ports:
        lst_ports.add(port)
        lst_v6_ports.add(port)

    lst_ports = list(lst_ports)
    lst_v6_ports = list(lst_v6_ports)
    lst_ports.sort(reverse = True)
    lst_v6_ports.sort(reverse = True)

    acl_table["EVERFLOW"]["ports"] = lst_ports
    acl_table["EVERFLOWV6"]["ports"] = lst_v6_ports

    return [{"ACL_TABLE": acl_table }]


def get_device_info():
    global tor_data

    ret = []
    tor_name = tor_data["name"]["remote"]

    neighbor = {}

    for link in tor_data["links"]:
        neighbor[link["local"]["sonic_name"]] = {
                "name": tor_name,
                "port": link["remote"] }

    ret.append({"DEVICE_NEIGHBOR": neighbor})

    if tor_data["hwsku"]["remote"]:
        ret.append({"DEVICE_NEIGHBOR_METADATA": {
            tor_name: {
                "lo_addr": "None",
                "mgmt_addr": tor_data["mgmt_ip"]["remote"],
                "hwsku": tor_data["hwsku"]["remote"],
                "type": "ToRRouter" } } } ) 
    return ret


def get_port_related_data(is_mlnx, is_storage_backend):
    ret = []
    cable = {}
    queue = {}
    buffer_pg = {}
    buffer_q = {}
    buffer_port_ingress = {}
    buffer_port_egress = {}
    qos = {}
    pfc_wd = {}
    pfc_time = get_pfc_time()
    
    log_debug("is_version_2019_higher={}".format(is_version_2019_higher()))

    for local_port in sonic_local_ports:
        # Hard coded as 300m per discussion with Neetha

        #  "CABLE_LENGTH"
        cable[local_port] = "300m"

        # "BUFFER_PG"
        buffer_pg["{}|0".format(local_port)] = {
                "profile": "[BUFFER_PROFILE|ingress_lossy_profile]" }

        # "QUEUE"
        for i in range(3):
            queue["{}|{}".format(local_port, i)] = {
                    "scheduler": "[SCHEDULER|scheduler.0]"}

        for i in range(3, 5):
            queue["{}|{}".format(local_port, i)] = {
                    "wred_profile": "[WRED_PROFILE|AZURE_LOSSLESS]",
                    "scheduler": "[SCHEDULER|scheduler.1]"}
        
        for i in range(5,7):
            queue["{}|{}".format(local_port, i)] = {
                    "scheduler": "[SCHEDULER|scheduler.0]"}

        # "BUFFER_QUEUE"
        lossy_profile = "[BUFFER_PROFILE|{}]".format(
                    "q_lossy_profile" if is_mlnx else "egress_lossy_profile")

        buffer_q["{}|0-2".format(local_port)] = {"profile": lossy_profile}

        buffer_q["{}|3-4".format(local_port)] = {
                "profile": "[BUFFER_PROFILE|egress_lossless_profile]" }

        buffer_q["{}|5-6".format(local_port)] = {"profile": lossy_profile}

        if is_mlnx:
            # "BUFFER_PORT_INGRESS_PROFILE_LIST"
            if is_version_2019_higher():
                buffer_port_ingress[local_port] = {
                        "profile_list": "[BUFFER_PROFILE|ingress_lossless_profile]"
                        }
            else:
                buffer_port_ingress[local_port] = {
                        "profile_list": "[BUFFER_PROFILE|ingress_lossless_profile],[BUFFER_PROFILE|ingress_lossy_profile]"
                        }
            # "BUFFER_PORT_EGRESS_PROFILE_LIST"
            buffer_port_egress[local_port] = {
                    "profile_list": "[BUFFER_PROFILE|egress_lossless_profile],[BUFFER_PROFILE|egress_lossy_profile]"
                    }
            ret.append({ "BUFFER_PORT_INGRESS_PROFILE_LIST": buffer_port_ingress })
            ret.append({ "BUFFER_PORT_EGRESS_PROFILE_LIST": buffer_port_egress })

        # "PORT_QOS_MAP"
        qos[local_port] = {
                "tc_to_pg_map": "[TC_TO_PRIORITY_GROUP_MAP|AZURE]",
                "tc_to_queue_map": "[TC_TO_QUEUE_MAP|AZURE]",
                "pfc_enable": "3,4",
                "pfc_to_queue_map": "[MAP_PFC_PRIORITY_TO_QUEUE|AZURE]"
                }

        if is_storage_backend:
            qos[local_port]["dot1p_to_tc_map"] = "[DOT1P_TO_TC_MAP|AZURE]"
        else:
            qos[local_port]["dscp_to_tc_map"]  = "[DSCP_TO_TC_MAP|AZURE]"

        if is_mlnx:
            qos[local_port]["pfc_to_pg_map"] = "[PFC_PRIORITY_TO_PRIORITY_GROUP_MAP|AZURE]"

        if pfc_time:
            # "PFC_WD"
            pfc_wd[local_port] = {
                    "action": "drop",
                    "detection_time": pfc_time,
                    "restoration_time": pfc_time }


        
    ret.append({ "CABLE_LENGTH": { "AZURE": cable } })
    ret.append({ "QUEUE": queue })
    ret.append({ "BUFFER_PG": buffer_pg })
    ret.append({ "BUFFER_QUEUE": buffer_q })
    ret.append({ "PORT_QOS_MAP": qos })
    if pfc_wd:
        ret.append({ "PFC_WD": pfc_wd })

    return ret
         

def get_bgp_neighbor():
    bgp = {}

    ip = tor_data["ip"]
    ipv6 = tor_data["ipv6"]

    bgp[ip["remote"]] = {
        "rrclient": "0",
        "name": tor_data["name"]["remote"],
        "local_addr": ip["local"],
        "nhopself": "0",
        "admin_status": "up",
        "holdtime": tor_data["bgp_info"]["holdtime"],
        "asn": tor_data["bgp_info"]["asn"],
        "keepalive": tor_data["bgp_info"]["keepalive"]
        }

    bgp[ipv6["remote"].lower()] = bgp[ip["remote"]].copy()
    bgp[ipv6["remote"].lower()]["local_addr"] = ipv6["local"].lower()

    return [ { "BGP_NEIGHBOR": bgp } ]


def write_out(lst, tmpdir):
    global managed_files

    _, fpath = mkstemp(prefix="clet_", suffix=".json", dir=tmpdir)
    with open(fpath, "w") as s:
        s.write(json.dumps(lst, indent=4))
    managed_files["configlet"] = fpath


def main(tmpdir, is_mlnx, is_storage_backend):
    global sonic_local_ports
    ret = []

    _, sonic_local_ports = strip.get_local_ports()

    ret += update_port()
    if not is_storage_backend:
        ret += add_interface()
        ret += get_port_channel()
    else:
        ret += get_vlan_sub_interface()
    ret += get_acl()
    ret += get_device_info()
    ret += get_port_related_data(is_mlnx, is_storage_backend)
    ret += get_bgp_neighbor()

    write_out(ret, tmpdir)

    return 0



    
    







