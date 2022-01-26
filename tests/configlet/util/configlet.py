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


def get_cable_len(ifname):
    return {ifname: config_db_data_orig['CABLE_LENGTH']['AZURE'][ifname]}

def get_pg_profile(ifname):
    def target_if_pg_only(key):
        return ifname in key
    res = {}
    pgs = config_db_data_orig['BUFFER_PG']
    for pg in filter(target_if_pg_only, pgs):
        res[pg] = pgs[pg]
    return res

def get_queue_cfg(ifname):
    def target_if_queue_only(key):
        return ifname in key
    res = {}
    queues = config_db_data_orig['QUEUE']
    for key in filter(target_if_queue_only, queues):
        res[key] = queues[key]
    return res

def get_queue_profile(ifname):
    def target_if_queue_only(key):
        return ifname in key 
    res = {}
    queues = config_db_data_orig['BUFFER_QUEUE']
    for key in filter(target_if_queue_only, queues):
        q_range = key[key.rindex('|')+1:]
        res[ifname + '|' + q_range] = queues[key]
    return res

def get_qos_map(ifname):
    return {ifname: config_db_data_orig['PORT_QOS_MAP'][ifname]}
    
def get_pfcwd_config(ifname):
    pfc_wd = {}
    pfc_time = get_pfc_time()
    if pfc_time:
            # "PFC_WD"
            pfc_wd[ifname] = {
                    "action": "drop",
                    "detection_time": pfc_time,
                    "restoration_time": pfc_time }
    return pfc_wd

def get_port_qos_config():
    ret = []
    cable = {}
    queue = {}
    buffer_pg = {}
    buffer_q = {}
    qos = {}
    pfc_wd = {}    
    
    log_debug("is_version_2019_higher={}".format(is_version_2019_higher()))

    for local_port in sonic_local_ports:
        cable.update(get_cable_len(local_port))
        buffer_pg.update(get_pg_profile(local_port))
        queue.update(get_queue_cfg(local_port))
        buffer_q.update(get_queue_profile(local_port))
        qos.update(get_qos_map(local_port))
        pfc_wd.update(get_pfcwd_config(local_port))

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


def main(tmpdir, is_storage_backend):
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
    ret += get_port_qos_config()
    ret += get_bgp_neighbor()

    write_out(ret, tmpdir)
