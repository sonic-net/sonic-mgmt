
import re
from spytest import st, cutils

def bcm_show(dut, cmd, skip_tmpl=True, max_time=0):
    if not st.is_feature_supported("bcmcmd", dut): return ""
    return st.show(dut, cmd, skip_tmpl=skip_tmpl, max_time=max_time)

def bcm_config(dut, cmd, skip_error_check=True):
    if not st.is_feature_supported("bcmcmd", dut): return ""
    return st.config(dut, cmd, skip_error_check=skip_error_check)

def dump_l3_egress(dut):
    bcm_show(dut, "bcmcmd 'l3 ecmp egress show'")

def dump_l3_alpm(dut):
    bcm_show(dut, 'bcmcmd "l3 alpm show brief"')

def dump_l2(dut):
    bcm_show(dut, 'bcmcmd "l2 show"')

def dump_vlan(dut):
    bcm_show(dut, 'bcmcmd "vlan show"')

def dump_multicast(dut):
    bcm_show(dut, 'bcmcmd "multicast show"')

def dump_ipmc_table(dut):
    bcm_show(dut, 'bcmcmd "ipmc table show"')

def dump_kernel_fdb(dut,vlan_id=None):
    if vlan_id is None:
        st.show(dut, 'sudo bridge fdb show', skip_tmpl=True)
    else:
        st.show(dut, 'sudo bridge fdb show vlan {}'.format(vlan_id), skip_tmpl=True)

def dump_ports_info(dut):
    bcm_config(dut, 'bcmcmd "d chg port"')

def dump_trunk(dut):
    bcm_config(dut, 'bcmcmd "trunk show"')

def dump_l3_defip(dut):
    bcm_show(dut, "bcmcmd 'l3 defip show'")

def dump_l3_ip6route(dut):
    bcm_show(dut, "bcmcmd 'l3 ip6route show'")

def dump_l3_l3table(dut):
    bcm_show(dut, "bcmcmd 'l3 l3table show'")

def dump_l3_ip6host(dut):
    bcm_show(dut, "bcmcmd 'l3 ip6host show'")

def dump_counters(dut, interface=None):
    if not interface:
        command = 'bcmcmd "show c"'
    else:
        command = 'bcmcmd "show c {}"'.format(interface)
    bcm_show(dut, command, skip_tmpl=True)

def clear_counters(dut):
    bcm_config(dut, 'bcmcmd "clear c"')

def get_counters(dut, interface=None, skip_tmpl=False):
    if not interface:
        command = 'bcmcmd "show c"'
    else:
        command = 'bcmcmd "show c {}"'.format(interface)
    return bcm_show(dut, command, skip_tmpl=skip_tmpl)

def get_ipv4_route_count(dut, timeout=120):
    command = 'bcmcmd "l3 defip show" | wc -l'
    output = bcm_show(dut, command, skip_tmpl=True, max_time=timeout)
    x = re.search(r"\d+", output)
    if x:
        return int(x.group()) - 5
    else:
        return -1

def get_ipv6_route_count(dut, timeout=120):
    command = 'sudo bcmcmd "l3 ip6route show" | wc -l'
    output = st.show(dut, command, skip_tmpl=True, max_time=timeout)
    x = re.search(r"\d+", output)
    if x:
        return int(x.group()) - 7
    else:
        return -1

def bcmcmd_show_ps(dut):
    return bcm_show(dut, 'bcmcmd "ps"')

def get_pmap(dut):
    command = 'bcmcmd "show pmap"'
    return bcm_show(dut, command)

def exec_search(dut,command,param_list,match_dict,**kwargs):
    output = bcm_show(dut, 'bcmcmd "{}"'.format(command))
    if not output:
        st.error("output is empty")
        return False
    for key in match_dict.keys():
        if not cutils.filter_and_select(output,param_list,{key:match_dict[key]}):
            st.error("No match for key {} with value {}".format(key, match_dict[key]))
            return False
        else:
            st.log("Match found for key {} with value {}".format(key, match_dict[key]))
            return cutils.filter_and_select(output,param_list,{key:match_dict[key]})

def get_l2_out(dut, mac):
  return exec_search(dut,'l2 show',["gport"],{"mac":mac})

def get_l3_out(dut, mac):
  return exec_search(dut,'l3 egress show',["port"],{"mac":mac})

def dump_threshold_info(dut, test, platform, mode):
    """
    BCMCMD debug prints for Threshold feature.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param test:
    :param platform:
    :return:
    """
    if mode == "asic_portmap":
        bcm_show(dut, 'bcmcmd "ps"')
        bcm_show(dut, 'bcmcmd "show portmap"')
        return

    platform = platform.lower()
    hw_constants = st.get_datastore(dut, "constants")
    cmd = []
    # TH and TH2
    if platform in hw_constants["TH_PLATFORMS"] + hw_constants["TH2_PLATFORMS"]:
        cmd.append("g MMU_GCFG_BST_TRACKING_ENABLE")
        cmd.append("g THDI_BST_TRIGGER_STATUS_TYPE")
        cmd.append("g THDU_BST_STAT")
        cmd.append("g MMU_THDM_DB_DEVICE_BST_STAT")
        cmd.append("g THDI_BST_PG_SHARED_PROFILE_XPE0")
        cmd.append("g THDI_BST_PG_SHARED_PROFILE_XPE1")
        cmd.append("g THDI_BST_PG_SHARED_PROFILE_XPE2")
        cmd.append("g THDI_BST_PG_SHARED_PROFILE_XPE3")
        cmd.append("g THDI_BST_PG_HDRM_PROFILE_XPE0")
        cmd.append("g THDI_BST_PG_HDRM_PROFILE_XPE1")
        cmd.append("g THDI_BST_PG_HDRM_PROFILE_XPE2")
        cmd.append("g THDI_BST_PG_HDRM_PROFILE_XPE3")
        cmd.append("g OP_UC_QUEUE_BST_THRESHOLD")
        cmd.append("g MMU_THDM_DB_QUEUE_MC_BST_THRESHOLD_PROFILE")
        if test in ['shared', 'headroom']:
            cmd.append("d chg THDI_PORT_PG_BST_XPE0_PIPE0")
            cmd.append("d chg THDI_PORT_PG_BST_XPE0_PIPE3")
            cmd.append("d chg THDI_PORT_PG_BST_XPE1_PIPE0")
            cmd.append("d chg THDI_PORT_PG_BST_XPE1_PIPE3")
            cmd.append("d chg THDI_PORT_PG_BST_XPE2_PIPE1")
            cmd.append("d chg THDI_PORT_PG_BST_XPE2_PIPE2")
            cmd.append("d chg THDI_PORT_PG_BST_XPE3_PIPE1")
            cmd.append("d chg THDI_PORT_PG_BST_XPE3_PIPE2")
        elif test in ['unicast']:
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE0_PIPE0")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE0_PIPE1")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE1_PIPE2")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE1_PIPE3")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE2_PIPE0")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE2_PIPE1")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE3_PIPE2")
            cmd.append("d chg MMU_THDU_BST_QUEUE_XPE3_PIPE3")
        elif test in ['multicast']:
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE0_PIPE0")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE0_PIPE1")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE1_PIPE2")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE1_PIPE3")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE2_PIPE0")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE2_PIPE1")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE3_PIPE2")
            cmd.append("d chg MMU_THDM_DB_QUEUE_BST_XPE3_PIPE3")

    # TD3
    elif platform in hw_constants["TD3_PLATFORMS"]:
        cmd.extend(["g MMU_GCFG_BST_TRACKING_ENABLE", "g THDI_BST_TRIGGER_STATUS_TYPE"])
        cmd.extend(["g THDU_BST_STAT", "g MMU_THDM_DB_DEVICE_BST_STAT"])
        if test in ['shared', 'headroom']:
            cmd.extend(["d chg THDI_PORT_PG_BST_XPE0_PIPE0", "d chg THDI_PORT_PG_BST_XPE0_PIPE1"])
        elif test in ['unicast']:
            cmd.extend(["d chg MMU_THDU_BST_QUEUE_XPE0_PIPE0", "d chg MMU_THDU_BST_QUEUE_XPE0_PIPE1"])
        elif test in ['multicast']:
            cmd.extend(["d chg MMU_THDM_DB_QUEUE_BST_XPE0_PIPE0", "d chg MMU_THDM_DB_QUEUE_BST_XPE0_PIPE1"])

    # TD2
    elif platform in hw_constants["TD2_PLATFORMS"]:
        cmd.extend(["g BST_TRACKING_ENABLE", "g MMU_THDM_DB_DEVICE_BST_STAT"])
        cmd.extend(["g THDI_BST_TRIGGER_STATUS_TYPE_PIPEX", "g THDI_BST_TRIGGER_STATUS_TYPE_PIPEY"])
        if test in ['shared', 'headroom']:
            cmd.extend(["d chg THDI_PORT_PG_BST_X", "d chg THDI_PORT_PG_BST_Y"])
        elif test in ['unicast']:
            cmd.extend(["d chg MMU_THDU_XPIPE_BST_QUEUE", "d chg MMU_THDU_YPIPE_BST_QUEUE"])
        elif test in ['multicast']:
            cmd.extend(["d chg MMU_THDM_DB_QUEUE_BST_0", "d chg MMU_THDM_DB_QUEUE_BST_1"])

    # TH3
    elif platform in hw_constants["TH3_PLATFORMS"]:
        cmd.append("g MMU_GLBCFG_BST_TRACKING_ENABLE")
        cmd.append("g MMU_THDI_BST_PG_SHARED_PROFILE")
        cmd.append("g MMU_THDI_BST_PG_HDRM_PROFILE")
        cmd.append("g MMU_THDO_MC_QUEUE_TOT_BST_THRESHOLD")
        cmd.append("g MMU_THDO_QUE_TOT_BST_THRESHOLD")
        cmd.append("d MMU_THDI_PORT_BST_CONFIG_PIPEx (x=0-3)")
        cmd.append("d MMU_THDI_PORT_PG_SHARED_BST_PIPEx (x=0-3)")
        cmd.append("d MMU_THDO_BST_TOTAL_QUEUE_ITMx (x=0-1)")

    else:
        st.error('Unhandled platform - {}'.format(platform))

    for each_cmd in ['bcmcmd "{}"'.format(e) for e in cmd]:
        bcm_config(dut, each_cmd, skip_error_check=True)

def get_intf_pmap(dut, interface_name=None):
    """
    Author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This API is used to get the interface pmap details
    :param dut: dut
    :param interface_name: List of interface names
    :return:
    """
    import apis.system.interface as interface_obj
    ##Passing the cli_type as click in the API call "interface_status_show" because the lanes information is available only in click CLI.
    ##Please refer the JIRA: SONIC-22102 for more information.
    interfaces = cutils.make_list(interface_name) if interface_name else ''
    if interfaces:
        if any("/" in interface for interface in interfaces):
            interfaces = st.get_other_names(dut, interfaces)
            key = 'alias'
        else:
            key = 'interface'
        st.debug("The interfaces list is: {}".format(interfaces))
        interface_list = interface_obj.interface_status_show(dut, interfaces=interfaces, cli_type='click')
    else:
        key = 'alias' if interface_obj.show_ifname_type(dut, cli_type='klish') else 'interface'
        interface_list = interface_obj.interface_status_show(dut, cli_type='click')
    interface_pmap = dict()
    pmap_list = get_pmap(dut)
    for detail in cutils.iterable(interface_list):
        lane = detail["lanes"].split(",")[0] if "," in detail["lanes"] else detail["lanes"]
        for pmap in pmap_list:
            if pmap["physical"] == lane:
                interface_pmap[detail[key]] = pmap["interface"]
    return interface_pmap

def remove_vlan_1(dut):
    bcm_config(dut, 'bcmcmd "vlan remove 1 PortBitMap=all"')

