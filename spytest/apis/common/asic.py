
from spytest import st

def bcm_show(dut, cmd, skip_tmpl=True):
    if not st.is_feature_supported("bcmcmd", dut): return ""
    return st.show(dut, cmd, skip_tmpl=skip_tmpl)

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

def dump_counters(dut):
    bcm_show(dut, 'bcmcmd "show c"', skip_tmpl=False)

def clear_counters(dut):
    bcm_config(dut, 'bcmcmd "clear c"')

def bcmcmd_show_ps(dut):
    return bcm_show(dut, 'bcmcmd "ps"')

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

