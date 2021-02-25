#!/usr/bin/env python

import argparse
import json
import random
import re
import subprocess
import sys
import time
from collections import defaultdict

# Global parameter for memory scanners
MEMORY_SCAN_INTERVAL_USEC = int(3e5)
MEMORY_SCAN_ENTRIES = 16384
SRAM_SCAN_INTERVAL_USEC = int(3e5)
SRAM_SCAN_ENTRIES = 16384

DEFAULT_SER_INJECTION_INTERVAL_SEC = 0.1
DEFAULT_SYSLOG_POLLING_INTERVAL_SEC = 0.1

"""
Follow memory cannot be tested on corresponding platforms for reasons
    1). The memory was reported to be corrected at a different location without name.
    2). The memory was reported to be corrected only when corrupting another location.

How to create skip list on an new ASIC:
    1. configure target DUT to not timeout ssh connections.
    2. copy ser_injector.py to target DUT.
    3. on target DUT: 'python ser_injector.py -v -c thorough | tee ser.log', copy
       the timeout set to the matching asic.
    4. If a new ASIC is not known to this script yet. Update asci name
       and lspci signature in get_asic_name() function
"""
SKIP_MEMORY_PER_ASIC = {
    'td2' : [
        # cannot pass
        u'L3_DEFIP_ALPM_IPV4.ipipe0', u'L3_ENTRY_IPV6_MULTICAST.ipipe0', u'L3_ENTRY_IPV6_UNICAST.ipipe0',
        u'FP_GM_FIELDS.ipipe0', u'L3_ENTRY_IPV4_MULTICAST.ipipe0', u'L3_DEFIP_ALPM_IPV6_64.ipipe0',
        u'L3_DEFIP_ALPM_IPV6_128.ipipe0', u'FP_GLOBAL_MASK_TCAM.ipipe0', u'MODPORT_MAP_MIRROR.ipipe0',
        u'EGR_IP_TUNNEL_MPLS.epipe0',
        # fail only with basic mode
        u'EGR_IP_TUNNEL_IPV6.epipe0', u'EGR_DVP_ATTRIBUTE_1.epipe0', u'EGR_MPLS_VC_AND_SWAP_LABEL_TABLE.epipe0',
        u'L3_TUNNEL_DATA_ONLY.ipipe0',
        ],
    'td3' : [
        # cannot pass
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE3.mmu_sc0', u'ING_SNAT.ipipe0',
        u'TCB_THRESHOLD_PROFILE_MAP_XPE2.mmu_xpe0', u'MMU_THDU_OFFSET_QGROUP1_PIPE2.mmu_xpe0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE0.mmu_sc0', u'ING_VP_VLAN_MEMBERSHIP.ipipe0',
        u'L3_ENTRY_IPV4_UNICAST.ipipe0', u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE1.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_2.mmu_xpe0', u'MMU_THDU_CONFIG_PORT_PIPE3.mmu_xpe0',
        u'THDI_PORT_SP_CONFIG_PIPE3.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_4.mmu_xpe0',
        u'MMU_THDU_Q_TO_QGRP_MAP_PIPE0.mmu_xpe0', u'MMU_MTRO_CONFIG_L0_MEM_PIPE0.mmu_sed0',
        u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE2.mmu_xpe0', u'MMU_THDU_RESUME_PORT_PIPE0.mmu_xpe0',
        u'MMU_THDU_Q_TO_QGRP_MAP_PIPE2.mmu_xpe0', u'FP_STORM_CONTROL_METERS.ipipe0',
        u'THDI_PORT_SP_CONFIG_PIPE1.mmu_xpe0', u'MMU_THDU_RESUME_PORT_PIPE1.mmu_xpe0', u'VLAN_XLATE.ipipe0',
        u'MMU_THDU_OFFSET_QGROUP_PIPE1.mmu_xpe0', u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE0.mmu_sed0',
        u'MMU_THDM_DB_QUEUE_CONFIG_PIPE2.mmu_xpe0', u'MMU_THDU_CONFIG_PORT_PIPE2.mmu_xpe0',
        u'MMU_THDU_CONFIG_PORT_PIPE1.mmu_xpe0', u'MMU_THDU_Q_TO_QGRP_MAP_PIPE1.mmu_xpe0',
        u'MMU_MTRO_CONFIG_L0_MEM_PIPE1.mmu_sed0', u'IFP_TCAM.ipipe0', u'MMU_THDM_DB_QUEUE_CONFIG_PIPE0.mmu_xpe0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE1.mmu_sed0', u'L3_TUNNEL.ipipe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE1.mmu_xpe0', u'L2_ENTRY.ipipe0', u'L3_DEFIP_ALPM_IPV6_128.ipipe0',
        u'FP_GLOBAL_MASK_TCAM.ipipe0', u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE2.mmu_xpe0',
        u'MMU_THDM_DB_PORTSP_CONFIG_PIPE3.mmu_xpe0', u'MMU_THDU_OFFSET_QUEUE_PIPE3.mmu_xpe0', u'FP_GM_FIELDS.ipipe0',
        u'TCB_THRESHOLD_PROFILE_MAP_XPE1.mmu_xpe0', u'MMU_THDU_OFFSET_QUEUE_PIPE2.mmu_xpe0',
        u'EGR_IP_TUNNEL_IPV6.epipe0', u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE0.mmu_xpe0', u'MODPORT_MAP_MIRROR.ipipe0',
        u'VLAN_MAC.ipipe0', u'MMU_THDU_CONFIG_QUEUE_PIPE2.mmu_xpe0', u'MMU_THDU_RESUME_PORT_PIPE2.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE3.mmu_xpe0', u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE0.mmu_xpe0',
        u'MMU_THDU_OFFSET_QGROUP_PIPE3.mmu_xpe0', u'MMU_THDU_CONFIG_QGROUP_PIPE3.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_7.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_3.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE2.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE1.mmu_xpe0',
        u'INTFO_TC2PRI_MAPPING.mmu_glb0', u'MMU_MTRO_CONFIG_L0_MEM_PIPE2.mmu_sed0', u'MPLS_ENTRY_DOUBLE.ipipe0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE1.mmu_sc0', u'MMU_THDU_OFFSET_QUEUE_PIPE0.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_1_B.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_1.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE2.mmu_xpe0', u'EGR_IP_TUNNEL_MPLS.epipe0', u'L3_DEFIP_ALPM_IPV4.ipipe0',
        u'THDI_PORT_SP_CONFIG_PIPE2.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_0.mmu_xpe0',
        u'MMU_THDU_Q_TO_QGRP_MAP_PIPE3.mmu_xpe0', u'TCB_THRESHOLD_PROFILE_MAP_XPE0.mmu_xpe0',
        u'EGR_VP_VLAN_MEMBERSHIP.epipe0', u'MMU_WRED_DROP_CURVE_PROFILE_8.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE3.mmu_xpe0', u'MMU_THDU_CONFIG_QUEUE_PIPE0.mmu_xpe0',
        u'MMU_THDM_DB_PORTSP_CONFIG_PIPE2.mmu_xpe0', u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE1.mmu_xpe0',
        u'EGR_VLAN_XLATE.epipe0', u'L3_DEFIP_ALPM_IPV6_64.ipipe0', u'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC0.mmu_xpe0',
        u'L3_ENTRY_IPV6_MULTICAST.ipipe0', u'MMU_THDU_OFFSET_QGROUP_PIPE2.mmu_xpe0',
        u'MMU_THDU_CONFIG_QUEUE_PIPE1.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE0.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE1.mmu_xpe0', u'MMU_THDU_OFFSET_QUEUE_PIPE1.mmu_xpe0',
        u'MMU_THDU_CONFIG_PORT_PIPE0.mmu_xpe0', u'L3_ENTRY_IPV6_UNICAST.ipipe0', u'ING_DNAT_ADDRESS_TYPE.ipipe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE0.mmu_xpe0', u'MMU_THDM_DB_PORTSP_CONFIG_PIPE1.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_CONFIG_PIPE3.mmu_xpe0', u'L3_ENTRY_IPV4_MULTICAST.ipipe0',
        u'MMU_THDU_CONFIG_QUEUE_PIPE3.mmu_xpe0', u'THDI_PORT_SP_CONFIG_PIPE0.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_5.mmu_xpe0', u'TCB_THRESHOLD_PROFILE_MAP_XPE3.mmu_xpe0',
        u'MMU_THDU_RESUME_PORT_PIPE3.mmu_xpe0', u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE3.mmu_xpe0',
        u'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC1.mmu_xpe0', u'MMU_MTRO_CONFIG_L0_MEM_PIPE3.mmu_sed0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE2.mmu_sc0', u'MMU_THDM_DB_PORTSP_CONFIG_PIPE0.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_6.mmu_xpe0', u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE3.mmu_sed0',
        u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE0.mmu_xpe0', u'MMU_THDM_DB_PORTSP_CONFIG_C_PIPE3.mmu_xpe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE2.mmu_xpe0', u'MMU_THDM_DB_QUEUE_CONFIG_PIPE1.mmu_xpe0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE2.mmu_sed0', u'IFP_TCAM_WIDE_PIPE3.ipipe0',
        u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE3.mmu_xpe0', u'MMU_THDU_OFFSET_QGROUP_PIPE0.mmu_xpe0',
        u'IFP_TCAM_WIDE_PIPE2.ipipe0',
        # fail only with basic mode
        u'MODPORT_MAP_SUBPORT_MIRROR.ipipe0', u'EGR_VLAN_XLATE_2_DOUBLE.epipe0', u'PKT_FLOW_SELECT_TCAM_2.ipipe0',
        u'EGR_ZONE_3_EDITOR_CONTROL_TCAM.epipe0', u'RH_ECMP_FLOWSET_PIPE0.ipipe0', u'EGR_VLAN_XLATE_1_DOUBLE.epipe0',
        u'RH_ECMP_FLOWSET.ipipe0', u'DST_COMPRESSION_PIPE1.ipipe0', u'EGR_FIELD_EXTRACTION_PROFILE_2_TCAM.epipe0',
        u'VLAN_XLATE_2_DOUBLE.ipipe0', u'L3_DEFIP.ipipe0', u'EGR_PKT_FLOW_SELECT_TCAM.epipe0',
        u'FLEX_RTAG7_HASH_TCAM.ipipe0', u'L2_ENTRY_SINGLE.ipipe0', u'VLAN_XLATE_1_SINGLE.ipipe0',
        u'EGR_FIELD_EXTRACTION_PROFILE_1_TCAM.epipe0', u'EXACT_MATCH_LOGICAL_TABLE_SELECT.ipipe0',
        u'SRC_COMPRESSION.ipipe0', u'EGR_VLAN_XLATE_1_SINGLE.epipe0', u'RH_HGT_FLOWSET_PIPE0.ipipe0',
        u'VLAN_SUBNET.ipipe0', u'RH_LAG_FLOWSET_PIPE1.ipipe0', u'MY_STATION_TCAM_2.ipipe0',
        u'EGR_ZONE_4_EDITOR_CONTROL_TCAM.epipe0', u'RH_LAG_FLOWSET.ipipe0', u'RH_HGT_FLOWSET_PIPE1.ipipe0',
        u'L3_DEFIP_PAIR_128.ipipe0', u'L3_ENTRY_ONLY_SINGLE.ipipe0', u'MPLS_ENTRY_SINGLE.ipipe0',
        u'EGR_ZONE_2_EDITOR_CONTROL_TCAM.epipe0', u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE1.ipipe0',
        u'IFP_TCAM_PIPE1.ipipe0', u'L3_ENTRY_QUAD.ipipe0', u'RH_ECMP_FLOWSET_PIPE1.ipipe0',
        u'VLAN_XLATE_2_SINGLE.ipipe0', u'L2_ENTRY_ONLY_SINGLE.ipipe0', u'EGR_ZONE_1_EDITOR_CONTROL_TCAM.epipe0',
        u'SRC_COMPRESSION_PIPE0.ipipe0', u'L3_ENTRY_ONLY_DOUBLE.ipipe0', u'SRC_COMPRESSION_PIPE1.ipipe0',
        u'SUBPORT_ID_TO_SGPP_MAP.ipipe0', u'PKT_FLOW_SELECT_TCAM_0.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE0.ipipe0', u'L3_ENTRY_SINGLE.ipipe0', u'DST_COMPRESSION.ipipe0',
        u'L2_USER_ENTRY.ipipe0', u'L3_ENTRY_ONLY_QUAD.ipipe0', u'PKT_FLOW_SELECT_TCAM_1.ipipe0',
        u'IP_PARSER1_MICE_TCAM_0.ipipe0', u'PHB_SELECT_TCAM.ipipe0', u'MY_STATION_TCAM.ipipe0',
        u'CPU_COS_MAP.ipipe0', u'L3_DEFIP_ALPM_RAW.ipipe0', u'DST_COMPRESSION_PIPE0.ipipe0',
        u'IFP_LOGICAL_TABLE_SELECT.ipipe0', u'IFP_LOGICAL_TABLE_SELECT_PIPE0.ipipe0', u'VLAN_XLATE_1_DOUBLE.ipipe0',
        u'RH_HGT_FLOWSET.ipipe0', u'IFP_TCAM_PIPE0.ipipe0', u'IP_PARSER1_MICE_TCAM_1.ipipe0',
        u'EGR_IP_TUNNEL_MPLS_DOUBLE_WIDE.epipe0', u'IFP_LOGICAL_TABLE_SELECT_PIPE1.ipipe0', u'L3_ENTRY_DOUBLE.ipipe0',
        u'IP_PARSER2_MICE_TCAM_1.ipipe0', u'IP_PARSER2_MICE_TCAM_0.ipipe0', u'RH_LAG_FLOWSET_PIPE0.ipipe0',
        u'EGR_VLAN_XLATE_2_SINGLE.epipe0', u'EGR_QOS_CTRL_TCAM.epipe0', u'EGR_ZONE_0_EDITOR_CONTROL_TCAM.epipe0',
        # fail randomly with basic mode
        u'IFP_POLICY_TABLE_WIDE_PIPE0.ipipe0', u'IFP_POLICY_TABLE_WIDE.ipipe0', u'IFP_POLICY_TABLE_WIDE_PIPE1.ipipe0',
        u'IFP_METER_TABLE_PIPE1.ipipe0', u'IFP_METER_TABLE.ipipe0',
        ],
    'th' : [
        # cannot pass
        u'EGR_IP_TUNNEL_MPLS.epipe0', u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE1.mmu_xpe0',
        u'MMU_THDU_RESUME_PORT_PIPE3.mmu_xpe0', u'MMU_THDU_CONFIG_QUEUE_PIPE2.mmu_xpe0', u'MPLS_ENTRY_DOUBLE.ipipe0',
        u'MMU_THDU_CONFIG_QUEUE_PIPE3.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_8.mmu_xpe0',
        u'IFP_TCAM_WIDE_PIPE2.ipipe0', u'FP_GM_FIELDS.ipipe0', u'FP_STORM_CONTROL_METERS.ipipe0',
        u'MMU_THDU_OFFSET_QUEUE_PIPE1.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_2.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE1.mmu_xpe0', u'THDI_PORT_SP_CONFIG_PIPE1.mmu_xpe0',
        u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE1.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE3.mmu_xpe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE0.mmu_xpe0', u'MMU_THDU_CONFIG_QGROUP_PIPE3.mmu_xpe0',
        u'EGR_IP_TUNNEL_IPV6.epipe0', u'MODPORT_MAP_MIRROR.ipipe0', u'MMU_THDU_OFFSET_QGROUP_PIPE1.mmu_xpe0',
        u'THDI_PORT_SP_CONFIG_PIPE0.mmu_xpe0', u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE3.mmu_xpe0',
        u'MMU_THDM_DB_PORTSP_CONFIG_PIPE1.mmu_xpe0', u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE0.mmu_sc0',
        u'L3_DEFIP_ALPM_IPV6_128.ipipe0', u'IFP_TCAM_WIDE_PIPE3.ipipe0', u'MMU_THDU_Q_TO_QGRP_MAP_PIPE0.mmu_xpe0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE2.mmu_sc0', u'MMU_THDM_DB_QUEUE_CONFIG_PIPE2.mmu_xpe0',
        u'MMU_THDM_DB_PORTSP_CONFIG_PIPE2.mmu_xpe0', u'MMU_THDU_Q_TO_QGRP_MAP_PIPE2.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE2.mmu_xpe0', u'VLAN_XLATE.ipipe0',
        u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE3.mmu_xpe0', u'VLAN_MAC.ipipe0', u'MMU_THDU_CONFIG_QUEUE_PIPE1.mmu_xpe0',
        u'MMU_THDU_RESUME_PORT_PIPE2.mmu_xpe0', u'MMU_THDM_DB_QUEUE_CONFIG_PIPE1.mmu_xpe0',
        u'L3_DEFIP_ALPM_IPV4.ipipe0', u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE3.mmu_sc0',
        u'MMU_THDM_DB_PORTSP_CONFIG_PIPE0.mmu_xpe0', u'IFP_TCAM_WIDE_PIPE1.ipipe0',
        u'MMU_THDM_DB_PORTSP_CONFIG_PIPE3.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_6.mmu_xpe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE2.mmu_xpe0', u'FP_GLOBAL_MASK_TCAM.ipipe0',
        u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE0.mmu_xpe0', u'L3_ENTRY_IPV4_MULTICAST.ipipe0',
        u'THDI_PORT_SP_CONFIG_PIPE3.mmu_xpe0', u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE3.mmu_xpe0',
        u'MMU_THDU_OFFSET_QGROUP_PIPE2.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_4.mmu_xpe0',
        u'MMU_THDU_OFFSET_QGROUP_PIPE3.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE0.mmu_xpe0',
        u'MMU_THDU_Q_TO_QGRP_MAP_PIPE1.mmu_xpe0', u'MMU_THDU_RESUME_PORT_PIPE0.mmu_xpe0',
        u'IFP_TCAM_WIDE_PIPE0.ipipe0', u'L3_ENTRY_IPV6_MULTICAST.ipipe0', u'MMU_THDU_OFFSET_QUEUE_PIPE2.mmu_xpe0',
        u'IFP_TCAM.ipipe0', u'THDI_PORT_SP_CONFIG_PIPE2.mmu_xpe0', u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE0.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE2.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE2.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_3.mmu_xpe0', u'MMU_THDU_OFFSET_QGROUP_PIPE0.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_1.mmu_xpe0', u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE1.mmu_sc0',
        u'MMU_THDU_RESUME_PORT_PIPE1.mmu_xpe0', u'EGR_VLAN_XLATE.epipe0', u'MMU_THDU_Q_TO_QGRP_MAP_PIPE3.mmu_xpe0',
        u'L3_ENTRY_IPV4_UNICAST.ipipe0', u'MMU_WRED_DROP_CURVE_PROFILE_7.mmu_xpe0',
        u'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC0.mmu_xpe0', u'MMU_THDU_OFFSET_QUEUE_PIPE3.mmu_xpe0',
        u'MMU_THDU_CONFIG_PORT_PIPE2.mmu_xpe0', u'L2_ENTRY.ipipe0', u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE2.mmu_xpe0',
        u'MMU_THDU_CONFIG_PORT_PIPE1.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE0.mmu_xpe0',
        u'MMU_THDU_CONFIG_PORT_PIPE3.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_0.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE1.mmu_xpe0', u'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC1.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_CONFIG_PIPE3.mmu_xpe0', u'MMU_WRED_DROP_CURVE_PROFILE_5.mmu_xpe0',
        u'L3_DEFIP_ALPM_IPV6_64.ipipe0', u'MMU_THDM_DB_QUEUE_CONFIG_PIPE0.mmu_xpe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE1.mmu_xpe0', u'MMU_THDU_OFFSET_QUEUE_PIPE0.mmu_xpe0',
        u'L3_ENTRY_IPV6_UNICAST.ipipe0',
        # fail randomly with basic mode
        u'IFP_POLICY_TABLE_PIPE0.ipipe0', u'IFP_POLICY_TABLE.ipipe0', u'MMU_THDU_CONFIG_QUEUE_PIPE0.mmu_xpe0',
        u'EXACT_MATCH_4_PIPE1.ipipe0', u'EXACT_MATCH_4_PIPE2.ipipe0', u'EXACT_MATCH_2_PIPE1.ipipe0',
        u'EXACT_MATCH_4_PIPE0.ipipe0', u'EXACT_MATCH_2_PIPE2.ipipe0', u'EXACT_MATCH_2_PIPE0.ipipe0',
        u'EXACT_MATCH_4_PIPE3.ipipe0', u'EXACT_MATCH_4.ipipe0', u'EXACT_MATCH_2_PIPE3.ipipe0',
        u'EXACT_MATCH_2.ipipe0', u'ING_FLEX_CTR_OFFSET_TABLE_11.ipipe0', u'PORT_LAG_FAILOVER_SET.ipipe0',
        u'VFP_POLICY_TABLE_PIPE2.ipipe0', u'Q_SCHED_L1_WEIGHT_MEM_PIPE2.mmu_sc0', u'SYSTEM_CONFIG_TABLE.ipipe0',
        u'RTAG7_PORT_BASED_HASH.ipipe0', u'MMU_REPL_LIST_TBL_PIPE2.mmu_sc0', u'EGR_GPP_ATTRIBUTES.epipe0',
        u'EGRESS_MASK.ipipe0', u'MMU_THDU_CONFIG_QUEUE_PIPE0.mmu_xpe0', u'EMIRROR_CONTROL2.ipipe0',
        u'VLAN_MPLS.ipipe0', u'ING_DVP_TABLE.ipipe0', u'EXACT_MATCH_QOS_ACTIONS_PROFILE.ipipe0',
        u'MMU_REPL_GROUP_INFO_TBL_PIPE3.mmu_sc0', u'MMU_REPL_LIST_TBL_PIPE1.mmu_sc0', u'VFI_1.ipipe0',
        u'MMU_THDU_CONFIG_PORT_PIPE0.mmu_xpe0', u'EFP_POLICY_TABLE_PIPE0.epipe0', u'EFP_POLICY_TABLE.epipe0',
        u'IFP_STORM_CONTROL_METERS.ipipe0',
        ],
    'th2' : [
        # cannot pass
        u'TCB_THRESHOLD_PROFILE_MAP_XPE3.mmu_xpe0', u'MMU_THDU_RESUME_PORT_PIPE0.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE3.mmu_xpe0', u'VLAN_MAC.ipipe0', u'EGR_VP_VLAN_MEMBERSHIP.epipe0',
        u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE1.mmu_xpe0', u'MMU_THDM_DB_PORTSP_CONFIG_PIPE3.mmu_xpe0',
        u'MMU_THDU_RESUME_PORT_PIPE3.mmu_xpe0', u'MMU_THDU_CONFIG_QUEUE_PIPE2.mmu_xpe0',
        u'TCB_THRESHOLD_PROFILE_MAP_XPE1.mmu_xpe0', u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE2.mmu_sed0',
        u'MMU_THDU_OFFSET_QGROUP_PIPE2.mmu_xpe0', u'MMU_THDM_DB_QUEUE_CONFIG_PIPE0.mmu_xpe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE0.mmu_xpe0', u'MMU_MTRO_CONFIG_L0_MEM_PIPE2.mmu_sed0',
        u'L3_ENTRY_IPV6_MULTICAST.ipipe0', u'MMU_WRED_DROP_CURVE_PROFILE_0.mmu_xpe0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE0.mmu_sed0', u'VLAN_XLATE.ipipe0',
        u'MMU_THDU_RESUME_PORT_PIPE1.mmu_xpe0', u'L3_ENTRY_IPV4_MULTICAST.ipipe0',
        u'MMU_THDU_OFFSET_QUEUE_PIPE0.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE0.mmu_xpe0',
        u'INTFO_TC2PRI_MAPPING.mmu_glb0', u'MMU_THDU_Q_TO_QGRP_MAP_PIPE1.mmu_xpe0',
        u'MMU_MTRO_CONFIG_L0_MEM_PIPE3.mmu_sed0', u'MMU_THDU_OFFSET_QGROUP_PIPE0.mmu_xpe0',
        u'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC1.mmu_xpe0', u'MMU_THDU_CONFIG_QUEUE_PIPE0.mmu_xpe0',
        u'IFP_TCAM_WIDE_PIPE0.ipipe0', u'L3_DEFIP_ALPM_IPV6_64.ipipe0', u'MMU_WRED_DROP_CURVE_PROFILE_6.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_5.mmu_xpe0', u'IFP_TCAM_WIDE_PIPE2.ipipe0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE3.mmu_sed0', u'MMU_THDU_CONFIG_QGROUP_PIPE1.mmu_xpe0',
        u'THDI_PORT_SP_CONFIG_PIPE3.mmu_xpe0', u'MMU_THDU_RESUME_PORT_PIPE2.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_CONFIG_PIPE1.mmu_xpe0', u'MMU_THDM_MCQE_PORTSP_CONFIG_C_PIPE3.mmu_xpe0',
        u'L3_TUNNEL.ipipe0', u'MPLS_ENTRY_DOUBLE.ipipe0', u'ING_DNAT_ADDRESS_TYPE.ipipe0',
        u'THDI_PORT_SP_CONFIG_PIPE0.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE2.mmu_xpe0',
        u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE3.mmu_xpe0', u'L3_DEFIP_ALPM_IPV4.ipipe0',
        u'MMU_THDM_DB_PORTSP_CONFIG_PIPE0.mmu_xpe0', u'MMU_MTRO_CONFIG_L0_MEM_PIPE0.mmu_sed0',
        u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE3.mmu_xpe0', u'MMU_THDM_DB_PORTSP_CONFIG_PIPE2.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_3.mmu_xpe0', u'IFP_TCAM_WIDE_PIPE1.ipipe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE2.mmu_xpe0', u'MMU_THDU_Q_TO_QGRP_MAP_PIPE3.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_2.mmu_xpe0', u'MMU_THDU_CONFIG_PORT_PIPE1.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_7.mmu_xpe0', u'L3_ENTRY_IPV4_UNICAST.ipipe0', u'IFP_TCAM_WIDE_PIPE3.ipipe0',
        u'MMU_THDU_CONFIG_QGROUP_PIPE3.mmu_xpe0', u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE2.mmu_xpe0',
        u'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE1.mmu_sed0', u'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC0.mmu_xpe0',
        u'MMU_THDU_CONFIG_QUEUE_PIPE3.mmu_xpe0', u'THDI_PORT_SP_CONFIG_PIPE2.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_8.mmu_xpe0', u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE2.mmu_xpe0',
        u'TCB_THRESHOLD_PROFILE_MAP_XPE0.mmu_xpe0', u'MMU_THDU_CONFIG_PORT_PIPE0.mmu_xpe0',
        u'MMU_THDU_OFFSET_QUEUE_PIPE1.mmu_xpe0', u'MMU_THDU_Q_TO_QGRP_MAP_PIPE2.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE1.mmu_xpe0', u'L3_DEFIP_ALPM_IPV6_128.ipipe0',
        u'MMU_THDM_DB_QUEUE_CONFIG_PIPE3.mmu_xpe0', u'MODPORT_MAP_MIRROR.ipipe0', u'IFP_TCAM.ipipe0',
        u'MMU_THDM_DB_PORTSP_CONFIG_PIPE1.mmu_xpe0', u'EGR_VLAN_XLATE.epipe0', u'FP_GM_FIELDS.ipipe0',
        u'MMU_THDU_CONFIG_QUEUE_PIPE1.mmu_xpe0', u'MMU_MTRO_CONFIG_L0_MEM_PIPE1.mmu_sed0',
        u'THDI_PORT_SP_CONFIG_PIPE1.mmu_xpe0', u'MMU_THDU_OFFSET_QGROUP_PIPE1.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE0.mmu_xpe0', u'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE0.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_4.mmu_xpe0', u'TCB_THRESHOLD_PROFILE_MAP_XPE2.mmu_xpe0',
        u'FP_STORM_CONTROL_METERS.ipipe0', u'L2_ENTRY.ipipe0', u'EGR_IP_TUNNEL_IPV6.epipe0',
        u'MMU_THDU_OFFSET_QUEUE_PIPE3.mmu_xpe0', u'MMU_THDU_OFFSET_QUEUE_PIPE2.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE2.mmu_xpe0', u'MMU_THDU_CONFIG_PORT_PIPE2.mmu_xpe0',
        u'L3_ENTRY_IPV6_UNICAST.ipipe0', u'MMU_THDU_Q_TO_QGRP_MAP_PIPE0.mmu_xpe0',
        u'MMU_WRED_DROP_CURVE_PROFILE_1.mmu_xpe0', u'MMU_THDM_DB_QUEUE_CONFIG_PIPE2.mmu_xpe0',
        u'EGR_IP_TUNNEL_MPLS.epipe0', u'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE3.mmu_xpe0',
        u'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE1.mmu_xpe0', u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE1.mmu_xpe0',
        u'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE0.mmu_xpe0', u'ING_SNAT.ipipe0',
        u'MMU_THDM_MCQE_QUEUE_OFFSET_B_PIPE1.mmu_xpe0', u'MMU_THDU_OFFSET_QGROUP_PIPE3.mmu_xpe0',
        u'ING_VP_VLAN_MEMBERSHIP.ipipe0', u'MMU_THDU_CONFIG_PORT_PIPE3.mmu_xpe0', u'FP_GLOBAL_MASK_TCAM.ipipe0',
        ],
    'th3' : [
        # cannot pass
        u'L3_DEFIP_TCAM_LEVEL1.ipipe0',
        u'MATCH_LOGICAL_TABLE_SELECT_PIPE7.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE7.ipipe0',
        u'MMU_QSCH_L2_WEIGHT_MEM_PIPE7.mmu_eb0',
        u'L3_ENTRY_ONLY_SINGLE.ipipe0',
        u'IFP_LOGICAL_TABLE_SELECT_PIPE6.ipipe0',
        u'MMU_QSCH_L2_WEIGHT_MEM_PIPE3.mmu_eb0',
        u'IFP_LOGICAL_TABLE_SELECT_PIPE0.ipipe0',
        u'L3_ENTRY_SINGLE.ipipe0',
        u'L2_ENTRY.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE6.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE0.ipipe0',
        u'L3_DEFIP_ALPM_LEVEL3.ipipe0',
        u'L3_ENTRY_DOUBLE.ipipe0',
        u'L3_TUNNEL_QUAD.ipipe0',
        u'L3_DEFIP_PAIR_LEVEL1.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE3.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE1.ipipe0',
        u'L3_ENTRY_ONLY_DOUBLE.ipipe0',
        u'MMU_QSCH_L2_WEIGHT_MEM_PIPE0.mmu_eb0',
        u'L3_DEFIP_ALPM_LEVEL2.ipipe0',
        u'EGR_IP_TUNNEL_IPV6.epipe0',
        u'EXACT_MATCH_ECC.ipipe0',
        u'IFP_LOGICAL_TABLE_SELECT_PIPE3.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE5.ipipe0',
        u'L3_DEFIP_ALPM_LEVEL3_SINGLE.ipipe0',
        u'IFP_LOGICAL_TABLE_SELECT.ipipe0',
        u'MMU_QSCH_L2_WEIGHT_MEM_PIPE5.mmu_eb0',
        u'IFP_LOGICAL_TABLE_SELECT_PIPE2.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE2.ipipe0',
        u'L3_ENTRY_QUAD.ipipe0',
        u'IFP_LOGICAL_TABLE_SELECT_PIPE1.ipipe0',
        u'EGR_IP_TUNNEL_MPLS.epipe0',
        u'IFP_LOGICAL_TABLE_SELECT_PIPE5.ipipe0',
        u'MMU_QSCH_L2_WEIGHT_MEM_PIPE4.mmu_eb0',
        u'L2_USER_ENTRY.ipipe0',
        u'MMU_QSCH_L2_WEIGHT_MEM_PIPE6.mmu_eb0',
        u'MY_STATION_TCAM.ipipe0',
        u'IFP_LOGICAL_TABLE_SELECT_PIPE4.ipipe0',
        u'L3_DEFIP_LEVEL1.ipipe0'        ,
        u'MMU_QSCH_L2_WEIGHT_MEM_PIPE2.mmu_eb0',
        u'L3_DEFIP_ALPM_LEVEL2_SINGLE.ipipe0',
        u'L3_TUNNEL_DOUBLE.ipipe0',
        u'L3_ENTRY_ONLY_QUAD.ipipe0',
        u'IFP_LOGICAL_TABLE_SELECT_PIPE7.ipipe0',
        u'MMU_QSCH_L2_WEIGHT_MEM_PIPE1.mmu_eb0',
        u'MPLS_ENTRY_SINGLE.ipipe0',
        u'CPU_COS_MAP.ipipe0',
        u'L3_TUNNEL_SINGLE.ipipe0',
        u'L3_DEFIP_ALPM_LEVEL2_HIT_ONLY.ipipe0',
        u'L2_ENTRY_ONLY_SINGLE.ipipe0',
        u'L3_DEFIP_LEVEL1_HIT_ONLY.ipipe0',
        u'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE4.ipipe0',
        u'L3_DEFIP_ALPM_LEVEL3_HIT_ONLY.ipipe0'
        ]
}

# Stop trying if stall has been detected for so many consecutive iterations
# Combined with the test duration below. If we don't make progress for so
# long, then we stop waiting.
DEFAULT_STALL_INDICATION = 15
DEFAULT_SER_TEST_TIME_SEC = 60
DEFAULT_BATCH_SIZE=10

# Print verbose output for debugging
VERBOSE=False

def run_cmd(cmd):
    '''
    @summary: Utility that runs a command in a subprocess
    @param cmd: Command to be run
    @return: stdout of the command run
    @return: stderr of the command run
    '''
    out = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()
    return stdout, stderr

def get_asic_name():
    asic = "unknown"
    stdout, _ = run_cmd("lspci")
    output = stdout.decode("utf-8")
    if ("Broadcom Limited Device b960" in output or
        "Broadcom Limited Broadcom BCM56960" in output):
        asic = "th"
    elif "Broadcom Limited Device b971" in output:
        asic = "th2"
    elif "Broadcom Limited Device b850" in output:
        asic = "td2"
    elif "Broadcom Limited Device b870" in output:
        asic = "td3"
    elif "Broadcom Limited Device b980" in output:
        asic = "th3"

    return asic


def get_skip_list_per_asic():
    global SKIP_MEMORY_PER_ASIC

    asic = get_asic_name()

    return SKIP_MEMORY_PER_ASIC[asic] if asic in SKIP_MEMORY_PER_ASIC else []


class BcmMemory():
    '''
    @summary: BcmMemory captures different memory tables of the Broadcom ASIC. Memory are split into two categories:
              cached and uncached. Broadcom SER correction is enabled for cached memory tables. For cached memory tables,
              memory attributes are also retreived
    '''
    def __init__(self):
        '''
        @summary: Class constructor
        '''
        self.cached_memory = {}
        self.uncached_memory = {}
        self.memory_address = {}

    def get_memory_attributes(self, mem):
        '''
        @summary: Reads Broadcom memory attributes using list command. Attributes include start address, flags,
                  number of entries, entry size in bytes and entry size in words. The method uses regex to parse
                  the command output since there is not SAI APIs for it.
        '''
        stdout, stderr = run_cmd(["bcmcmd",  "list " + mem])

        attributes = stdout.decode("utf-8").split("\n")

        attr = {}
        m = re.search('^Memory:.*address (.+)$', attributes[1])
        attr['address'] = int(m.group(1), 16)

        m = re.search('^Flags: (.*)$', attributes[2])
        attr['flags'] = m.group(1).strip().split(" ")

        m = re.search('^Entries: (\d+).*each (\d+) bytes (\d+) words', attributes[4])
        attr['entries'] = int(m.group(1))
        attr['size_byte'] = int(m.group(2))
        attr['size_word'] = int(m.group(3))

        return attr

    def rekey_memory_address(self, mem):
        # Reading from file will change key type from int to str.
        # for the test to run correctly, the key needs to be
        # adjusted back to int.
        for key, val in mem.items():
            self.memory_address[int(key)] = val

    def read_memory_from_file(self):
        file_name = '/tmp/{}-mem-info.json'.format(get_asic_name())
        try:
            with open(file_name, 'r') as info:
                contents = json.load(info)
            self.cached_memory = contents['cached_memory']
            self.uncached_memory = contents['uncached_memory']
            self.rekey_memory_address(contents['memory_address'])
        except IOError as e:
            return False

        return True

    def write_memory_to_file(self):
        contents = { 'cached_memory' : self.cached_memory,
                     'uncached_memory' : self.uncached_memory,
                     'memory_address' : self.memory_address }
        file_name = '/tmp/{}-mem-info.json'.format(get_asic_name())
        try:
            with open(file_name, 'w') as info:
                json.dump(contents, info, indent=4)
        except IOError as e:
            pass

    def read_memory(self):
        '''
        @summary: Read different memory tables using cache command. It update both cached_memory and uncached_memory
                  hash tables. For cached memory, ut aksi creat a reverse index of address to memory table name. This indez
                  is stored in memory_address hash table

                  Sample output of bcmcmd 'cache' command:
                  cache
                  Caching is off for:
                       COS_MAP_SEL.ipipe0
                       CPU_COS_MAP_DATA_ONLY.ipipe0
                       .
                  Caching is on for:
                       ALTERNATE_EMIRROR_BITMAP.ipipe0
                       BCAST_BLOCK_MASK.ipipe0
        '''
        if self.read_memory_from_file():
            return

        stdout, stderr = run_cmd(['bcmcmd', 'cache'])

        cache_flag = False
        memories = stdout.decode("utf-8").split("\n")

        # remove Head line and 3 trailing prompt lines
        memories = memories[1 : len(memories) - 3]
        for memory in memories:
            if memory.find("Caching is off") > -1:
                cache_flag = False
            elif memory.find("Caching is on") > -1:
                cache_flag = True
            else:
                if cache_flag:
                    self.cached_memory.update({mem:{} for mem in memory.strip().split(" ")})
                else:
                    self.uncached_memory.update({mem:{} for mem in memory.strip().split(" ")})

        self.memory_address = defaultdict(list)
        for mem in self.cached_memory:
            self.cached_memory[mem] = self.get_memory_attributes(mem)
            self.memory_address[self.cached_memory[mem]['address']].append(mem)
            if VERBOSE:
                print('--- found cache memory {} : {} : {}'.format(mem, hex(self.cached_memory[mem]['address']), self.memory_address[self.cached_memory[mem]['address']]))

        self.write_memory_to_file()

    def get_cached_memory(self):
        '''
        @summary: Accessor method for cached_memory hash table
        '''
        return self.cached_memory

    def get_memory_by_address(self):
        '''
        @summary: Accessor method for memory_address hash table
        '''
        return self.memory_address

class SerTest(object):
    '''
    @summary: SerTest conducts SER injection test on Broadcom ASIC. SER injection test use Broadcom SER injection
              utility to insert SER into different memory tables. Before the SER injection, Broadcom mem/sram scanners
              are started and syslog file location is marked. Subsequently, the test proceeeds into monitoring syslog
              for any SER correction taking place.
    '''
    def __init__(self, test_time_sec = DEFAULT_SER_TEST_TIME_SEC,
                 ser_injection_interval_sec = DEFAULT_SER_INJECTION_INTERVAL_SEC,
                 syslog_poll_interval_sec = DEFAULT_SYSLOG_POLLING_INTERVAL_SEC,
                 stall_indication = DEFAULT_STALL_INDICATION):
        '''
        @summary: Class constructor
        '''
        self.syslog_poll_interval_sec = syslog_poll_interval_sec
        self.test_time_sec = test_time_sec
        self.ser_injection_interval_sec = ser_injection_interval_sec
        self.stall_indication = stall_indication
        self.test_candidates = []
        self.mem_verification_pending = []
        self.mem_verified = {}
        self.mem_failed = {}
        self.mem_ser_unsupported = []
        self.miss_counts = {}
        self.bcmMemory = BcmMemory()


    def test_memory(self, completeness='basic'):
        '''
        @summary: perform SER memory test
        '''
        global MEMORY_SCAN_INTERVAL_USEC
        global MEMORY_SCAN_ENTRIES
        global SRAM_SCAN_INTERVAL_USEC
        global SRAM_SCAN_ENTRIES

        skip_list = []

        self.bcmMemory.read_memory()
        if completeness == 'thorough':
            self.test_candidates = list(set(self.bcmMemory.get_cached_memory().keys()))
        elif completeness == 'diagnose':
            # Re-probing the normally skipped entries
            self.test_candidates = get_skip_list_per_asic()
        else:
            skip_list = get_skip_list_per_asic()
            self.test_candidates = list(set(self.bcmMemory.get_cached_memory().keys()) - set(skip_list))

        if completeness == 'debug':
            batch_size = min(1, len(self.test_candidates))
            self.mem_verification_pending = random.sample(self.test_candidates, batch_size)
        elif completeness == 'basic':
            batch_size = min(DEFAULT_BATCH_SIZE, len(self.test_candidates))
            sample_size = min(batch_size * 6, len(self.test_candidates))
            self.mem_verification_pending = random.sample(self.test_candidates, sample_size)
        else:
            batch_size = min(DEFAULT_BATCH_SIZE, len(self.test_candidates))
            # Still go through random to ramdomize the ordering
            self.mem_verification_pending = random.sample(self.test_candidates, len(self.test_candidates))

        # Enable memory scan and sram scan once for all memories
        self.enable_mem_scan(MEMORY_SCAN_INTERVAL_USEC, MEMORY_SCAN_ENTRIES)
        self.enable_sram_scan(SRAM_SCAN_INTERVAL_USEC, SRAM_SCAN_ENTRIES)

        count = 0
        stall = 0
        # Test idea: initiaate small batches and wait for short timeout, until the test
        #            is either done or stalled.
        #            running test this way because:
        #            - Injecting too many errors takes too long.
        #            - Lots of memory name reported identical address. So chances are one
        #              test will cover many memory names.
        #            - Because the test is watching the syslog and take hit memory out of
        #              the candidate list, so we could afford to use short timeout.
        #            - As result of short timeout, we need to make sure we don't declare
        #              stalling too fast.
        #            - Increase batch size when stalling is detected. So that eventually,
        #              all remaining memory will be tested in each iteration.
        while (len(self.mem_verification_pending) > 0):
            count += 1
            print("Test iteration {}, stalled {}, candidate(s) left {}".format(count, stall, len(self.mem_verification_pending)))
            size_before = len(self.mem_verification_pending)
            batch_size = min(batch_size, size_before)
            test_memory = list(self.mem_verification_pending[0:batch_size])
            self.run_test(test_memory)
            size_after = len(self.mem_verification_pending)
            if size_before != size_after:
                # No need to track misses until the stalling starts
                self.miss_counts = {}
                stall = 0
            else:
                stall = stall + 1
                batch_size = min(len(self.mem_verification_pending), batch_size + DEFAULT_BATCH_SIZE) # Increase batch size when stall is detected
                if stall >= self.stall_indication:
                    if VERBOSE:
                        print('--- stall detected. Stop testing')
                    break

        print("SER test on ASIC : {}".format(get_asic_name()))
        if VERBOSE:
            print("SER Test memories candidates (%s): %s" % (len(self.test_candidates), self.test_candidates))
            print("SER Test succeeded for memories (%s): %s" % (len(self.mem_verified), self.mem_verified))
            print("SER Test skipped memories (%s): %s" % (len(skip_list), skip_list))
        else:
            print("SER Test memories candidates (%s)" % (len(self.test_candidates)))
            print("SER Test succeeded for memories (%s)" % (len(self.mem_verified)))
        print("SER Test failed for memories (%s): %s" % (len(self.mem_failed), self.mem_failed))
        print("SER Test timed out for memories (%s): %s" % (len(self.mem_verification_pending), self.mem_verification_pending))
        print("SER Test is not supported for memories (%s): %s" % (len(self.mem_ser_unsupported), self.mem_ser_unsupported))

        if VERBOSE:
            print("--- found {} memory location(s) reported misaligned correction events ---".format(len(self.miss_counts)))
            for address, count in self.miss_counts.items():
                print("--- unknown address {} was triggered {} times".format(hex(address), count))

        return len(self.mem_failed) + len(self.mem_verification_pending)

    def enable_memory_scan(self, cmd, interval_usec, rate):
        '''
        @summary: Enable Broadcom memory scan
        @param cmd: Broadcom to use
        @param interval_usec: memory scanner interval i usec
        @param rate: rate (number of entries) per interval
        '''
        for x in range(3):
            stdout, stderr = run_cmd(["bcmcmd", cmd + " interval=" + str(interval_usec) + " rate=" + str(rate)])
            lines = stdout.decode("utf-8").split("\n")
            if lines[1].find('mSCAN: Started on unit 0') > -1:
                return

        raise ValueError('Failed to start memory scanner: %s' % cmd)

    def enable_mem_scan(self, interval_usec, rate):
        '''
        @summary: Wrapper around enable_memory_scan
        @param interval_usec: memory scanner interval i usec
        @param rate: rate (number of entries) per interval
        '''
        self.enable_memory_scan('memscan', interval_usec, rate)

    def enable_sram_scan(self, interval_usec, rate):
        '''
        @summary: Enable Broadcom sram scan
        @param interval_usec: memory scanner interval i usec
        @param rate: rate (number of entries) per interval
        '''
        self.enable_memory_scan('sramscan', interval_usec, rate)

    def verify_ser(self, entry, log):
        '''
        @summary: verify SER log entry
        @param entry: indext of the memory table where SER was injected
        @param log: syslog log line

        @return: memory table name
        @return: Flag if SER injection entry matches log line entry
        '''
        m = re.search("^.*addr:(.*) port.*index: (\d+)", log)
        if not m:
            print("--- cannot parse log {}".format(log))
            return None, None

        address = int(m.group(1), 16)
        mem_entry = int(m.group(2))

        memory = self.bcmMemory.get_memory_by_address()
        if address in memory:
            return memory[address], entry == mem_entry

        if address in self.miss_counts:
            self.miss_counts[address] = self.miss_counts[address] + 1
        else:
            self.miss_counts[address] = 1

        if VERBOSE:
            print("--- addr {} ({}) not found in dict: {} time(s)".format(hex(address), address, self.miss_counts[address]))

        return None, None

    def inject_ser(self, mem, index = 0, tag = None):
        '''
        @summary: Inject SER error suing Broadcom ser inject command
        @param mem: name of the memory table to inject SER into
        @param index: index of the entry to inject SER into
        '''
        if VERBOSE:
            print('--- injecting error at {} index {} tag {}'.format(mem, index, tag))
        return run_cmd(["bcmcmd",  "ser inject memory=" + mem + " index=" + str(index)])

    def verify_and_update_test_result(self, entry, line):
        '''
        @summary: Verify log line and update test result
        @param entry: index of the entry to inject SER into
        @param log: syslog log line
        '''
        mem, entry_found = self.verify_ser(entry, line)
        if mem is not None:
            # memory could be aliased, mark all aliased memory as passed/failed
            for m in mem:
                if entry_found:
                    if m in self.mem_verified:
                        self.mem_verified[m] += 1
                    else:
                        print("Successfully tested memory %s" % m)
                        self.mem_verified.update({m : 1})
                else:
                    if m in self.mem_failed:
                        self.mem_failed[m] += 1
                    else:
                        print("Failed verification for memory %s, syslog '%s'" % (m, line))
                        self.mem_failed.update({m : 1})

                if m in self.mem_verification_pending:
                    self.mem_verification_pending.remove(m)
                else:
                    print("Memory %s appeared more than once" % m)
        elif VERBOSE:
            print("Memory corresponding to the following syslog was not found! Syslog: '%s'" % line)

    def run_test(self, memory, entry = 0):
        '''
        @summary: Run SER injection test on cached memory tables
        @param memory: Cached memory tables
        @param entry: index of the entry to inject SER into
        '''
        with open('/var/log/syslog') as syslog_file:
            # mark current location of the syslog file
            syslog_file.seek(0, 2)
            cnt = len(memory)
            idx = 0
            for mem in memory:
                idx = idx + 1
                tag = '{} / {}'.format(idx, cnt)
                self.mem_verification_pending.remove(mem)
                stdout, stderr = self.inject_ser(mem, tag = tag)
                if stdout.find('SER correction for it is not currently supported') > -1:
                    print("memory %s does not support ser" % mem)
                    self.mem_ser_unsupported.append(mem)
                else:
                    self.mem_verification_pending.append(mem)
                time.sleep(self.ser_injection_interval_sec)

            wait_start_time = time.time()
            while len(self.mem_verification_pending) > 0:
                line = syslog_file.readline()
                if line:
                    if line.find('SER_CORRECTION') > -1:
                        self.verify_and_update_test_result(entry, line)
                else:
                    time.sleep(self.syslog_poll_interval_sec)
                    current_time = time.time()
                    elapsed_time = current_time - wait_start_time
                    if elapsed_time > self.test_time_sec:
                        print("timed out waiting for ser correction...")
                        break

def main():
    global VERBOSE

    parser = argparse.ArgumentParser(description='Completeness level')
    parser.add_argument('-c', '--completeness', help='Completeness level: debug, basic, confident, thorough, diagnose',
                        type=str, required=False, default='basic',
                        choices=['debug', 'basic', 'confident', 'thorough', 'diagnose'])
    parser.add_argument('-v', '--verbose', help='Set verbose output', action='store_true', required=False, default=False)
    args = parser.parse_args()

    VERBOSE = args.verbose

    start_time = time.time()
    serTest = SerTest()
    rc = serTest.test_memory(args.completeness)
    print("--- %s seconds, rc %d ---" % ((time.time() - start_time), rc))
    sys.exit(rc)

if __name__ == "__main__":
    main()
