#!/usr/bin/env python

import argparse
import json
import random
import re
import subprocess
import sys
import time
from collections import defaultdict
import logging

log_filename = "/tmp/ser_injector.log"

# Global parameter for memory scanners
MEMORY_SCAN_INTERVAL_USEC = int(3e5)
MEMORY_SCAN_ENTRIES = 16384
SRAM_SCAN_INTERVAL_USEC = int(3e5)
SRAM_SCAN_ENTRIES = 16384

DEFAULT_SER_INJECTION_INTERVAL_SEC = 0.1
DEFAULT_SYSLOG_POLLING_INTERVAL_SEC = 0.1

# Stop trying if stall has been detected for so many consecutive iterations
# Combined with the test duration below. If we don't make progress for so
# long, then we stop waiting.
DEFAULT_STALL_INDICATION = 15
DEFAULT_SER_TEST_TIME_SEC = 60
DEFAULT_BATCH_SIZE = 10
DEFAULT_THOROUGH_BATCH_SIZE = 20
DEFAULT_INJECTION_SLOW_SEC = 5

# Print verbose output for debugging
VERBOSE = False

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
    'td2': {
        'timeout': [
            'L3_DEFIP_ALPM_IPV4.ipipe0', 'L3_ENTRY_IPV6_MULTICAST.ipipe0', 'L3_ENTRY_IPV6_UNICAST.ipipe0',
            'FP_GM_FIELDS.ipipe0', 'L3_ENTRY_IPV4_MULTICAST.ipipe0', 'L3_DEFIP_ALPM_IPV6_64.ipipe0',
            'L3_DEFIP_ALPM_IPV6_128.ipipe0', 'FP_GLOBAL_MASK_TCAM.ipipe0', 'MODPORT_MAP_MIRROR.ipipe0',
            'EGR_IP_TUNNEL_MPLS.epipe0',
        ],
        'timeout_basic': [
            'EGR_IP_TUNNEL_IPV6.epipe0', 'EGR_DVP_ATTRIBUTE_1.epipe0', 'EGR_MPLS_VC_AND_SWAP_LABEL_TABLE.epipe0',
            'L3_TUNNEL_DATA_ONLY.ipipe0',
        ],
        'slow_injection': [
        ],
        'unsupported': [
        ]
    },
    'td3': {
        'timeout': [
            'VLAN_SUBNET.ipipe0', 'EGR_ZONE_3_EDITOR_CONTROL_TCAM.epipe0', 'L3_ENTRY_QUAD.ipipe0',
            'THDI_PORT_SP_CONFIG_PIPE1.mmu_xpe0', 'RH_HGT_FLOWSET_PIPE1.ipipe0', 'RH_ECMP_FLOWSET.ipipe0',
            'VLAN_XLATE_2_DOUBLE.ipipe0', 'IFP_TCAM_PIPE1.ipipe0', 'MMU_THDU_OFFSET_QUEUE_PIPE0.mmu_xpe0',
            'CPU_COS_MAP.ipipe0', 'L3_ENTRY_DOUBLE.ipipe0', 'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE1.ipipe0',
            'EGR_ZONE_1_EDITOR_CONTROL_TCAM.epipe0', 'RH_ECMP_FLOWSET_PIPE0.ipipe0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE0.ipipe0', 'MMU_WRED_DROP_CURVE_PROFILE_0.mmu_xpe0',
            'MMU_THDU_CONFIG_QUEUE_PIPE0.mmu_xpe0', 'MMU_THDM_DB_PORTSP_CONFIG_PIPE1.mmu_xpe0',
            'SRC_COMPRESSION_PIPE0.ipipe0', 'RH_LAG_FLOWSET.ipipe0', 'DST_COMPRESSION.ipipe0',
            'IP_PARSER2_MICE_TCAM_0.ipipe0', 'EGR_VLAN_XLATE_1_SINGLE.epipe0', 'IP_PARSER1_MICE_TCAM_0.ipipe0',
            'L3_DEFIP_ALPM_RAW.ipipe0', 'MPLS_ENTRY_DOUBLE.ipipe0', 'ING_VP_VLAN_MEMBERSHIP.ipipe0',
            'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE1.mmu_xpe0', 'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE0.ipipe0',
            'MMU_WRED_DROP_CURVE_PROFILE_4.mmu_xpe0', 'MMU_THDU_RESUME_PORT_PIPE0.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_4_B.mmu_xpe0', 'EGR_QOS_CTRL_TCAM.epipe0',
            'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE1.mmu_xpe0', 'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE0.mmu_xpe0',
            'MY_STATION_TCAM.ipipe0', 'PKT_FLOW_SELECT_TCAM_2.ipipe0', 'SUBPORT_ID_TO_SGPP_MAP.ipipe0',
            'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE0.mmu_xpe0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE1.mmu_xpe0',
            'ING_SNAT.ipipe0', 'EGR_ZONE_4_EDITOR_CONTROL_TCAM.epipe0', 'IFP_POLICY_TABLE_WIDE_PIPE0.ipipe0',
            'MMU_WRED_DROP_CURVE_PROFILE_2.mmu_xpe0', 'L2_USER_ENTRY.ipipe0', 'MY_STATION_TCAM_2.ipipe0',
            'MMU_THDU_CONFIG_PORT_PIPE1.mmu_xpe0', 'EGR_ZONE_2_EDITOR_CONTROL_TCAM.epipe0',
            'L3_ENTRY_ONLY_SINGLE.ipipe0', 'EGR_VLAN_XLATE_2_SINGLE.epipe0', 'PHB_SELECT_TCAM.ipipe0',
            'SRC_COMPRESSION.ipipe0', 'EGR_PKT_FLOW_SELECT_TCAM.epipe0', 'MODPORT_MAP_MIRROR.ipipe0',
            'MMU_THDU_CONFIG_QGROUP_PIPE0.mmu_xpe0', 'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE0.mmu_xpe0',
            'MMU_THDU_CONFIG_PORT_PIPE0.mmu_xpe0', 'IFP_LOGICAL_TABLE_SELECT.ipipe0',
            'PKT_FLOW_SELECT_TCAM_1.ipipe0', 'IFP_TCAM.ipipe0', 'RH_LAG_FLOWSET_PIPE0.ipipe0',
            'ING_DNAT_ADDRESS_TYPE.ipipe0', 'SRC_COMPRESSION_PIPE1.ipipe0', 'MODPORT_MAP_SUBPORT_MIRROR.ipipe0',
            'MMU_THDU_CONFIG_QUEUE_PIPE1.mmu_xpe0', 'PKT_FLOW_SELECT_TCAM_0.ipipe0',
            'IFP_POLICY_TABLE_WIDE_PIPE1.ipipe0', 'MMU_THDU_CONFIG_QUEUE1_PIPE1.mmu_xpe0',
            'DST_COMPRESSION_PIPE0.ipipe0', 'L3_DEFIP_PAIR_128.ipipe0', 'EGR_IP_TUNNEL_MPLS.epipe0',
            'L3_DEFIP.ipipe0', 'L2_ENTRY_ONLY_SINGLE.ipipe0', 'MMU_THDU_OFFSET_QGROUP_PIPE0.mmu_xpe0',
            'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE1.mmu_xpe0', 'MMU_WRED_DROP_CURVE_PROFILE_8.mmu_xpe0',
            'DST_COMPRESSION_PIPE1.ipipe0', 'MMU_WRED_DROP_CURVE_PROFILE_6.mmu_xpe0',
            'IP_PARSER1_MICE_TCAM_1.ipipe0', 'MMU_THDU_RESUME_PORT_PIPE1.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_5.mmu_xpe0', 'MMU_WRED_DROP_CURVE_PROFILE_7.mmu_xpe0',
            'EGR_VP_VLAN_MEMBERSHIP.epipe0', 'L3_ENTRY_ONLY_DOUBLE.ipipe0', 'FLEX_RTAG7_HASH_TCAM.ipipe0',
            'MMU_THDU_OFFSET_QUEUE_PIPE1.mmu_xpe0', 'EGR_VLAN_XLATE_1_DOUBLE.epipe0',
            'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE0.mmu_xpe0', 'VLAN_XLATE_1_DOUBLE.ipipe0',
            'EGR_VLAN_XLATE_2_DOUBLE.epipe0', 'IFP_LOGICAL_TABLE_SELECT_PIPE1.ipipe0',
            'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE1.mmu_xpe0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE0.mmu_xpe0',
            'MMU_THDU_OFFSET_QGROUP_PIPE1.mmu_xpe0', 'THDI_PORT_SP_CONFIG_PIPE0.mmu_xpe0',
            'RH_LAG_FLOWSET_PIPE1.ipipe0', 'MPLS_ENTRY_SINGLE.ipipe0',
            'EGR_FIELD_EXTRACTION_PROFILE_2_TCAM.epipe0', 'EGR_IP_TUNNEL_MPLS_DOUBLE_WIDE.epipe0',
            'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE0.mmu_sed0', 'MMU_THDM_DB_QUEUE_CONFIG_PIPE0.mmu_xpe0',
            'MMU_MTRO_CONFIG_L0_MEM_PIPE0.mmu_sed0', 'VLAN_XLATE_1_SINGLE.ipipe0',
            'MMU_THDM_DB_PORTSP_CONFIG_PIPE0.mmu_xpe0', 'IFP_TCAM_PIPE0.ipipe0', 'RH_HGT_FLOWSET.ipipe0',
            'TCB_THRESHOLD_PROFILE_MAP_XPE0.mmu_xpe0', 'EXACT_MATCH_LOGICAL_TABLE_SELECT.ipipe0',
            'VLAN_XLATE_2_SINGLE.ipipe0', 'RH_ECMP_FLOWSET_PIPE1.ipipe0',
            'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC0.mmu_xpe0', 'EGR_FIELD_EXTRACTION_PROFILE_1_TCAM.epipe0',
            'L2_ENTRY.ipipe0', 'MMU_THDU_CONFIG_QGROUP_PIPE1.mmu_xpe0', 'L2_ENTRY_SINGLE.ipipe0',
            'RH_HGT_FLOWSET_PIPE0.ipipe0', 'MMU_WRED_DROP_CURVE_PROFILE_1.mmu_xpe0',
            'MMU_THDM_DB_QUEUE_CONFIG_PIPE1.mmu_xpe0', 'IP_PARSER2_MICE_TCAM_1.ipipe0',
            'MMU_THDM_DB_QUEUE_CONFIG_A_PIPE1.mmu_xpe0', 'L3_ENTRY_SINGLE.ipipe0', 'IFP_POLICY_TABLE_WIDE.ipipe0',
            'L3_TUNNEL.ipipe0', 'EGR_IP_TUNNEL_IPV6.epipe0', 'EGR_VLAN.epipe0',
            'EGR_ZONE_1_DOT1P_MAPPING_TABLE_2.epipe0', 'EGR_ZONE_1_DOT1P_MAPPING_TABLE_3.epipe0',
            'EGR_ZONE_3_DOT1P_MAPPING_TABLE_4.epipe0', 'EGR_VLAN_CONTROL_3.epipe0',
            'EGR_ZONE_3_DOT1P_MAPPING_TABLE_2.epipe0', 'EGR_ZONE_1_DOT1P_MAPPING_TABLE_1.epipe0',
            'EGR_ZONE_1_DOT1P_MAPPING_TABLE_4.eABLE_4.epipe0', 'EGR_ZONE_3_DOT1P_MAPPING_TABLE_1.epipe0',
            'EGR_FLEX_CONTAINER_UPDATE_PROFILE_1.epipe0', 'EGR_ZONE_3_DOT1P_MAPPING_TABLE_3.epipe0',
            'EGR_VLAN_CONTROL_2.epipe0', 'EGR_ZONE_1_DOT1P_MAPPING_TABLE_4.epipe0',
            'MMU_MTRO_CONFIG_L1_MEM.mmu_sed0',
            'MMU_MTRO_CONFIG_L1_MEM_A.mmu_sed0', 'MMU_MTRO_CONFIG_L1_MEM_B.mmu_sed0',
            'MMU_MTRO_CONFIG_L1_MEM_A_PIPE0.mmu_sed0', 'MMU_MTRO_CONFIG_L1_MEM_B_PIPE0.mmu_sed0',
            'MMU_MTRO_CONFIG_L1_MEM_PIPE0.mmu_sed0', 'MMU_MTRO_CONFIG_L1_MEM_PIPE1.mmu_sed0',
            'MMU_MTRO_CONFIG_L1_MEM_PIPE2.mmu_sed0', 'MMU_MTRO_CONFIG_L1_MEM_PIPE3.mmu_sed0',
        ],
        'timeout_basic': [
            'EGR_ZONE_0_EDITOR_CONTROL_TCAM.epipe0', 'DLB_ECMP_FLOWSET_MEMBER.ipipe0',
            'DLB_ECMP_FLOWSET_MEMBER_PIPE0.ipipe0', 'INTFO_TC2PRI_MAPPING.mmu_glb0',
            'EGR_FLEX_CONTAINER_UPDATE_PROFILE_0.epipe0',
        ],
        'slow_injection': [
            'MMU_WRED_DROP_CURVE_PROFILE_3.mmu_xpe0', 'IFP_STORM_CONTROL_METERS.ipipe0', 'TDM_CALENDAR0_PIPE0.mmu_sc0',
            'EFP_METER_TABLE_PIPE1.epipe0', 'MMU_MTRO_EGRMETERINGCONFIG_MEM_B_PIPE1.mmu_sed0',
            'IFP_METER_TABLE_PIPE1.ipipe0', 'MMU_WRED_CONFIG_PIPE0.mmu_xpe0', 'MMU_WRED_CONFIG_PIPE1.mmu_xpe0',
            'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE1.mmu_sed0', 'TDM_CALENDAR0_PIPE1.mmu_sc0', 'IFP_METER_TABLE.ipipe0',
            'L3_ENTRY_ONLY_QUAD.ipipe0', 'IFP_METER_TABLE_PIPE0.ipipe0', 'EFP_METER_TABLE.epipe0',
            'DLB_HGT_LAG_QUANTIZE_CONTROL.ipipe0', 'MMU_MTRO_CONFIG_L0_MEM_PIPE1.mmu_sed0',
            'EFP_METER_TABLE_PIPE0.epipe0', 'DLB_ECMP_QUANTIZE_CONTROL.ipipe0',
        ],
        'unsupported': [
            'EGR_VLAN_XLATE_2_ECC.epipe0', 'IP_PARSER1_HME_STAGE_TCAM_NARROW_ONLY_0.ipipe0',
            'IP_PARSER0_HME_STAGE_TCAM_NARROW_ONLY_0.ipipe0', 'IP_PARSER1_HME_STAGE_TCAM_NARROW_ONLY_4.ipipe0',
            'IP_PARSER2_HME_STAGE_TCAM_NARROW_ONLY_0.ipipe0', 'L3_DEFIP_ALPM_HIT_ONLY.ipipe0',
            'L3_DEFIP_PAIR_128_HIT_ONLY.ipipe0', 'IP_PARSER1_HME_STAGE_TCAM_NARROW_ONLY_3.ipipe0',
            'IP_PARSER2_HME_STAGE_TCAM_NARROW_ONLY_1.ipipe0', 'L3_DEFIP_HIT_ONLY.ipipe0', 'L2_ENTRY_ECC.ipipe0',
            'IP_PARSER1_HME_STAGE_TCAM_NARROW_ONLY_1.ipipe0', 'EGR_VLAN_XLATE_1_ECC.epipe0',
            'IP_PARSER2_HME_STAGE_TCAM_NARROW_ONLY_4.ipipe0', 'L3_ENTRY_ECC.ipipe0', 'VLAN_XLATE_1_ECC.ipipe0',
            'VLAN_XLATE_2_ECC.ipipe0',
        ]
    },
    'th': {
        'timeout': [
            'EGR_IP_TUNNEL_MPLS.epipe0', 'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE1.mmu_xpe0',
            'MMU_THDU_RESUME_PORT_PIPE3.mmu_xpe0', 'MMU_THDU_CONFIG_QUEUE_PIPE2.mmu_xpe0', 'MPLS_ENTRY_DOUBLE.ipipe0',
            'MMU_THDU_CONFIG_QUEUE_PIPE3.mmu_xpe0', 'MMU_WRED_DROP_CURVE_PROFILE_8.mmu_xpe0',
            'IFP_TCAM_WIDE_PIPE2.ipipe0', 'FP_GM_FIELDS.ipipe0', 'FP_STORM_CONTROL_METERS.ipipe0',
            'MMU_THDU_OFFSET_QUEUE_PIPE1.mmu_xpe0', 'MMU_WRED_DROP_CURVE_PROFILE_2.mmu_xpe0',
            'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE1.mmu_xpe0', 'THDI_PORT_SP_CONFIG_PIPE1.mmu_xpe0',
            'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE1.mmu_xpe0', 'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE3.mmu_xpe0',
            'MMU_THDU_CONFIG_QGROUP_PIPE0.mmu_xpe0', 'MMU_THDU_CONFIG_QGROUP_PIPE3.mmu_xpe0',
            'EGR_IP_TUNNEL_IPV6.epipe0', 'MODPORT_MAP_MIRROR.ipipe0', 'MMU_THDU_OFFSET_QGROUP_PIPE1.mmu_xpe0',
            'THDI_PORT_SP_CONFIG_PIPE0.mmu_xpe0', 'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE3.mmu_xpe0',
            'MMU_THDM_DB_PORTSP_CONFIG_PIPE1.mmu_xpe0', 'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE0.mmu_sc0',
            'L3_DEFIP_ALPM_IPV6_128.ipipe0', 'IFP_TCAM_WIDE_PIPE3.ipipe0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE0.mmu_xpe0',
            'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE2.mmu_sc0', 'MMU_THDM_DB_QUEUE_CONFIG_PIPE2.mmu_xpe0',
            'MMU_THDM_DB_PORTSP_CONFIG_PIPE2.mmu_xpe0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE2.mmu_xpe0',
            'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE2.mmu_xpe0', 'VLAN_XLATE.ipipe0',
            'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE3.mmu_xpe0', 'VLAN_MAC.ipipe0', 'MMU_THDU_CONFIG_QUEUE_PIPE1.mmu_xpe0',
            'MMU_THDU_RESUME_PORT_PIPE2.mmu_xpe0', 'MMU_THDM_DB_QUEUE_CONFIG_PIPE1.mmu_xpe0',
            'L3_DEFIP_ALPM_IPV4.ipipe0', 'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE3.mmu_sc0',
            'MMU_THDM_DB_PORTSP_CONFIG_PIPE0.mmu_xpe0', 'IFP_TCAM_WIDE_PIPE1.ipipe0',
            'MMU_THDM_DB_PORTSP_CONFIG_PIPE3.mmu_xpe0', 'MMU_WRED_DROP_CURVE_PROFILE_6.mmu_xpe0',
            'MMU_THDU_CONFIG_QGROUP_PIPE2.mmu_xpe0', 'FP_GLOBAL_MASK_TCAM.ipipe0',
            'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE0.mmu_xpe0', 'L3_ENTRY_IPV4_MULTICAST.ipipe0',
            'THDI_PORT_SP_CONFIG_PIPE3.mmu_xpe0', 'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE3.mmu_xpe0',
            'MMU_THDU_OFFSET_QGROUP_PIPE2.mmu_xpe0', 'MMU_WRED_DROP_CURVE_PROFILE_4.mmu_xpe0',
            'MMU_THDU_OFFSET_QGROUP_PIPE3.mmu_xpe0', 'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE0.mmu_xpe0',
            'MMU_THDU_Q_TO_QGRP_MAP_PIPE1.mmu_xpe0', 'MMU_THDU_RESUME_PORT_PIPE0.mmu_xpe0',
            'IFP_TCAM_WIDE_PIPE0.ipipe0', 'L3_ENTRY_IPV6_MULTICAST.ipipe0', 'MMU_THDU_OFFSET_QUEUE_PIPE2.mmu_xpe0',
            'IFP_TCAM.ipipe0', 'THDI_PORT_SP_CONFIG_PIPE2.mmu_xpe0', 'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE0.mmu_xpe0',
            'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE2.mmu_xpe0', 'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE2.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_3.mmu_xpe0', 'MMU_THDU_OFFSET_QGROUP_PIPE0.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_1.mmu_xpe0', 'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE1.mmu_sc0',
            'MMU_THDU_RESUME_PORT_PIPE1.mmu_xpe0', 'EGR_VLAN_XLATE.epipe0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE3.mmu_xpe0',
            'L3_ENTRY_IPV4_UNICAST.ipipe0', 'MMU_WRED_DROP_CURVE_PROFILE_7.mmu_xpe0',
            'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC0.mmu_xpe0', 'MMU_THDU_OFFSET_QUEUE_PIPE3.mmu_xpe0',
            'MMU_THDU_CONFIG_PORT_PIPE2.mmu_xpe0', 'L2_ENTRY.ipipe0', 'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE2.mmu_xpe0',
            'MMU_THDU_CONFIG_PORT_PIPE1.mmu_xpe0', 'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE0.mmu_xpe0',
            'MMU_THDU_CONFIG_PORT_PIPE3.mmu_xpe0', 'MMU_WRED_DROP_CURVE_PROFILE_0.mmu_xpe0',
            'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE1.mmu_xpe0', 'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC1.mmu_xpe0',
            'MMU_THDM_DB_QUEUE_CONFIG_PIPE3.mmu_xpe0', 'MMU_WRED_DROP_CURVE_PROFILE_5.mmu_xpe0',
            'L3_DEFIP_ALPM_IPV6_64.ipipe0', 'MMU_THDM_DB_QUEUE_CONFIG_PIPE0.mmu_xpe0',
            'MMU_THDU_CONFIG_QGROUP_PIPE1.mmu_xpe0', 'MMU_THDU_OFFSET_QUEUE_PIPE0.mmu_xpe0',
            'L3_ENTRY_IPV6_UNICAST.ipipe0',
        ],
        'timeout_basic': [
            'IFP_POLICY_TABLE_PIPE0.ipipe0', 'IFP_POLICY_TABLE.ipipe0', 'MMU_THDU_CONFIG_QUEUE_PIPE0.mmu_xpe0',
            'EXACT_MATCH_4_PIPE1.ipipe0', 'EXACT_MATCH_4_PIPE2.ipipe0', 'EXACT_MATCH_2_PIPE1.ipipe0',
            'EXACT_MATCH_4_PIPE0.ipipe0', 'EXACT_MATCH_2_PIPE2.ipipe0', 'EXACT_MATCH_2_PIPE0.ipipe0',
            'EXACT_MATCH_4_PIPE3.ipipe0', 'EXACT_MATCH_4.ipipe0', 'EXACT_MATCH_2_PIPE3.ipipe0',
            'EXACT_MATCH_2.ipipe0', 'ING_FLEX_CTR_OFFSET_TABLE_11.ipipe0', 'PORT_LAG_FAILOVER_SET.ipipe0',
            'VFP_POLICY_TABLE_PIPE2.ipipe0', 'Q_SCHED_L1_WEIGHT_MEM_PIPE2.mmu_sc0', 'SYSTEM_CONFIG_TABLE.ipipe0',
            'RTAG7_PORT_BASED_HASH.ipipe0', 'MMU_REPL_LIST_TBL_PIPE2.mmu_sc0', 'EGR_GPP_ATTRIBUTES.epipe0',
            'EGRESS_MASK.ipipe0', 'MMU_THDU_CONFIG_QUEUE_PIPE0.mmu_xpe0', 'EMIRROR_CONTROL2.ipipe0',
            'VLAN_MPLS.ipipe0', 'ING_DVP_TABLE.ipipe0', 'EXACT_MATCH_QOS_ACTIONS_PROFILE.ipipe0',
            'MMU_REPL_GROUP_INFO_TBL_PIPE3.mmu_sc0', 'MMU_REPL_LIST_TBL_PIPE1.mmu_sc0', 'VFI_1.ipipe0',
            'MMU_THDU_CONFIG_PORT_PIPE0.mmu_xpe0', 'EFP_POLICY_TABLE_PIPE0.epipe0', 'EFP_POLICY_TABLE.epipe0',
            'IFP_STORM_CONTROL_METERS.ipipe0',
        ],
        'slow_injection': [
        ],
        'unsupported': [
        ]
    },
    'th2': {
        'timeout': [
            'TCB_THRESHOLD_PROFILE_MAP_XPE3.mmu_xpe0', 'MMU_THDU_RESUME_PORT_PIPE0.mmu_xpe0',
            'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE3.mmu_xpe0', 'VLAN_MAC.ipipe0', 'EGR_VP_VLAN_MEMBERSHIP.epipe0',
            'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE1.mmu_xpe0', 'MMU_THDM_DB_PORTSP_CONFIG_PIPE3.mmu_xpe0',
            'MMU_THDU_RESUME_PORT_PIPE3.mmu_xpe0', 'MMU_THDU_CONFIG_QUEUE_PIPE2.mmu_xpe0',
            'TCB_THRESHOLD_PROFILE_MAP_XPE1.mmu_xpe0', 'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE2.mmu_sed0',
            'MMU_THDU_OFFSET_QGROUP_PIPE2.mmu_xpe0', 'MMU_THDM_DB_QUEUE_CONFIG_PIPE0.mmu_xpe0',
            'MMU_THDU_CONFIG_QGROUP_PIPE0.mmu_xpe0', 'MMU_MTRO_CONFIG_L0_MEM_PIPE2.mmu_sed0',
            'L3_ENTRY_IPV6_MULTICAST.ipipe0', 'MMU_WRED_DROP_CURVE_PROFILE_0.mmu_xpe0',
            'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE0.mmu_sed0', 'VLAN_XLATE.ipipe0',
            'MMU_THDU_RESUME_PORT_PIPE1.mmu_xpe0', 'L3_ENTRY_IPV4_MULTICAST.ipipe0',
            'MMU_THDU_OFFSET_QUEUE_PIPE0.mmu_xpe0', 'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE0.mmu_xpe0',
            'INTFO_TC2PRI_MAPPING.mmu_glb0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE1.mmu_xpe0',
            'MMU_MTRO_CONFIG_L0_MEM_PIPE3.mmu_sed0', 'MMU_THDU_OFFSET_QGROUP_PIPE0.mmu_xpe0',
            'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC1.mmu_xpe0', 'MMU_THDU_CONFIG_QUEUE_PIPE0.mmu_xpe0',
            'IFP_TCAM_WIDE_PIPE0.ipipe0', 'L3_DEFIP_ALPM_IPV6_64.ipipe0', 'MMU_WRED_DROP_CURVE_PROFILE_6.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_5.mmu_xpe0', 'IFP_TCAM_WIDE_PIPE2.ipipe0',
            'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE3.mmu_sed0', 'MMU_THDU_CONFIG_QGROUP_PIPE1.mmu_xpe0',
            'THDI_PORT_SP_CONFIG_PIPE3.mmu_xpe0', 'MMU_THDU_RESUME_PORT_PIPE2.mmu_xpe0',
            'MMU_THDM_DB_QUEUE_CONFIG_PIPE1.mmu_xpe0', 'MMU_THDM_MCQE_PORTSP_CONFIG_C_PIPE3.mmu_xpe0',
            'L3_TUNNEL.ipipe0', 'MPLS_ENTRY_DOUBLE.ipipe0', 'ING_DNAT_ADDRESS_TYPE.ipipe0',
            'THDI_PORT_SP_CONFIG_PIPE0.mmu_xpe0', 'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE2.mmu_xpe0',
            'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE3.mmu_xpe0', 'L3_DEFIP_ALPM_IPV4.ipipe0',
            'MMU_THDM_DB_PORTSP_CONFIG_PIPE0.mmu_xpe0', 'MMU_MTRO_CONFIG_L0_MEM_PIPE0.mmu_sed0',
            'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE3.mmu_xpe0', 'MMU_THDM_DB_PORTSP_CONFIG_PIPE2.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_3.mmu_xpe0', 'IFP_TCAM_WIDE_PIPE1.ipipe0',
            'MMU_THDU_CONFIG_QGROUP_PIPE2.mmu_xpe0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE3.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_2.mmu_xpe0', 'MMU_THDU_CONFIG_PORT_PIPE1.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_7.mmu_xpe0', 'L3_ENTRY_IPV4_UNICAST.ipipe0', 'IFP_TCAM_WIDE_PIPE3.ipipe0',
            'MMU_THDU_CONFIG_QGROUP_PIPE3.mmu_xpe0', 'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE2.mmu_xpe0',
            'MMU_MTRO_EGRMETERINGCONFIG_MEM_PIPE1.mmu_sed0', 'MMU_REPL_GROUP_INITIAL_COPY_COUNT_SC0.mmu_xpe0',
            'MMU_THDU_CONFIG_QUEUE_PIPE3.mmu_xpe0', 'THDI_PORT_SP_CONFIG_PIPE2.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_8.mmu_xpe0', 'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE2.mmu_xpe0',
            'TCB_THRESHOLD_PROFILE_MAP_XPE0.mmu_xpe0', 'MMU_THDU_CONFIG_PORT_PIPE0.mmu_xpe0',
            'MMU_THDU_OFFSET_QUEUE_PIPE1.mmu_xpe0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE2.mmu_xpe0',
            'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE1.mmu_xpe0', 'L3_DEFIP_ALPM_IPV6_128.ipipe0',
            'MMU_THDM_DB_QUEUE_CONFIG_PIPE3.mmu_xpe0', 'MODPORT_MAP_MIRROR.ipipe0', 'IFP_TCAM.ipipe0',
            'MMU_THDM_DB_PORTSP_CONFIG_PIPE1.mmu_xpe0', 'EGR_VLAN_XLATE.epipe0', 'FP_GM_FIELDS.ipipe0',
            'MMU_THDU_CONFIG_QUEUE_PIPE1.mmu_xpe0', 'MMU_MTRO_CONFIG_L0_MEM_PIPE1.mmu_sed0',
            'THDI_PORT_SP_CONFIG_PIPE1.mmu_xpe0', 'MMU_THDU_OFFSET_QGROUP_PIPE1.mmu_xpe0',
            'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE0.mmu_xpe0', 'MMU_THDM_MCQE_PORTSP_CONFIG_PIPE0.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_4.mmu_xpe0', 'TCB_THRESHOLD_PROFILE_MAP_XPE2.mmu_xpe0',
            'FP_STORM_CONTROL_METERS.ipipe0', 'L2_ENTRY.ipipe0', 'EGR_IP_TUNNEL_IPV6.epipe0',
            'MMU_THDU_OFFSET_QUEUE_PIPE3.mmu_xpe0', 'MMU_THDU_OFFSET_QUEUE_PIPE2.mmu_xpe0',
            'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE2.mmu_xpe0', 'MMU_THDU_CONFIG_PORT_PIPE2.mmu_xpe0',
            'L3_ENTRY_IPV6_UNICAST.ipipe0', 'MMU_THDU_Q_TO_QGRP_MAP_PIPE0.mmu_xpe0',
            'MMU_WRED_DROP_CURVE_PROFILE_1.mmu_xpe0', 'MMU_THDM_DB_QUEUE_CONFIG_PIPE2.mmu_xpe0',
            'EGR_IP_TUNNEL_MPLS.epipe0', 'MMU_THDM_MCQE_QUEUE_CONFIG_PIPE3.mmu_xpe0',
            'MMU_THDM_DB_QUEUE_OFFSET_0_PIPE1.mmu_xpe0', 'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE1.mmu_xpe0',
            'MMU_THDM_MCQE_QUEUE_OFFSET_PIPE0.mmu_xpe0', 'ING_SNAT.ipipe0',
            'MMU_THDM_MCQE_QUEUE_OFFSET_B_PIPE1.mmu_xpe0', 'MMU_THDU_OFFSET_QGROUP_PIPE3.mmu_xpe0',
            'ING_VP_VLAN_MEMBERSHIP.ipipe0', 'MMU_THDU_CONFIG_PORT_PIPE3.mmu_xpe0', 'FP_GLOBAL_MASK_TCAM.ipipe0',
            'IS_TDM_CALENDAR0.ipipe0', 'IS_TDM_CALENDAR1.ipipe0', 'IS_TDM_CALENDAR0_PIPE0.ipipe0',
            'IS_TDM_CALENDAR0_PIPE1.ipipe0', 'IS_TDM_CALENDAR0_PIPE2.ipipe0', 'IS_TDM_CALENDAR0_PIPE3.ipipe0',
            'IS_TDM_CALENDAR1_PIPE0.ipipe0', 'IS_TDM_CALENDAR1_PIPE1.ipipe0', 'IS_TDM_CALENDAR1_PIPE2.ipipe0',
            'IS_TDM_CALENDAR1_PIPE3.ipipe0', 'MMU_MTRO_CONFIG_L1_MEM.mmu_sed0',
            'MMU_MTRO_CONFIG_L1_MEM_A.mmu_sed0', 'MMU_MTRO_CONFIG_L1_MEM_B.mmu_sed0',
            'MMU_MTRO_CONFIG_L1_MEM_A_PIPE0.mmu_sed0', 'MMU_MTRO_CONFIG_L1_MEM_B_PIPE0.mmu_sed0',
            'MMU_MTRO_CONFIG_L1_MEM_PIPE0.mmu_sed0', 'MMU_MTRO_CONFIG_L1_MEM_PIPE1.mmu_sed0',
            'MMU_MTRO_CONFIG_L1_MEM_PIPE2.mmu_sed0', 'MMU_MTRO_CONFIG_L1_MEM_PIPE3.mmu_sed0',
        ],
        'timeout_basic': [
        ],
        'slow_injection': [
        ],
        'unsupported': [
        ]
    },
    'th3': {
        'timeout': [
            'L3_DEFIP_TCAM_LEVEL1.ipipe0',
            'MATCH_LOGICAL_TABLE_SELECT_PIPE7.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE7.ipipe0',
            'MMU_QSCH_L2_WEIGHT_MEM_PIPE7.mmu_eb0',
            'L3_ENTRY_ONLY_SINGLE.ipipe0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE6.ipipe0',
            'MMU_QSCH_L2_WEIGHT_MEM_PIPE3.mmu_eb0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE0.ipipe0',
            'L3_ENTRY_SINGLE.ipipe0',
            'L2_ENTRY.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE6.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE0.ipipe0',
            'L3_DEFIP_ALPM_LEVEL3.ipipe0',
            'L3_ENTRY_DOUBLE.ipipe0',
            'L3_TUNNEL_QUAD.ipipe0',
            'L3_DEFIP_PAIR_LEVEL1.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE3.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE1.ipipe0',
            'L3_ENTRY_ONLY_DOUBLE.ipipe0',
            'MMU_QSCH_L2_WEIGHT_MEM_PIPE0.mmu_eb0',
            'L3_DEFIP_ALPM_LEVEL2.ipipe0',
            'EGR_IP_TUNNEL_IPV6.epipe0',
            'EXACT_MATCH_ECC.ipipe0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE3.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE5.ipipe0',
            'L3_DEFIP_ALPM_LEVEL3_SINGLE.ipipe0',
            'IFP_LOGICAL_TABLE_SELECT.ipipe0',
            'MMU_QSCH_L2_WEIGHT_MEM_PIPE5.mmu_eb0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE2.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE2.ipipe0',
            'L3_ENTRY_QUAD.ipipe0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE1.ipipe0',
            'EGR_IP_TUNNEL_MPLS.epipe0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE5.ipipe0',
            'MMU_QSCH_L2_WEIGHT_MEM_PIPE4.mmu_eb0',
            'L2_USER_ENTRY.ipipe0',
            'MMU_QSCH_L2_WEIGHT_MEM_PIPE6.mmu_eb0',
            'MY_STATION_TCAM.ipipe0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE4.ipipe0',
            'L3_DEFIP_LEVEL1.ipipe0',
            'MMU_QSCH_L2_WEIGHT_MEM_PIPE2.mmu_eb0',
            'L3_DEFIP_ALPM_LEVEL2_SINGLE.ipipe0',
            'L3_TUNNEL_DOUBLE.ipipe0',
            'L3_ENTRY_ONLY_QUAD.ipipe0',
            'IFP_LOGICAL_TABLE_SELECT_PIPE7.ipipe0',
            'MMU_QSCH_L2_WEIGHT_MEM_PIPE1.mmu_eb0',
            'MPLS_ENTRY_SINGLE.ipipe0',
            'CPU_COS_MAP.ipipe0',
            'L3_TUNNEL_SINGLE.ipipe0',
            'L3_DEFIP_ALPM_LEVEL2_HIT_ONLY.ipipe0',
            'L2_ENTRY_ONLY_SINGLE.ipipe0',
            'L3_DEFIP_LEVEL1_HIT_ONLY.ipipe0',
            'EXACT_MATCH_LOGICAL_TABLE_SELECT_PIPE4.ipipe0',
            'L3_DEFIP_ALPM_LEVEL3_HIT_ONLY.ipipe0'
        ],
        'timeout_basic': [
        ],
        'slow_injection': [
        ],
        'unsupported': [
        ]
    },
    'default': {
        'timeout': [],
        'timeout_basic': [],
        'slow_injection': [],
        'unsupported': [],
    },
}


def run_cmd(cmd, asic_id=None):
    '''
    @summary: Utility that runs a command in a subprocess
    @param cmd: Command to be run
    @return: stdout of the command run
    @return: stderr of the command run
    '''
    if asic_id is not None:
        if cmd[0] == "bcmcmd":
            cmd = cmd[1:]
            args = " ".join(cmd)
            cmd = ["bcmcmd", "-n", str(asic_id), args]

    logging.debug("cmd: {}".format(cmd))
    out = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    stdout, stderr = out.communicate()
    logging.debug("stdout: {}; stderr {}".format(stdout, stderr))
    return stdout, stderr


def get_asic_name():
    asic = "unknown"
    stdout, _ = run_cmd("lspci")
    output = stdout.decode("utf-8")
    if ("Broadcom Limited Device b960" in output or
        "Broadcom Limited Broadcom BCM56960" in output or
        "Broadcom Inc. and subsidiaries Device b960" in output or
        "Broadcom Inc. and subsidiaries Broadcom BCM56960" in output or
            "Broadcom Inc. and subsidiaries BCM56960" in output):
        asic = "th"
    elif ("Broadcom Limited Device b971" in output or
          "Broadcom Inc. and subsidiaries Device b971" in output):
        asic = "th2"
    elif ("Broadcom Limited Device b850" in output or
          "Broadcom Limited Broadcom BCM56850" in output or
          "Broadcom Inc. and subsidiaries Device b850" in output or
          "Broadcom Inc. and subsidiaries Broadcom BCM56850" in output):
        asic = "td2"
    elif ("Broadcom Limited Device b870" in output or
          "Broadcom Inc. and subsidiaries Device b870" in output):
        asic = "td3"
    elif ("Broadcom Limited Device b980" in output or
          "Broadcom Inc. and subsidiaries Device b980" in output):
        asic = "th3"

    return asic


def get_skip_list_per_asic():
    global SKIP_MEMORY_PER_ASIC

    asic = get_asic_name()

    return SKIP_MEMORY_PER_ASIC[asic] if asic in SKIP_MEMORY_PER_ASIC else SKIP_MEMORY_PER_ASIC['default']


class BcmMemory():
    '''
    @summary: BcmMemory captures different memory tables of the Broadcom ASIC.
              Memory are split into two categories: cached and uncached.
              Broadcom SER correction is enabled for cached memory tables.
              For cached memory tables, memory attributes are also retreived
    '''

    def __init__(self, asic_id=None):
        '''
        @summary: Class constructor
        '''
        self.cached_memory = {}
        self.uncached_memory = {}
        self.memory_address = {}
        self.asic_id = asic_id

    def get_memory_attributes(self, mem):
        '''
        @summary: Reads Broadcom memory attributes using list command. Attributes include start address, flags,
                  number of entries, entry size in bytes and entry size in words. The method uses regex to parse
                  the command output since there is not SAI APIs for it.
        '''
        stdout, stderr = run_cmd(["bcmcmd",  "list " + mem], self.asic_id)

        attributes = stdout.decode("utf-8").split("\n")

        attr = {}
        m = re.search('^Memory:.*address (.+)$', attributes[1])
        attr['address'] = int(m.group(1), 16)

        m = re.search('^Flags: (.*)$', attributes[2])
        attr['flags'] = m.group(1).strip().split(" ")

        m = re.search(r'^Entries: (\d+).*each (\d+) bytes (\d+) words', attributes[4])
        attr['entries'] = int(m.group(1))
        attr['size_byte'] = int(m.group(2))
        attr['size_word'] = int(m.group(3))

        return attr

    def rekey_memory_address(self, mem):
        # Reading from file will change key type from int to str.
        # for the test to run correctly, the key needs to be
        # adjusted back to int.
        for key, val in list(mem.items()):
            self.memory_address[int(key)] = val

    def read_memory_from_file(self):
        file_name = '/tmp/{}-mem-info.json'.format(get_asic_name())
        try:
            with open(file_name, 'r') as info:
                contents = json.load(info)
            self.cached_memory = contents['cached_memory']
            self.uncached_memory = contents['uncached_memory']
            self.rekey_memory_address(contents['memory_address'])
        except IOError:
            return False

        return True

    def write_memory_to_file(self):
        contents = {'cached_memory': self.cached_memory,
                    'uncached_memory': self.uncached_memory,
                    'memory_address': self.memory_address}
        file_name = '/tmp/{}-mem-info.json'.format(get_asic_name())
        try:
            with open(file_name, 'w') as info:
                json.dump(contents, info, indent=4)
        except IOError:
            pass

    def read_memory(self):
        '''
        @summary: Read different memory tables using cache command. It update
                  both cached_memory and uncached_memory hash tables. For
                  cached memory, ut aksi creat a reverse index of address to
                  memory table name. This indez is stored in memory_address hash
                  table

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

        stdout, stderr = run_cmd(['bcmcmd', 'cache'], self.asic_id)

        cache_flag = False
        memories = stdout.decode("utf-8").split("\n")

        # remove Head line and 3 trailing prompt lines
        memories = memories[1: len(memories) - 3]
        for memory in memories:
            if memory.find("Caching is off") > -1:
                cache_flag = False
            elif memory.find("Caching is on") > -1:
                cache_flag = True
            else:
                if cache_flag:
                    self.cached_memory.update(
                        {mem: {} for mem in memory.strip().split(" ")})
                else:
                    self.uncached_memory.update(
                        {mem: {} for mem in memory.strip().split(" ")})

        self.memory_address = defaultdict(list)
        for mem in self.cached_memory:
            self.cached_memory[mem] = self.get_memory_attributes(mem)
            self.memory_address[self.cached_memory[mem]['address']].append(mem)
            if VERBOSE:
                logging.info(('--- found cache memory {} : {} : {}'.format(mem, hex(
                    self.cached_memory[mem]['address']), self.memory_address[self.cached_memory[mem]['address']])))

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

    def __init__(self, test_time_sec=DEFAULT_SER_TEST_TIME_SEC,
                 ser_injection_interval_sec=DEFAULT_SER_INJECTION_INTERVAL_SEC,
                 syslog_poll_interval_sec=DEFAULT_SYSLOG_POLLING_INTERVAL_SEC,
                 stall_indication=DEFAULT_STALL_INDICATION,
                 batch_size=DEFAULT_BATCH_SIZE,
                 injection_slow_sec=DEFAULT_INJECTION_SLOW_SEC,
                 skip_slow_injections=False,
                 asic_id=None):
        '''
        @summary: Class constructor
        '''
        self.syslog_poll_interval_sec = syslog_poll_interval_sec
        self.test_time_sec = test_time_sec
        self.ser_injection_interval_sec = ser_injection_interval_sec
        self.stall_indication = stall_indication
        self.batch_size = batch_size
        self.injection_slow_sec = injection_slow_sec
        self.skip_slow_injections = skip_slow_injections
        self.asic_id = asic_id
        self.test_candidates = []
        self.mem_verification_pending = []
        self.mem_verified = {}
        self.mem_failed = {}
        self.mem_ser_unsupported = []
        self.mem_injection_speed = {}
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

        full_skip_list = get_skip_list_per_asic()

        self.bcmMemory.read_memory()
        if completeness == 'thorough':
            self.test_candidates = list(
                set(self.bcmMemory.get_cached_memory().keys()))
            if self.batch_size == DEFAULT_BATCH_SIZE:
                # Slightly increase batch size to reduce run time
                self.batch_size = DEFAULT_THOROUGH_BATCH_SIZE
            skip_list = []
        elif completeness == 'diagnose':
            # Re-probing the normally skipped entries
            self.test_candidates = list(set(full_skip_list['timeout'] + full_skip_list['timeout_basic'] +
                                            full_skip_list['unsupported'] + full_skip_list['slow_injection']))
        else:
            skip_list = list(set(
                full_skip_list['timeout'] + full_skip_list['unsupported'] + full_skip_list['slow_injection']))
            if completeness != 'confident':
                skip_list = list(
                    set(skip_list + full_skip_list['timeout_basic']))
            self.test_candidates = list(
                set(self.bcmMemory.get_cached_memory().keys()) - set(skip_list))

        if self.skip_slow_injections:
            self.test_candidates = list(
                set(self.test_candidates) - set(full_skip_list['slow_injection']))
            skip_list = list(set(skip_list + full_skip_list['slow_injection']))

        if completeness == 'debug':
            batch_size = min(1, len(self.test_candidates))
            self.mem_verification_pending = random.sample(
                self.test_candidates, batch_size)
        elif completeness == 'basic':
            batch_size = min(self.batch_size, len(self.test_candidates))
            sample_size = min(batch_size * 6, len(self.test_candidates))
            self.mem_verification_pending = random.sample(
                self.test_candidates, sample_size)
        else:  # default: 'confident', 'thorough'
            batch_size = min(self.batch_size, len(self.test_candidates))
            # Still go through random to ramdomize the ordering
            self.mem_verification_pending = random.sample(
                self.test_candidates, len(self.test_candidates))

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
            size_before = len(self.mem_verification_pending)
            batch_size = min(batch_size, size_before)
            logging.info(("Test iteration {}, stalled {}, candidate(s) left {} batch_size {}".format(
                count, stall, size_before, batch_size)))
            test_memory = list(self.mem_verification_pending[0:batch_size])
            self.run_test(test_memory)
            size_after = len(self.mem_verification_pending)
            if size_before != size_after:
                # No need to track misses until the stalling starts
                self.miss_counts = {}
                stall = 0
            else:
                stall = stall + 1
                # Increase batch size when stall is detected
                batch_size = min(len(self.mem_verification_pending),
                                 batch_size + self.batch_size)
                if stall >= self.stall_indication:
                    if VERBOSE:
                        logging.info('--- stall detected. Stop testing')
                    break

        logging.info(("SER test on ASIC : {}".format(get_asic_name())))
        if VERBOSE:
            logging.info(("SER Test memories candidates (%s): %s" % (len(self.test_candidates), self.test_candidates)))
            logging.info(("SER Test succeeded for memories (%s): %s" % (len(self.mem_verified), self.mem_verified)))
            logging.info(("SER Test skipped memories (%s): %s" % (len(skip_list), skip_list)))
        else:
            logging.info(("SER Test memories candidates (%s)" % (len(self.test_candidates))))
            logging.info(("SER Test succeeded for memories (%s)" % (len(self.mem_verified))))
        logging.info(("SER Test failed for memories (%s): %s %s" %
                      (len(self.mem_failed), self.mem_failed, list(self.mem_failed.keys()))))
        logging.info(("SER Test timed out for memories (%s): %s" %
                      (len(self.mem_verification_pending), self.mem_verification_pending)))
        logging.info(("SER Test is not supported for memories (%s): %s" %
                      (len(self.mem_ser_unsupported), self.mem_ser_unsupported)))
        slow_injection = {k: v for k, v in list(
            self.mem_injection_speed.items()) if v['slow'] > 0}
        logging.info(("SER Test memory error injection too slow (%s): %s %s" %
                      (len(slow_injection), slow_injection, list(slow_injection.keys()))))

        if VERBOSE:
            logging.info("--- found {} memory location(s) reported misaligned "
                         "correction events ---".format(len(self.miss_counts)))

            for address, count in list(self.miss_counts.items()):
                logging.info(
                    ("--- unknown address {} was triggered {} times".format(hex(address), count)))

        return len(self.mem_failed) + len(self.mem_verification_pending)

    def enable_memory_scan(self, cmd, interval_usec, rate):
        '''
        @summary: Enable Broadcom memory scan
        @param cmd: Broadcom to use
        @param interval_usec: memory scanner interval i usec
        @param rate: rate (number of entries) per interval
        '''
        for x in range(3):
            stdout, stderr = run_cmd(
                [
                    "bcmcmd",
                    cmd + " interval=" +
                    str(interval_usec) + " rate=" + str(rate)
                ],
                self.asic_id
            )
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
        m = re.search(r"^.*addr:(.*) port.*index: (\d+)", log)
        if not m:
            logging.info(("--- cannot parse log {}".format(log)))
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
            logging.info(("--- addr {} ({}) not found in dict: {} time(s)".format(
                hex(address), address, self.miss_counts[address])))

        return None, None

    def inject_ser(self, mem, index=0, tag=None):
        '''
        @summary: Inject SER error suing Broadcom ser inject command
        @param mem: name of the memory table to inject SER into
        @param index: index of the entry to inject SER into
        '''
        if VERBOSE:
            logging.info(('--- injecting error at {} index {} tag {}'.format(mem, index, tag)))
        return run_cmd(
            [
                "bcmcmd",
                "ser inject memory=" + mem + " index=" + str(index)
            ],
            self.asic_id
        )

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
                        logging.info(("Successfully tested memory %s" % m))
                        self.mem_verified.update({m: 1})
                else:
                    if m in self.mem_failed:
                        self.mem_failed[m] += 1
                    else:
                        logging.info(
                            ("Failed verification for memory %s, syslog '%s'" % (m, line)))
                        self.mem_failed.update({m: 1})

                if m in self.mem_verification_pending:
                    self.mem_verification_pending.remove(m)
                else:
                    logging.info(("Memory %s appeared more than once" % m))
        elif VERBOSE:
            logging.info(
                ("Memory corresponding to the following syslog was not found! Syslog: '%s'" % line))

    def run_test(self, memory, entry=0):
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
                inj_start_time = time.time()
                stdout, stderr = self.inject_ser(mem, tag=tag)
                inj_time = time.time() - inj_start_time
                speed = self.mem_injection_speed.get(
                    mem, {'slow': 0, 'fast': 0, 'slow_times': []})
                if inj_time < self.injection_slow_sec:
                    speed['fast'] = speed['fast'] + 1
                else:
                    speed['slow'] = speed['slow'] + 1
                    speed['slow_times'].append(inj_time)
                    if VERBOSE:
                        logging.info(
                            ('--- mem {} error inject is slow: {}'.format(mem, speed)))
                self.mem_injection_speed[mem] = speed
                if stdout.decode().find('SER correction for it is not currently supported') > -1:
                    logging.info(("memory %s does not support ser" % mem))
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
                        logging.info("timed out waiting for ser correction...")
                        break


def main():
    global VERBOSE

    parser = argparse.ArgumentParser(description='Completeness level')
    parser.add_argument(
        '-b', '--batch_size',
        help='batch size: number of entries to inject at each batch, default {}'.format(
            DEFAULT_BATCH_SIZE
        ),
        type=int, required=False, default=DEFAULT_BATCH_SIZE
    )
    parser.add_argument(
        '-c', '--completeness',
        help='Completeness level: debug, basic, confident, thorough, diagnose',
        type=str, required=False, default='basic',
        choices=['debug', 'basic', 'confident', 'thorough', 'diagnose']
    )
    parser.add_argument(
        '-e', '--skip_slow_injections',
        help='Skip slow injections, default False', action='store_true',
        required=False, default=False
    )
    parser.add_argument(
        '-i', '--injection_slow_sec',
        help='injection slow threshold in secs: stall count when stopping test, default {}'.format(
            DEFAULT_INJECTION_SLOW_SEC
        ),
        type=int, required=False, default=DEFAULT_INJECTION_SLOW_SEC
    )
    parser.add_argument(
        '-s', '--stall_limit',
        help='Stall limit: stall count when stopping test, default {}'.format(
            DEFAULT_STALL_INDICATION
        ),
        type=int, required=False, default=DEFAULT_STALL_INDICATION
    )
    parser.add_argument(
        '-t', '--test_batch_timeout',
        help='test batch timeout: max wait time for each batch (in seconds), default {}'.format(
            DEFAULT_SER_TEST_TIME_SEC
        ),
        type=int, required=False, default=DEFAULT_SER_TEST_TIME_SEC
    )
    parser.add_argument(
        '-v', '--verbose', help='Set verbose output', action='store_true',
        required=False, default=False
    )
    parser.add_argument(
        '-n', '--asic_id',
        help='ASIC ID on multi ASIC platform, default is None',
        type=int, required=False, default=None
    )
    parser.add_argument(
        '-f', '--log_filename',
        type=str, required=False, default=log_filename,
    )
    args = parser.parse_args()

    logging.basicConfig(filename=args.log_filename,
                        level=logging.DEBUG,
                        format='%(asctime)s-%(levelname)s-%(lineno)d - %(message)s')

    VERBOSE = args.verbose

    start_time = time.time()
    serTest = SerTest(
        test_time_sec=args.test_batch_timeout,
        stall_indication=args.stall_limit,
        batch_size=args.batch_size,
        injection_slow_sec=args.injection_slow_sec,
        skip_slow_injections=args.skip_slow_injections,
        asic_id=args.asic_id
    )
    rc = serTest.test_memory(args.completeness)
    logging.info(("--- %s seconds, rc %d ---" % ((time.time() - start_time), rc)))
    sys.exit(rc)


if __name__ == "__main__":
    main()
