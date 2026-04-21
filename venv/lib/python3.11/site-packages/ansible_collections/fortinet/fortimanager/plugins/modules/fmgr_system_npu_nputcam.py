#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_system_npu_nputcam
short_description: Configure NPU TCAM policies.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.4.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    system_npu_nputcam:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            data:
                type: dict
                description: Data.
                suboptions:
                    df:
                        type: str
                        description: Tcam data ip flag df.
                        choices:
                            - 'disable'
                            - 'enable'
                    dstip:
                        type: str
                        description: Tcam data dst ipv4 address.
                    dstipv6:
                        type: str
                        description: Tcam data dst ipv6 address.
                    dstmac:
                        type: str
                        description: Tcam data dst macaddr.
                    dstport:
                        type: int
                        description: Tcam data L4 dst port.
                    ethertype:
                        type: str
                        description: Tcam data ethertype.
                    ext_tag:
                        aliases: ['ext-tag']
                        type: str
                        description: Tcam data extension tag.
                        choices:
                            - 'disable'
                            - 'enable'
                    frag_off:
                        aliases: ['frag-off']
                        type: int
                        description: Tcam data ip flag fragment offset.
                    gen_buf_cnt:
                        aliases: ['gen-buf-cnt']
                        type: int
                        description: Tcam data gen info buffer count.
                    gen_iv:
                        aliases: ['gen-iv']
                        type: str
                        description: Tcam data gen info iv.
                        choices:
                            - 'invalid'
                            - 'valid'
                    gen_l3_flags:
                        aliases: ['gen-l3-flags']
                        type: int
                        description: Tcam data gen info L3 flags.
                    gen_l4_flags:
                        aliases: ['gen-l4-flags']
                        type: int
                        description: Tcam data gen info L4 flags.
                    gen_pkt_ctrl:
                        aliases: ['gen-pkt-ctrl']
                        type: int
                        description: Tcam data gen info packet control.
                    gen_pri:
                        aliases: ['gen-pri']
                        type: int
                        description: Tcam data gen info priority.
                    gen_pri_v:
                        aliases: ['gen-pri-v']
                        type: str
                        description: Tcam data gen info priority valid.
                        choices:
                            - 'invalid'
                            - 'valid'
                    gen_tv:
                        aliases: ['gen-tv']
                        type: str
                        description: Tcam data gen info tv.
                        choices:
                            - 'invalid'
                            - 'valid'
                    ihl:
                        type: int
                        description: Tcam data ipv4 IHL.
                    ip4_id:
                        aliases: ['ip4-id']
                        type: int
                        description: Tcam data ipv4 id.
                    ip6_fl:
                        aliases: ['ip6-fl']
                        type: int
                        description: Tcam data ipv6 flow label.
                    ipver:
                        type: int
                        description: Tcam data ip header version.
                    l4_wd10:
                        aliases: ['l4-wd10']
                        type: int
                        description: Tcam data L4 word10.
                    l4_wd11:
                        aliases: ['l4-wd11']
                        type: int
                        description: Tcam data L4 word11.
                    l4_wd8:
                        aliases: ['l4-wd8']
                        type: int
                        description: Tcam data L4 word8.
                    l4_wd9:
                        aliases: ['l4-wd9']
                        type: int
                        description: Tcam data L4 word9.
                    mf:
                        type: str
                        description: Tcam data ip flag mf.
                        choices:
                            - 'disable'
                            - 'enable'
                    protocol:
                        type: int
                        description: Tcam data ip protocol.
                    slink:
                        type: int
                        description: Tcam data sublink.
                    smac_change:
                        aliases: ['smac-change']
                        type: str
                        description: Tcam data source MAC change.
                        choices:
                            - 'disable'
                            - 'enable'
                    sp:
                        type: int
                        description: Tcam data source port.
                    src_cfi:
                        aliases: ['src-cfi']
                        type: str
                        description: Tcam data source cfi.
                        choices:
                            - 'disable'
                            - 'enable'
                    src_prio:
                        aliases: ['src-prio']
                        type: int
                        description: Tcam data source priority.
                    src_updt:
                        aliases: ['src-updt']
                        type: str
                        description: Tcam data source update.
                        choices:
                            - 'disable'
                            - 'enable'
                    srcip:
                        type: str
                        description: Tcam data src ipv4 address.
                    srcipv6:
                        type: str
                        description: Tcam data src ipv6 address.
                    srcmac:
                        type: str
                        description: Tcam data src macaddr.
                    srcport:
                        type: int
                        description: Tcam data L4 src port.
                    svid:
                        type: int
                        description: Tcam data source vid.
                    tcp_ack:
                        aliases: ['tcp-ack']
                        type: str
                        description: Tcam data tcp flag ack.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_cwr:
                        aliases: ['tcp-cwr']
                        type: str
                        description: Tcam data tcp flag cwr.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_ece:
                        aliases: ['tcp-ece']
                        type: str
                        description: Tcam data tcp flag ece.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_fin:
                        aliases: ['tcp-fin']
                        type: str
                        description: Tcam data tcp flag fin.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_push:
                        aliases: ['tcp-push']
                        type: str
                        description: Tcam data tcp flag push.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_rst:
                        aliases: ['tcp-rst']
                        type: str
                        description: Tcam data tcp flag rst.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_syn:
                        aliases: ['tcp-syn']
                        type: str
                        description: Tcam data tcp flag syn.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_urg:
                        aliases: ['tcp-urg']
                        type: str
                        description: Tcam data tcp flag urg.
                        choices:
                            - 'disable'
                            - 'enable'
                    tgt_cfi:
                        aliases: ['tgt-cfi']
                        type: str
                        description: Tcam data target cfi.
                        choices:
                            - 'disable'
                            - 'enable'
                    tgt_prio:
                        aliases: ['tgt-prio']
                        type: int
                        description: Tcam data target priority.
                    tgt_updt:
                        aliases: ['tgt-updt']
                        type: str
                        description: Tcam data target port update.
                        choices:
                            - 'disable'
                            - 'enable'
                    tgt_v:
                        aliases: ['tgt-v']
                        type: str
                        description: Tcam data target valid.
                        choices:
                            - 'invalid'
                            - 'valid'
                    tos:
                        type: int
                        description: Tcam data ip tos.
                    tp:
                        type: int
                        description: Tcam data target port.
                    ttl:
                        type: int
                        description: Tcam data ip ttl.
                    tvid:
                        type: int
                        description: Tcam data target vid.
                    vdid:
                        type: int
                        description: Tcam data vdom id.
            dbg_dump:
                aliases: ['dbg-dump']
                type: int
                description: Debug driver dump data/mask pdq.
            mask:
                type: dict
                description: Mask.
                suboptions:
                    df:
                        type: str
                        description: Tcam mask ip flag df.
                        choices:
                            - 'disable'
                            - 'enable'
                    dstip:
                        type: str
                        description: Tcam mask dst ipv4 address.
                    dstipv6:
                        type: str
                        description: Tcam mask dst ipv6 address.
                    dstmac:
                        type: str
                        description: Tcam mask dst macaddr.
                    dstport:
                        type: int
                        description: Tcam mask L4 dst port.
                    ethertype:
                        type: str
                        description: Tcam mask ethertype.
                    ext_tag:
                        aliases: ['ext-tag']
                        type: str
                        description: Tcam mask extension tag.
                        choices:
                            - 'disable'
                            - 'enable'
                    frag_off:
                        aliases: ['frag-off']
                        type: int
                        description: Tcam data ip flag fragment offset.
                    gen_buf_cnt:
                        aliases: ['gen-buf-cnt']
                        type: int
                        description: Tcam mask gen info buffer count.
                    gen_iv:
                        aliases: ['gen-iv']
                        type: str
                        description: Tcam mask gen info iv.
                        choices:
                            - 'invalid'
                            - 'valid'
                    gen_l3_flags:
                        aliases: ['gen-l3-flags']
                        type: int
                        description: Tcam mask gen info L3 flags.
                    gen_l4_flags:
                        aliases: ['gen-l4-flags']
                        type: int
                        description: Tcam mask gen info L4 flags.
                    gen_pkt_ctrl:
                        aliases: ['gen-pkt-ctrl']
                        type: int
                        description: Tcam mask gen info packet control.
                    gen_pri:
                        aliases: ['gen-pri']
                        type: int
                        description: Tcam mask gen info priority.
                    gen_pri_v:
                        aliases: ['gen-pri-v']
                        type: str
                        description: Tcam mask gen info priority valid.
                        choices:
                            - 'invalid'
                            - 'valid'
                    gen_tv:
                        aliases: ['gen-tv']
                        type: str
                        description: Tcam mask gen info tv.
                        choices:
                            - 'invalid'
                            - 'valid'
                    ihl:
                        type: int
                        description: Tcam mask ipv4 IHL.
                    ip4_id:
                        aliases: ['ip4-id']
                        type: int
                        description: Tcam mask ipv4 id.
                    ip6_fl:
                        aliases: ['ip6-fl']
                        type: int
                        description: Tcam mask ipv6 flow label.
                    ipver:
                        type: int
                        description: Tcam mask ip header version.
                    l4_wd10:
                        aliases: ['l4-wd10']
                        type: int
                        description: Tcam mask L4 word10.
                    l4_wd11:
                        aliases: ['l4-wd11']
                        type: int
                        description: Tcam mask L4 word11.
                    l4_wd8:
                        aliases: ['l4-wd8']
                        type: int
                        description: Tcam mask L4 word8.
                    l4_wd9:
                        aliases: ['l4-wd9']
                        type: int
                        description: Tcam mask L4 word9.
                    mf:
                        type: str
                        description: Tcam mask ip flag mf.
                        choices:
                            - 'disable'
                            - 'enable'
                    protocol:
                        type: int
                        description: Tcam mask ip protocol.
                    slink:
                        type: int
                        description: Tcam mask sublink.
                    smac_change:
                        aliases: ['smac-change']
                        type: str
                        description: Tcam mask source MAC change.
                        choices:
                            - 'disable'
                            - 'enable'
                    sp:
                        type: int
                        description: Tcam mask source port.
                    src_cfi:
                        aliases: ['src-cfi']
                        type: str
                        description: Tcam mask source cfi.
                        choices:
                            - 'disable'
                            - 'enable'
                    src_prio:
                        aliases: ['src-prio']
                        type: int
                        description: Tcam mask source priority.
                    src_updt:
                        aliases: ['src-updt']
                        type: str
                        description: Tcam mask source update.
                        choices:
                            - 'disable'
                            - 'enable'
                    srcip:
                        type: str
                        description: Tcam mask src ipv4 address.
                    srcipv6:
                        type: str
                        description: Tcam mask src ipv6 address.
                    srcmac:
                        type: str
                        description: Tcam mask src macaddr.
                    srcport:
                        type: int
                        description: Tcam mask L4 src port.
                    svid:
                        type: int
                        description: Tcam mask source vid.
                    tcp_ack:
                        aliases: ['tcp-ack']
                        type: str
                        description: Tcam mask tcp flag ack.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_cwr:
                        aliases: ['tcp-cwr']
                        type: str
                        description: Tcam mask tcp flag cwr.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_ece:
                        aliases: ['tcp-ece']
                        type: str
                        description: Tcam mask tcp flag ece.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_fin:
                        aliases: ['tcp-fin']
                        type: str
                        description: Tcam mask tcp flag fin.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_push:
                        aliases: ['tcp-push']
                        type: str
                        description: Tcam mask tcp flag push.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_rst:
                        aliases: ['tcp-rst']
                        type: str
                        description: Tcam mask tcp flag rst.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_syn:
                        aliases: ['tcp-syn']
                        type: str
                        description: Tcam mask tcp flag syn.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_urg:
                        aliases: ['tcp-urg']
                        type: str
                        description: Tcam mask tcp flag urg.
                        choices:
                            - 'disable'
                            - 'enable'
                    tgt_cfi:
                        aliases: ['tgt-cfi']
                        type: str
                        description: Tcam mask target cfi.
                        choices:
                            - 'disable'
                            - 'enable'
                    tgt_prio:
                        aliases: ['tgt-prio']
                        type: int
                        description: Tcam mask target priority.
                    tgt_updt:
                        aliases: ['tgt-updt']
                        type: str
                        description: Tcam mask target port update.
                        choices:
                            - 'disable'
                            - 'enable'
                    tgt_v:
                        aliases: ['tgt-v']
                        type: str
                        description: Tcam mask target valid.
                        choices:
                            - 'invalid'
                            - 'valid'
                    tos:
                        type: int
                        description: Tcam mask ip tos.
                    tp:
                        type: int
                        description: Tcam mask target port.
                    ttl:
                        type: int
                        description: Tcam mask ip ttl.
                    tvid:
                        type: int
                        description: Tcam mask target vid.
                    vdid:
                        type: int
                        description: Tcam mask vdom id.
            mir_act:
                aliases: ['mir-act']
                type: dict
                description: Mir act.
                suboptions:
                    vlif:
                        type: int
                        description: Tcam mirror action vlif.
            name:
                type: str
                description: NPU TCAM policies name.
                required: true
            oid:
                type: int
                description: NPU TCAM OID.
            pri_act:
                aliases: ['pri-act']
                type: dict
                description: Pri act.
                suboptions:
                    priority:
                        type: int
                        description: Tcam priority action priority.
                    weight:
                        type: int
                        description: Tcam priority action weight.
            sact:
                type: dict
                description: Sact.
                suboptions:
                    act:
                        type: int
                        description: Tcam sact act.
                    act_v:
                        aliases: ['act-v']
                        type: str
                        description: Enable to set sact act.
                        choices:
                            - 'disable'
                            - 'enable'
                    bmproc:
                        type: int
                        description: Tcam sact bmproc.
                    bmproc_v:
                        aliases: ['bmproc-v']
                        type: str
                        description: Enable to set sact bmproc.
                        choices:
                            - 'disable'
                            - 'enable'
                    df_lif:
                        aliases: ['df-lif']
                        type: int
                        description: Tcam sact df-lif.
                    df_lif_v:
                        aliases: ['df-lif-v']
                        type: str
                        description: Enable to set sact df-lif.
                        choices:
                            - 'disable'
                            - 'enable'
                    dfr:
                        type: int
                        description: Tcam sact dfr.
                    dfr_v:
                        aliases: ['dfr-v']
                        type: str
                        description: Enable to set sact dfr.
                        choices:
                            - 'disable'
                            - 'enable'
                    dmac_skip:
                        aliases: ['dmac-skip']
                        type: int
                        description: Tcam sact dmac-skip.
                    dmac_skip_v:
                        aliases: ['dmac-skip-v']
                        type: str
                        description: Enable to set sact dmac-skip.
                        choices:
                            - 'disable'
                            - 'enable'
                    dosen:
                        type: int
                        description: Tcam sact dosen.
                    dosen_v:
                        aliases: ['dosen-v']
                        type: str
                        description: Enable to set sact dosen.
                        choices:
                            - 'disable'
                            - 'enable'
                    espff_proc:
                        aliases: ['espff-proc']
                        type: int
                        description: Tcam sact espff-proc.
                    espff_proc_v:
                        aliases: ['espff-proc-v']
                        type: str
                        description: Enable to set sact espff-proc.
                        choices:
                            - 'disable'
                            - 'enable'
                    etype_pid:
                        aliases: ['etype-pid']
                        type: int
                        description: Tcam sact etype-pid.
                    etype_pid_v:
                        aliases: ['etype-pid-v']
                        type: str
                        description: Enable to set sact etype-pid.
                        choices:
                            - 'disable'
                            - 'enable'
                    frag_proc:
                        aliases: ['frag-proc']
                        type: int
                        description: Tcam sact frag-proc.
                    frag_proc_v:
                        aliases: ['frag-proc-v']
                        type: str
                        description: Enable to set sact frag-proc.
                        choices:
                            - 'disable'
                            - 'enable'
                    fwd:
                        type: int
                        description: Tcam sact fwd.
                    fwd_lif:
                        aliases: ['fwd-lif']
                        type: int
                        description: Tcam sact fwd-lif.
                    fwd_lif_v:
                        aliases: ['fwd-lif-v']
                        type: str
                        description: Enable to set sact fwd-lif.
                        choices:
                            - 'disable'
                            - 'enable'
                    fwd_tvid:
                        aliases: ['fwd-tvid']
                        type: int
                        description: Tcam sact fwd-tvid.
                    fwd_tvid_v:
                        aliases: ['fwd-tvid-v']
                        type: str
                        description: Enable to set sact fwd-vid.
                        choices:
                            - 'disable'
                            - 'enable'
                    fwd_v:
                        aliases: ['fwd-v']
                        type: str
                        description: Enable to set sact fwd.
                        choices:
                            - 'disable'
                            - 'enable'
                    icpen:
                        type: int
                        description: Tcam sact icpen.
                    icpen_v:
                        aliases: ['icpen-v']
                        type: str
                        description: Enable to set sact icpen.
                        choices:
                            - 'disable'
                            - 'enable'
                    igmp_mld_snp:
                        aliases: ['igmp-mld-snp']
                        type: int
                        description: Tcam sact igmp-mld-snp.
                    igmp_mld_snp_v:
                        aliases: ['igmp-mld-snp-v']
                        type: str
                        description: Enable to set sact igmp-mld-snp.
                        choices:
                            - 'disable'
                            - 'enable'
                    learn:
                        type: int
                        description: Tcam sact learn.
                    learn_v:
                        aliases: ['learn-v']
                        type: str
                        description: Enable to set sact learn.
                        choices:
                            - 'disable'
                            - 'enable'
                    m_srh_ctrl:
                        aliases: ['m-srh-ctrl']
                        type: int
                        description: Tcam sact m-srh-ctrl.
                    m_srh_ctrl_v:
                        aliases: ['m-srh-ctrl-v']
                        type: str
                        description: Enable to set sact m-srh-ctrl.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac_id:
                        aliases: ['mac-id']
                        type: int
                        description: Tcam sact mac-id.
                    mac_id_v:
                        aliases: ['mac-id-v']
                        type: str
                        description: Enable to set sact mac-id.
                        choices:
                            - 'disable'
                            - 'enable'
                    mss:
                        type: int
                        description: Tcam sact mss.
                    mss_v:
                        aliases: ['mss-v']
                        type: str
                        description: Enable to set sact mss.
                        choices:
                            - 'disable'
                            - 'enable'
                    pleen:
                        type: int
                        description: Tcam sact pleen.
                    pleen_v:
                        aliases: ['pleen-v']
                        type: str
                        description: Enable to set sact pleen.
                        choices:
                            - 'disable'
                            - 'enable'
                    prio_pid:
                        aliases: ['prio-pid']
                        type: int
                        description: Tcam sact prio-pid.
                    prio_pid_v:
                        aliases: ['prio-pid-v']
                        type: str
                        description: Enable to set sact prio-pid.
                        choices:
                            - 'disable'
                            - 'enable'
                    promis:
                        type: int
                        description: Tcam sact promis.
                    promis_v:
                        aliases: ['promis-v']
                        type: str
                        description: Enable to set sact promis.
                        choices:
                            - 'disable'
                            - 'enable'
                    rfsh:
                        type: int
                        description: Tcam sact rfsh.
                    rfsh_v:
                        aliases: ['rfsh-v']
                        type: str
                        description: Enable to set sact rfsh.
                        choices:
                            - 'disable'
                            - 'enable'
                    smac_skip:
                        aliases: ['smac-skip']
                        type: int
                        description: Tcam sact smac-skip.
                    smac_skip_v:
                        aliases: ['smac-skip-v']
                        type: str
                        description: Enable to set sact smac-skip.
                        choices:
                            - 'disable'
                            - 'enable'
                    tp_smchk_v:
                        aliases: ['tp-smchk-v']
                        type: str
                        description: Enable to set sact tp mode.
                        choices:
                            - 'disable'
                            - 'enable'
                    tp_smchk:
                        type: int
                        description: Tcam sact tp mode.
                    tpe_id:
                        aliases: ['tpe-id']
                        type: int
                        description: Tcam sact tpe-id.
                    tpe_id_v:
                        aliases: ['tpe-id-v']
                        type: str
                        description: Enable to set sact tpe-id.
                        choices:
                            - 'disable'
                            - 'enable'
                    vdm:
                        type: int
                        description: Tcam sact vdm.
                    vdm_v:
                        aliases: ['vdm-v']
                        type: str
                        description: Enable to set sact vdm.
                        choices:
                            - 'disable'
                            - 'enable'
                    vdom_id:
                        aliases: ['vdom-id']
                        type: int
                        description: Tcam sact vdom-id.
                    vdom_id_v:
                        aliases: ['vdom-id-v']
                        type: str
                        description: Enable to set sact vdom-id.
                        choices:
                            - 'disable'
                            - 'enable'
                    x_mode:
                        aliases: ['x-mode']
                        type: int
                        description: Tcam sact x-mode.
                    x_mode_v:
                        aliases: ['x-mode-v']
                        type: str
                        description: Enable to set sact x-mode.
                        choices:
                            - 'disable'
                            - 'enable'
            tact:
                type: dict
                description: Tact.
                suboptions:
                    act:
                        type: int
                        description: Tcam tact act.
                    act_v:
                        aliases: ['act-v']
                        type: str
                        description: Enable to set tact act.
                        choices:
                            - 'disable'
                            - 'enable'
                    fmtuv4_s:
                        aliases: ['fmtuv4-s']
                        type: int
                        description: Tcam tact fmtuv4-s.
                    fmtuv4_s_v:
                        aliases: ['fmtuv4-s-v']
                        type: str
                        description: Enable to set tact fmtuv4-s.
                        choices:
                            - 'disable'
                            - 'enable'
                    fmtuv6_s:
                        aliases: ['fmtuv6-s']
                        type: int
                        description: Tcam tact fmtuv6-s.
                    fmtuv6_s_v:
                        aliases: ['fmtuv6-s-v']
                        type: str
                        description: Enable to set tact fmtuv6-s.
                        choices:
                            - 'disable'
                            - 'enable'
                    lnkid:
                        type: int
                        description: Tcam tact lnkid.
                    lnkid_v:
                        aliases: ['lnkid-v']
                        type: str
                        description: Enable to set tact lnkid.
                        choices:
                            - 'disable'
                            - 'enable'
                    mac_id:
                        aliases: ['mac-id']
                        type: int
                        description: Tcam tact mac-id.
                    mac_id_v:
                        aliases: ['mac-id-v']
                        type: str
                        description: Enable to set tact mac-id.
                        choices:
                            - 'disable'
                            - 'enable'
                    mss_t:
                        aliases: ['mss-t']
                        type: int
                        description: Tcam tact mss.
                    mss_t_v:
                        aliases: ['mss-t-v']
                        type: str
                        description: Enable to set tact mss.
                        choices:
                            - 'disable'
                            - 'enable'
                    mtuv4:
                        type: int
                        description: Tcam tact mtuv4.
                    mtuv4_v:
                        aliases: ['mtuv4-v']
                        type: str
                        description: Enable to set tact mtuv4.
                        choices:
                            - 'disable'
                            - 'enable'
                    mtuv6:
                        type: int
                        description: Tcam tact mtuv6.
                    mtuv6_v:
                        aliases: ['mtuv6-v']
                        type: str
                        description: Enable to set tact mtuv6.
                        choices:
                            - 'disable'
                            - 'enable'
                    slif_act:
                        aliases: ['slif-act']
                        type: int
                        description: Tcam tact slif-act.
                    slif_act_v:
                        aliases: ['slif-act-v']
                        type: str
                        description: Enable to set tact slif-act.
                        choices:
                            - 'disable'
                            - 'enable'
                    sublnkid:
                        type: int
                        description: Tcam tact sublnkid.
                    sublnkid_v:
                        aliases: ['sublnkid-v']
                        type: str
                        description: Enable to set tact sublnkid.
                        choices:
                            - 'disable'
                            - 'enable'
                    tgtv_act:
                        aliases: ['tgtv-act']
                        type: int
                        description: Tcam tact tgtv-act.
                    tgtv_act_v:
                        aliases: ['tgtv-act-v']
                        type: str
                        description: Enable to set tact tgtv-act.
                        choices:
                            - 'disable'
                            - 'enable'
                    tlif_act:
                        aliases: ['tlif-act']
                        type: int
                        description: Tcam tact tlif-act.
                    tlif_act_v:
                        aliases: ['tlif-act-v']
                        type: str
                        description: Enable to set tact tlif-act.
                        choices:
                            - 'disable'
                            - 'enable'
                    tpeid:
                        type: int
                        description: Tcam tact tpeid.
                    tpeid_v:
                        aliases: ['tpeid-v']
                        type: str
                        description: Enable to set tact tpeid.
                        choices:
                            - 'disable'
                            - 'enable'
                    v6fe:
                        type: int
                        description: Tcam tact v6fe.
                    v6fe_v:
                        aliases: ['v6fe-v']
                        type: str
                        description: Enable to set tact v6fe.
                        choices:
                            - 'disable'
                            - 'enable'
                    vep_en_v:
                        aliases: ['vep-en-v']
                        type: str
                        description: Enable to set tact vep-en.
                        choices:
                            - 'disable'
                            - 'enable'
                    vep_slid:
                        aliases: ['vep-slid']
                        type: int
                        description: Tcam tact vep_slid.
                    vep_slid_v:
                        aliases: ['vep-slid-v']
                        type: str
                        description: Enable to set tact vep-slid.
                        choices:
                            - 'disable'
                            - 'enable'
                    vep_en:
                        type: int
                        description: Tcam tact vep_en.
                    xlt_lif:
                        aliases: ['xlt-lif']
                        type: int
                        description: Tcam tact xlt-lif.
                    xlt_lif_v:
                        aliases: ['xlt-lif-v']
                        type: str
                        description: Enable to set tact xlt-lif.
                        choices:
                            - 'disable'
                            - 'enable'
                    xlt_vid:
                        aliases: ['xlt-vid']
                        type: int
                        description: Tcam tact xlt-vid.
                    xlt_vid_v:
                        aliases: ['xlt-vid-v']
                        type: str
                        description: Enable to set tact xlt-vid.
                        choices:
                            - 'disable'
                            - 'enable'
            type:
                type: str
                description: TCAM policy type.
                choices:
                    - 'L2_src_tc'
                    - 'L2_tgt_tc'
                    - 'L2_src_mir'
                    - 'L2_tgt_mir'
                    - 'L2_src_act'
                    - 'L2_tgt_act'
                    - 'IPv4_src_tc'
                    - 'IPv4_tgt_tc'
                    - 'IPv4_src_mir'
                    - 'IPv4_tgt_mir'
                    - 'IPv4_src_act'
                    - 'IPv4_tgt_act'
                    - 'IPv6_src_tc'
                    - 'IPv6_tgt_tc'
                    - 'IPv6_src_mir'
                    - 'IPv6_tgt_mir'
                    - 'IPv6_src_act'
                    - 'IPv6_tgt_act'
            vid:
                type: int
                description: NPU TCAM VID.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure NPU TCAM policies.
      fortinet.fortimanager.fmgr_system_npu_nputcam:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        system_npu_nputcam:
          name: "your value" # Required variable, string
          # data:
          #   df: <value in [disable, enable]>
          #   dstip: <string>
          #   dstipv6: <string>
          #   dstmac: <string>
          #   dstport: <integer>
          #   ethertype: <string>
          #   ext_tag: <value in [disable, enable]>
          #   frag_off: <integer>
          #   gen_buf_cnt: <integer>
          #   gen_iv: <value in [invalid, valid]>
          #   gen_l3_flags: <integer>
          #   gen_l4_flags: <integer>
          #   gen_pkt_ctrl: <integer>
          #   gen_pri: <integer>
          #   gen_pri_v: <value in [invalid, valid]>
          #   gen_tv: <value in [invalid, valid]>
          #   ihl: <integer>
          #   ip4_id: <integer>
          #   ip6_fl: <integer>
          #   ipver: <integer>
          #   l4_wd10: <integer>
          #   l4_wd11: <integer>
          #   l4_wd8: <integer>
          #   l4_wd9: <integer>
          #   mf: <value in [disable, enable]>
          #   protocol: <integer>
          #   slink: <integer>
          #   smac_change: <value in [disable, enable]>
          #   sp: <integer>
          #   src_cfi: <value in [disable, enable]>
          #   src_prio: <integer>
          #   src_updt: <value in [disable, enable]>
          #   srcip: <string>
          #   srcipv6: <string>
          #   srcmac: <string>
          #   srcport: <integer>
          #   svid: <integer>
          #   tcp_ack: <value in [disable, enable]>
          #   tcp_cwr: <value in [disable, enable]>
          #   tcp_ece: <value in [disable, enable]>
          #   tcp_fin: <value in [disable, enable]>
          #   tcp_push: <value in [disable, enable]>
          #   tcp_rst: <value in [disable, enable]>
          #   tcp_syn: <value in [disable, enable]>
          #   tcp_urg: <value in [disable, enable]>
          #   tgt_cfi: <value in [disable, enable]>
          #   tgt_prio: <integer>
          #   tgt_updt: <value in [disable, enable]>
          #   tgt_v: <value in [invalid, valid]>
          #   tos: <integer>
          #   tp: <integer>
          #   ttl: <integer>
          #   tvid: <integer>
          #   vdid: <integer>
          # dbg_dump: <integer>
          # mask:
          #   df: <value in [disable, enable]>
          #   dstip: <string>
          #   dstipv6: <string>
          #   dstmac: <string>
          #   dstport: <integer>
          #   ethertype: <string>
          #   ext_tag: <value in [disable, enable]>
          #   frag_off: <integer>
          #   gen_buf_cnt: <integer>
          #   gen_iv: <value in [invalid, valid]>
          #   gen_l3_flags: <integer>
          #   gen_l4_flags: <integer>
          #   gen_pkt_ctrl: <integer>
          #   gen_pri: <integer>
          #   gen_pri_v: <value in [invalid, valid]>
          #   gen_tv: <value in [invalid, valid]>
          #   ihl: <integer>
          #   ip4_id: <integer>
          #   ip6_fl: <integer>
          #   ipver: <integer>
          #   l4_wd10: <integer>
          #   l4_wd11: <integer>
          #   l4_wd8: <integer>
          #   l4_wd9: <integer>
          #   mf: <value in [disable, enable]>
          #   protocol: <integer>
          #   slink: <integer>
          #   smac_change: <value in [disable, enable]>
          #   sp: <integer>
          #   src_cfi: <value in [disable, enable]>
          #   src_prio: <integer>
          #   src_updt: <value in [disable, enable]>
          #   srcip: <string>
          #   srcipv6: <string>
          #   srcmac: <string>
          #   srcport: <integer>
          #   svid: <integer>
          #   tcp_ack: <value in [disable, enable]>
          #   tcp_cwr: <value in [disable, enable]>
          #   tcp_ece: <value in [disable, enable]>
          #   tcp_fin: <value in [disable, enable]>
          #   tcp_push: <value in [disable, enable]>
          #   tcp_rst: <value in [disable, enable]>
          #   tcp_syn: <value in [disable, enable]>
          #   tcp_urg: <value in [disable, enable]>
          #   tgt_cfi: <value in [disable, enable]>
          #   tgt_prio: <integer>
          #   tgt_updt: <value in [disable, enable]>
          #   tgt_v: <value in [invalid, valid]>
          #   tos: <integer>
          #   tp: <integer>
          #   ttl: <integer>
          #   tvid: <integer>
          #   vdid: <integer>
          # mir_act:
          #   vlif: <integer>
          # oid: <integer>
          # pri_act:
          #   priority: <integer>
          #   weight: <integer>
          # sact:
          #   act: <integer>
          #   act_v: <value in [disable, enable]>
          #   bmproc: <integer>
          #   bmproc_v: <value in [disable, enable]>
          #   df_lif: <integer>
          #   df_lif_v: <value in [disable, enable]>
          #   dfr: <integer>
          #   dfr_v: <value in [disable, enable]>
          #   dmac_skip: <integer>
          #   dmac_skip_v: <value in [disable, enable]>
          #   dosen: <integer>
          #   dosen_v: <value in [disable, enable]>
          #   espff_proc: <integer>
          #   espff_proc_v: <value in [disable, enable]>
          #   etype_pid: <integer>
          #   etype_pid_v: <value in [disable, enable]>
          #   frag_proc: <integer>
          #   frag_proc_v: <value in [disable, enable]>
          #   fwd: <integer>
          #   fwd_lif: <integer>
          #   fwd_lif_v: <value in [disable, enable]>
          #   fwd_tvid: <integer>
          #   fwd_tvid_v: <value in [disable, enable]>
          #   fwd_v: <value in [disable, enable]>
          #   icpen: <integer>
          #   icpen_v: <value in [disable, enable]>
          #   igmp_mld_snp: <integer>
          #   igmp_mld_snp_v: <value in [disable, enable]>
          #   learn: <integer>
          #   learn_v: <value in [disable, enable]>
          #   m_srh_ctrl: <integer>
          #   m_srh_ctrl_v: <value in [disable, enable]>
          #   mac_id: <integer>
          #   mac_id_v: <value in [disable, enable]>
          #   mss: <integer>
          #   mss_v: <value in [disable, enable]>
          #   pleen: <integer>
          #   pleen_v: <value in [disable, enable]>
          #   prio_pid: <integer>
          #   prio_pid_v: <value in [disable, enable]>
          #   promis: <integer>
          #   promis_v: <value in [disable, enable]>
          #   rfsh: <integer>
          #   rfsh_v: <value in [disable, enable]>
          #   smac_skip: <integer>
          #   smac_skip_v: <value in [disable, enable]>
          #   tp_smchk_v: <value in [disable, enable]>
          #   tp_smchk: <integer>
          #   tpe_id: <integer>
          #   tpe_id_v: <value in [disable, enable]>
          #   vdm: <integer>
          #   vdm_v: <value in [disable, enable]>
          #   vdom_id: <integer>
          #   vdom_id_v: <value in [disable, enable]>
          #   x_mode: <integer>
          #   x_mode_v: <value in [disable, enable]>
          # tact:
          #   act: <integer>
          #   act_v: <value in [disable, enable]>
          #   fmtuv4_s: <integer>
          #   fmtuv4_s_v: <value in [disable, enable]>
          #   fmtuv6_s: <integer>
          #   fmtuv6_s_v: <value in [disable, enable]>
          #   lnkid: <integer>
          #   lnkid_v: <value in [disable, enable]>
          #   mac_id: <integer>
          #   mac_id_v: <value in [disable, enable]>
          #   mss_t: <integer>
          #   mss_t_v: <value in [disable, enable]>
          #   mtuv4: <integer>
          #   mtuv4_v: <value in [disable, enable]>
          #   mtuv6: <integer>
          #   mtuv6_v: <value in [disable, enable]>
          #   slif_act: <integer>
          #   slif_act_v: <value in [disable, enable]>
          #   sublnkid: <integer>
          #   sublnkid_v: <value in [disable, enable]>
          #   tgtv_act: <integer>
          #   tgtv_act_v: <value in [disable, enable]>
          #   tlif_act: <integer>
          #   tlif_act_v: <value in [disable, enable]>
          #   tpeid: <integer>
          #   tpeid_v: <value in [disable, enable]>
          #   v6fe: <integer>
          #   v6fe_v: <value in [disable, enable]>
          #   vep_en_v: <value in [disable, enable]>
          #   vep_slid: <integer>
          #   vep_slid_v: <value in [disable, enable]>
          #   vep_en: <integer>
          #   xlt_lif: <integer>
          #   xlt_lif_v: <value in [disable, enable]>
          #   xlt_vid: <integer>
          #   xlt_vid_v: <value in [disable, enable]>
          # type: <value in [L2_src_tc, L2_tgt_tc, L2_src_mir, ...]>
          # vid: <integer>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/system/npu/npu-tcam',
        '/pm/config/global/obj/system/npu/npu-tcam'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu_nputcam': {
            'type': 'dict',
            'v_range': [['7.4.2', '']],
            'options': {
                'data': {
                    'v_range': [['7.4.2', '']],
                    'type': 'dict',
                    'options': {
                        'df': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dstip': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'dstipv6': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'dstmac': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'dstport': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ethertype': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'ext-tag': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'frag-off': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-buf-cnt': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-iv': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                        'gen-l3-flags': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-l4-flags': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-pkt-ctrl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-pri': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-pri-v': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                        'gen-tv': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                        'ihl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ip4-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ip6-fl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ipver': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'l4-wd10': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'l4-wd11': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'l4-wd8': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'l4-wd9': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'mf': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'protocol': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'slink': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'smac-change': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sp': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'src-cfi': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'src-prio': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'src-updt': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'srcip': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'srcipv6': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'srcmac': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'srcport': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'svid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tcp-ack': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-cwr': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-ece': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-fin': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-push': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-rst': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-syn': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-urg': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tgt-cfi': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tgt-prio': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tgt-updt': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tgt-v': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                        'tos': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tp': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ttl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tvid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'vdid': {'v_range': [['7.4.2', '']], 'type': 'int'}
                    }
                },
                'dbg-dump': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'mask': {
                    'v_range': [['7.4.2', '']],
                    'type': 'dict',
                    'options': {
                        'df': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dstip': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'dstipv6': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'dstmac': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'dstport': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ethertype': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'ext-tag': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'frag-off': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-buf-cnt': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-iv': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                        'gen-l3-flags': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-l4-flags': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-pkt-ctrl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-pri': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'gen-pri-v': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                        'gen-tv': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                        'ihl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ip4-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ip6-fl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ipver': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'l4-wd10': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'l4-wd11': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'l4-wd8': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'l4-wd9': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'mf': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'protocol': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'slink': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'smac-change': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sp': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'src-cfi': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'src-prio': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'src-updt': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'srcip': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'srcipv6': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'srcmac': {'v_range': [['7.4.2', '']], 'type': 'str'},
                        'srcport': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'svid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tcp-ack': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-cwr': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-ece': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-fin': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-push': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-rst': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-syn': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-urg': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tgt-cfi': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tgt-prio': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tgt-updt': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tgt-v': {'v_range': [['7.4.2', '']], 'choices': ['invalid', 'valid'], 'type': 'str'},
                        'tos': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tp': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'ttl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tvid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'vdid': {'v_range': [['7.4.2', '']], 'type': 'int'}
                    }
                },
                'mir-act': {'v_range': [['7.4.2', '']], 'type': 'dict', 'options': {'vlif': {'v_range': [['7.4.2', '']], 'type': 'int'}}},
                'name': {'v_range': [['7.4.2', '']], 'required': True, 'type': 'str'},
                'oid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'pri-act': {
                    'v_range': [['7.4.2', '']],
                    'type': 'dict',
                    'options': {'priority': {'v_range': [['7.4.2', '']], 'type': 'int'}, 'weight': {'v_range': [['7.4.2', '']], 'type': 'int'}}
                },
                'sact': {
                    'v_range': [['7.4.2', '']],
                    'type': 'dict',
                    'options': {
                        'act': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'act-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bmproc': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'bmproc-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'df-lif': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'df-lif-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dfr': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'dfr-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dmac-skip': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'dmac-skip-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'dosen': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'dosen-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'espff-proc': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'espff-proc-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'etype-pid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'etype-pid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'frag-proc': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'frag-proc-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwd': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'fwd-lif': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'fwd-lif-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwd-tvid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'fwd-tvid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fwd-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'icpen': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'icpen-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'igmp-mld-snp': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'igmp-mld-snp-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'learn': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'learn-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'm-srh-ctrl': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'm-srh-ctrl-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'mac-id-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mss': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'mss-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pleen': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'pleen-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'prio-pid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'prio-pid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'promis': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'promis-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'rfsh': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'rfsh-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'smac-skip': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'smac-skip-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tp-smchk-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tp_smchk': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tpe-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tpe-id-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vdm': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'vdm-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vdom-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'vdom-id-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'x-mode': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'x-mode-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'tact': {
                    'v_range': [['7.4.2', '']],
                    'type': 'dict',
                    'options': {
                        'act': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'act-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fmtuv4-s': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'fmtuv4-s-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fmtuv6-s': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'fmtuv6-s-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'lnkid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'lnkid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mac-id': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'mac-id-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mss-t': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'mss-t-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mtuv4': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'mtuv4-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mtuv6': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'mtuv6-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'slif-act': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'slif-act-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'sublnkid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'sublnkid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tgtv-act': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tgtv-act-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tlif-act': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tlif-act-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tpeid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'tpeid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'v6fe': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'v6fe-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vep-en-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vep-slid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'vep-slid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'vep_en': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'xlt-lif': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'xlt-lif-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'xlt-vid': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'xlt-vid-v': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'type': {
                    'v_range': [['7.4.2', '']],
                    'choices': [
                        'L2_src_tc', 'L2_tgt_tc', 'L2_src_mir', 'L2_tgt_mir', 'L2_src_act', 'L2_tgt_act', 'IPv4_src_tc', 'IPv4_tgt_tc', 'IPv4_src_mir',
                        'IPv4_tgt_mir', 'IPv4_src_act', 'IPv4_tgt_act', 'IPv6_src_tc', 'IPv6_tgt_tc', 'IPv6_src_mir', 'IPv6_tgt_mir', 'IPv6_src_act',
                        'IPv6_tgt_act'
                    ],
                    'type': 'str'
                },
                'vid': {'v_range': [['7.4.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu_nputcam'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
