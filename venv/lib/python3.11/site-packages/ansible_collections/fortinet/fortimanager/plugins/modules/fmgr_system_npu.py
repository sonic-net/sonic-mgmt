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
module: fmgr_system_npu
short_description: Configure NPU attributes.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    system_npu:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            capwap_offload:
                aliases: ['capwap-offload']
                type: str
                description: Enable/disable offloading managed FortiAP and FortiLink CAPWAP sessions.
                choices:
                    - 'disable'
                    - 'enable'
            dedicated_management_affinity:
                aliases: ['dedicated-management-affinity']
                type: str
                description: Affinity setting for management deamons
            dedicated_management_cpu:
                aliases: ['dedicated-management-cpu']
                type: str
                description: Enable to dedicate one CPU for GUI and CLI connections when NPs are busy.
                choices:
                    - 'disable'
                    - 'enable'
            fastpath:
                type: str
                description: Enable/disable NP6 offloading
                choices:
                    - 'disable'
                    - 'enable'
            fp_anomaly:
                aliases: ['fp-anomaly']
                type: dict
                description: Fp anomaly.
                suboptions:
                    esp_minlen_err:
                        aliases: ['esp-minlen-err']
                        type: str
                        description: Invalid IPv4 ESP short packet anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    icmp_csum_err:
                        aliases: ['icmp-csum-err']
                        type: str
                        description: Invalid IPv4 ICMP packet checksum anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    icmp_minlen_err:
                        aliases: ['icmp-minlen-err']
                        type: str
                        description: Invalid IPv4 ICMP short packet anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_csum_err:
                        aliases: ['ipv4-csum-err']
                        type: str
                        description: Invalid IPv4 packet checksum anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_ihl_err:
                        aliases: ['ipv4-ihl-err']
                        type: str
                        description: Invalid IPv4 header length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_len_err:
                        aliases: ['ipv4-len-err']
                        type: str
                        description: Invalid IPv4 packet length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_opt_err:
                        aliases: ['ipv4-opt-err']
                        type: str
                        description: Invalid IPv4 option parsing anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_ttlzero_err:
                        aliases: ['ipv4-ttlzero-err']
                        type: str
                        description: Invalid IPv4 TTL field zero anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_ver_err:
                        aliases: ['ipv4-ver-err']
                        type: str
                        description: Invalid IPv4 header version anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_exthdr_len_err:
                        aliases: ['ipv6-exthdr-len-err']
                        type: str
                        description: Invalid IPv6 packet chain extension header total length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_exthdr_order_err:
                        aliases: ['ipv6-exthdr-order-err']
                        type: str
                        description: Invalid IPv6 packet extension header ordering anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_ihl_err:
                        aliases: ['ipv6-ihl-err']
                        type: str
                        description: Invalid IPv6 packet length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_plen_zero:
                        aliases: ['ipv6-plen-zero']
                        type: str
                        description: Invalid IPv6 packet payload length zero anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_ver_err:
                        aliases: ['ipv6-ver-err']
                        type: str
                        description: Invalid IPv6 packet version anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp_csum_err:
                        aliases: ['tcp-csum-err']
                        type: str
                        description: Invalid IPv4 TCP packet checksum anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp_hlen_err:
                        aliases: ['tcp-hlen-err']
                        type: str
                        description: Invalid IPv4 TCP header length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp_plen_err:
                        aliases: ['tcp-plen-err']
                        type: str
                        description: Invalid IPv4 TCP packet length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp_csum_err:
                        aliases: ['udp-csum-err']
                        type: str
                        description: Invalid IPv4 UDP packet checksum anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp_hlen_err:
                        aliases: ['udp-hlen-err']
                        type: str
                        description: Invalid IPv4 UDP packet header length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp_len_err:
                        aliases: ['udp-len-err']
                        type: str
                        description: Invalid IPv4 UDP packet length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp_plen_err:
                        aliases: ['udp-plen-err']
                        type: str
                        description: Invalid IPv4 UDP packet minimum length anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udplite_cover_err:
                        aliases: ['udplite-cover-err']
                        type: str
                        description: Invalid IPv4 UDP-Lite packet coverage anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udplite_csum_err:
                        aliases: ['udplite-csum-err']
                        type: str
                        description: Invalid IPv4 UDP-Lite packet checksum anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                            - 'allow'
                    unknproto_minlen_err:
                        aliases: ['unknproto-minlen-err']
                        type: str
                        description: Invalid IPv4 L4 unknown protocol short packet anomalies.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp_fin_only:
                        aliases: ['tcp-fin-only']
                        type: str
                        description: TCP SYN flood with only FIN flag set anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optsecurity:
                        aliases: ['ipv4-optsecurity']
                        type: str
                        description: Security option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optralert:
                        aliases: ['ipv6-optralert']
                        type: str
                        description: Router alert option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_syn_fin:
                        aliases: ['tcp-syn-fin']
                        type: str
                        description: TCP SYN flood SYN/FIN flag set anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_proto_err:
                        aliases: ['ipv4-proto-err']
                        type: str
                        description: Invalid layer 4 protocol anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_saddr_err:
                        aliases: ['ipv6-saddr-err']
                        type: str
                        description: Source address as multicast anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    icmp_frag:
                        aliases: ['icmp-frag']
                        type: str
                        description: Layer 3 fragmented packets that could be part of layer 4 ICMP anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optssrr:
                        aliases: ['ipv4-optssrr']
                        type: str
                        description: Strict source record route option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_opthomeaddr:
                        aliases: ['ipv6-opthomeaddr']
                        type: str
                        description: Home address option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    udp_land:
                        aliases: ['udp-land']
                        type: str
                        description: UDP land anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optinvld:
                        aliases: ['ipv6-optinvld']
                        type: str
                        description: Invalid option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_fin_noack:
                        aliases: ['tcp-fin-noack']
                        type: str
                        description: TCP SYN flood with FIN flag set without ACK setting anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_proto_err:
                        aliases: ['ipv6-proto-err']
                        type: str
                        description: Layer 4 invalid protocol anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_land:
                        aliases: ['tcp-land']
                        type: str
                        description: TCP land anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_unknopt:
                        aliases: ['ipv4-unknopt']
                        type: str
                        description: Unknown option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optstream:
                        aliases: ['ipv4-optstream']
                        type: str
                        description: Stream option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optjumbo:
                        aliases: ['ipv6-optjumbo']
                        type: str
                        description: Jumbo options anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    icmp_land:
                        aliases: ['icmp-land']
                        type: str
                        description: ICMP land anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_winnuke:
                        aliases: ['tcp-winnuke']
                        type: str
                        description: TCP WinNuke anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_daddr_err:
                        aliases: ['ipv6-daddr-err']
                        type: str
                        description: Destination address as unspecified or loopback address anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_land:
                        aliases: ['ipv4-land']
                        type: str
                        description: Land anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_opttunnel:
                        aliases: ['ipv6-opttunnel']
                        type: str
                        description: Tunnel encapsulation limit option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_no_flag:
                        aliases: ['tcp-no-flag']
                        type: str
                        description: TCP SYN flood with no flag set anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_land:
                        aliases: ['ipv6-land']
                        type: str
                        description: Land anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optlsrr:
                        aliases: ['ipv4-optlsrr']
                        type: str
                        description: Loose source record route option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_opttimestamp:
                        aliases: ['ipv4-opttimestamp']
                        type: str
                        description: Timestamp option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optrr:
                        aliases: ['ipv4-optrr']
                        type: str
                        description: Record route option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optnsap:
                        aliases: ['ipv6-optnsap']
                        type: str
                        description: Network service access point address option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_unknopt:
                        aliases: ['ipv6-unknopt']
                        type: str
                        description: Unknown option anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_syn_data:
                        aliases: ['tcp-syn-data']
                        type: str
                        description: TCP SYN flood packets with data anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optendpid:
                        aliases: ['ipv6-optendpid']
                        type: str
                        description: End point identification anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    gtpu_plen_err:
                        aliases: ['gtpu-plen-err']
                        type: str
                        description: Gtpu plen err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    vxlan_minlen_err:
                        aliases: ['vxlan-minlen-err']
                        type: str
                        description: Vxlan minlen err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    capwap_minlen_err:
                        aliases: ['capwap-minlen-err']
                        type: str
                        description: Capwap minlen err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    gre_csum_err:
                        aliases: ['gre-csum-err']
                        type: str
                        description: Gre csum err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                            - 'allow'
                    nvgre_minlen_err:
                        aliases: ['nvgre-minlen-err']
                        type: str
                        description: Nvgre minlen err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    sctp_l4len_err:
                        aliases: ['sctp-l4len-err']
                        type: str
                        description: Sctp l4len err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp_hlenvsl4len_err:
                        aliases: ['tcp-hlenvsl4len-err']
                        type: str
                        description: Tcp hlenvsl4len err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    sctp_crc_err:
                        aliases: ['sctp-crc-err']
                        type: str
                        description: Sctp crc err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    sctp_clen_err:
                        aliases: ['sctp-clen-err']
                        type: str
                        description: Sctp clen err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    uesp_minlen_err:
                        aliases: ['uesp-minlen-err']
                        type: str
                        description: Uesp minlen err.
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    sctp_csum_err:
                        aliases: ['sctp-csum-err']
                        type: str
                        description: Invalid IPv4 SCTP checksum anomalies.
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
            gtp_enhanced_cpu_range:
                aliases: ['gtp-enhanced-cpu-range']
                type: str
                description: GTP enhanced CPU range option.
                choices:
                    - '0'
                    - '1'
                    - '2'
            gtp_enhanced_mode:
                aliases: ['gtp-enhanced-mode']
                type: str
                description: Enable/disable GTP enhanced mode.
                choices:
                    - 'disable'
                    - 'enable'
            host_shortcut_mode:
                aliases: ['host-shortcut-mode']
                type: str
                description: Set np6 host shortcut mode.
                choices:
                    - 'bi-directional'
                    - 'host-shortcut'
            htx_gtse_quota:
                aliases: ['htx-gtse-quota']
                type: str
                description: Configure HTX GTSE quota.
                choices:
                    - '100Mbps'
                    - '200Mbps'
                    - '300Mbps'
                    - '400Mbps'
                    - '500Mbps'
                    - '600Mbps'
                    - '700Mbps'
                    - '800Mbps'
                    - '900Mbps'
                    - '1Gbps'
                    - '2Gbps'
                    - '4Gbps'
                    - '8Gbps'
                    - '10Gbps'
            intf_shaping_offload:
                aliases: ['intf-shaping-offload']
                type: str
                description: Enable/disable NPU offload when doing interface-based traffic shaping according to the egress-shaping-profile.
                choices:
                    - 'disable'
                    - 'enable'
            iph_rsvd_re_cksum:
                aliases: ['iph-rsvd-re-cksum']
                type: str
                description: Enable/disable IP checksum re-calculation for packets with iph.
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_dec_subengine_mask:
                aliases: ['ipsec-dec-subengine-mask']
                type: str
                description: IPsec decryption subengine mask
            ipsec_enc_subengine_mask:
                aliases: ['ipsec-enc-subengine-mask']
                type: str
                description: IPsec encryption subengine mask
            ipsec_inbound_cache:
                aliases: ['ipsec-inbound-cache']
                type: str
                description: Enable/disable IPsec inbound cache for anti-replay.
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_mtu_override:
                aliases: ['ipsec-mtu-override']
                type: str
                description: Enable/disable NP6 IPsec MTU override.
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_over_vlink:
                aliases: ['ipsec-over-vlink']
                type: str
                description: Enable/disable IPSEC over vlink.
                choices:
                    - 'disable'
                    - 'enable'
            isf_np_queues:
                aliases: ['isf-np-queues']
                type: dict
                description: Isf np queues.
                suboptions:
                    cos0:
                        type: str
                        description: CoS profile name for CoS 0.
                    cos1:
                        type: str
                        description: CoS profile name for CoS 1.
                    cos2:
                        type: str
                        description: CoS profile name for CoS 2.
                    cos3:
                        type: str
                        description: CoS profile name for CoS 3.
                    cos4:
                        type: str
                        description: CoS profile name for CoS 4.
                    cos5:
                        type: str
                        description: CoS profile name for CoS 5.
                    cos6:
                        type: str
                        description: CoS profile name for CoS 6.
                    cos7:
                        type: str
                        description: CoS profile name for CoS 7.
            lag_out_port_select:
                aliases: ['lag-out-port-select']
                type: str
                description: Enable/disable LAG outgoing port selection based on incoming traffic port.
                choices:
                    - 'disable'
                    - 'enable'
            mcast_session_accounting:
                aliases: ['mcast-session-accounting']
                type: str
                description: Enable/disable traffic accounting for each multicast session through TAE counter.
                choices:
                    - 'disable'
                    - 'session-based'
                    - 'tpe-based'
            np6_cps_optimization_mode:
                aliases: ['np6-cps-optimization-mode']
                type: str
                description: Enable/disable NP6 connection per second
                choices:
                    - 'disable'
                    - 'enable'
            per_session_accounting:
                aliases: ['per-session-accounting']
                type: str
                description: Enable/disable per-session accounting.
                choices:
                    - 'enable'
                    - 'disable'
                    - 'enable-by-log'
                    - 'all-enable'
                    - 'traffic-log-only'
            port_cpu_map:
                aliases: ['port-cpu-map']
                type: list
                elements: dict
                description: Port cpu map.
                suboptions:
                    cpu_core:
                        aliases: ['cpu-core']
                        type: str
                        description: The CPU core to map to an interface.
                    interface:
                        type: str
                        description: The interface to map to a CPU core.
            port_npu_map:
                aliases: ['port-npu-map']
                type: list
                elements: dict
                description: Port npu map.
                suboptions:
                    interface:
                        type: str
                        description: Set npu interface port to NPU group map.
                    npu_group_index:
                        aliases: ['npu-group-index']
                        type: int
                        description: Mapping NPU group index.
            priority_protocol:
                aliases: ['priority-protocol']
                type: dict
                description: Priority protocol.
                suboptions:
                    bfd:
                        type: str
                        description: Enable/disable NPU BFD priority protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    bgp:
                        type: str
                        description: Enable/disable NPU BGP priority protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    slbc:
                        type: str
                        description: Enable/disable NPU SLBC priority protocol.
                        choices:
                            - 'disable'
                            - 'enable'
            qos_mode:
                aliases: ['qos-mode']
                type: str
                description: QoS mode on switch and NP.
                choices:
                    - 'disable'
                    - 'priority'
                    - 'round-robin'
            rdp_offload:
                aliases: ['rdp-offload']
                type: str
                description: Enable/disable rdp offload.
                choices:
                    - 'disable'
                    - 'enable'
            recover_np6_link:
                aliases: ['recover-np6-link']
                type: str
                description: Enable/disable internal link failure check and recovery after boot up.
                choices:
                    - 'disable'
                    - 'enable'
            session_denied_offload:
                aliases: ['session-denied-offload']
                type: str
                description: Enable/disable offloading of denied sessions.
                choices:
                    - 'disable'
                    - 'enable'
            sse_backpressure:
                aliases: ['sse-backpressure']
                type: str
                description: Enable/disable sse backpressure.
                choices:
                    - 'disable'
                    - 'enable'
            strip_clear_text_padding:
                aliases: ['strip-clear-text-padding']
                type: str
                description: Enable/disable stripping clear text padding.
                choices:
                    - 'disable'
                    - 'enable'
            strip_esp_padding:
                aliases: ['strip-esp-padding']
                type: str
                description: Enable/disable stripping ESP padding.
                choices:
                    - 'disable'
                    - 'enable'
            sw_eh_hash:
                aliases: ['sw-eh-hash']
                type: dict
                description: Sw eh hash.
                suboptions:
                    computation:
                        type: str
                        description: Set hashing computation.
                        choices:
                            - 'xor16'
                            - 'xor8'
                            - 'xor4'
                            - 'crc16'
                    destination_ip_lower_16:
                        aliases: ['destination-ip-lower-16']
                        type: str
                        description: Include/exclude destination IP address lower 16 bits.
                        choices:
                            - 'include'
                            - 'exclude'
                    destination_ip_upper_16:
                        aliases: ['destination-ip-upper-16']
                        type: str
                        description: Include/exclude destination IP address upper 16 bits.
                        choices:
                            - 'include'
                            - 'exclude'
                    destination_port:
                        aliases: ['destination-port']
                        type: str
                        description: Include/exclude destination port if TCP/UDP.
                        choices:
                            - 'include'
                            - 'exclude'
                    ip_protocol:
                        aliases: ['ip-protocol']
                        type: str
                        description: Include/exclude IP protocol.
                        choices:
                            - 'include'
                            - 'exclude'
                    netmask_length:
                        aliases: ['netmask-length']
                        type: int
                        description: Network mask length.
                    source_ip_lower_16:
                        aliases: ['source-ip-lower-16']
                        type: str
                        description: Include/exclude source IP address lower 16 bits.
                        choices:
                            - 'include'
                            - 'exclude'
                    source_ip_upper_16:
                        aliases: ['source-ip-upper-16']
                        type: str
                        description: Include/exclude source IP address upper 16 bits.
                        choices:
                            - 'include'
                            - 'exclude'
                    source_port:
                        aliases: ['source-port']
                        type: str
                        description: Include/exclude source port if TCP/UDP.
                        choices:
                            - 'include'
                            - 'exclude'
            sw_np_bandwidth:
                aliases: ['sw-np-bandwidth']
                type: str
                description: Bandwidth from switch to NP.
                choices:
                    - '0G'
                    - '2G'
                    - '4G'
                    - '5G'
                    - '6G'
                    - '7G'
                    - '8G'
                    - '9G'
            switch_np_hash:
                aliases: ['switch-np-hash']
                type: str
                description: Switch-NP trunk port selection Criteria.
                choices:
                    - 'src-ip'
                    - 'dst-ip'
                    - 'src-dst-ip'
            uesp_offload:
                aliases: ['uesp-offload']
                type: str
                description: Enable/disable UDP-encapsulated ESP offload
                choices:
                    - 'disable'
                    - 'enable'
            np_queues:
                aliases: ['np-queues']
                type: dict
                description: Np queues.
                suboptions:
                    ethernet_type:
                        aliases: ['ethernet-type']
                        type: list
                        elements: dict
                        description: Ethernet type.
                        suboptions:
                            name:
                                type: str
                                description: Ethernet Type Name.
                            queue:
                                type: int
                                description: Queue Number.
                            type:
                                type: int
                                description: Ethernet Type.
                            weight:
                                type: int
                                description: Class Weight.
                    ip_protocol:
                        aliases: ['ip-protocol']
                        type: list
                        elements: dict
                        description: Ip protocol.
                        suboptions:
                            name:
                                type: str
                                description: IP Protocol Name.
                            protocol:
                                type: int
                                description: IP Protocol.
                            queue:
                                type: int
                                description: Queue Number.
                            weight:
                                type: int
                                description: Class Weight.
                    ip_service:
                        aliases: ['ip-service']
                        type: list
                        elements: dict
                        description: Ip service.
                        suboptions:
                            dport:
                                type: int
                                description: Destination port.
                            name:
                                type: str
                                description: IP service name.
                            protocol:
                                type: int
                                description: IP protocol.
                            queue:
                                type: int
                                description: Queue number.
                            sport:
                                type: int
                                description: Source port.
                            weight:
                                type: int
                                description: Class weight.
                    profile:
                        type: list
                        elements: dict
                        description: Profile.
                        suboptions:
                            cos0:
                                type: str
                                description: Queue number of CoS 0.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            cos1:
                                type: str
                                description: Queue number of CoS 1.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            cos2:
                                type: str
                                description: Queue number of CoS 2.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            cos3:
                                type: str
                                description: Queue number of CoS 3.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            cos4:
                                type: str
                                description: Queue number of CoS 4.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            cos5:
                                type: str
                                description: Queue number of CoS 5.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            cos6:
                                type: str
                                description: Queue number of CoS 6.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            cos7:
                                type: str
                                description: Queue number of CoS 7.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp0:
                                type: str
                                description: Queue number of DSCP 0.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp1:
                                type: str
                                description: Queue number of DSCP 1.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp10:
                                type: str
                                description: Queue number of DSCP 10.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp11:
                                type: str
                                description: Queue number of DSCP 11.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp12:
                                type: str
                                description: Queue number of DSCP 12.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp13:
                                type: str
                                description: Queue number of DSCP 13.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp14:
                                type: str
                                description: Queue number of DSCP 14.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp15:
                                type: str
                                description: Queue number of DSCP 15.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp16:
                                type: str
                                description: Queue number of DSCP 16.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp17:
                                type: str
                                description: Queue number of DSCP 17.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp18:
                                type: str
                                description: Queue number of DSCP 18.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp19:
                                type: str
                                description: Queue number of DSCP 19.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp2:
                                type: str
                                description: Queue number of DSCP 2.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp20:
                                type: str
                                description: Queue number of DSCP 20.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp21:
                                type: str
                                description: Queue number of DSCP 21.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp22:
                                type: str
                                description: Queue number of DSCP 22.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp23:
                                type: str
                                description: Queue number of DSCP 23.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp24:
                                type: str
                                description: Queue number of DSCP 24.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp25:
                                type: str
                                description: Queue number of DSCP 25.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp26:
                                type: str
                                description: Queue number of DSCP 26.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp27:
                                type: str
                                description: Queue number of DSCP 27.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp28:
                                type: str
                                description: Queue number of DSCP 28.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp29:
                                type: str
                                description: Queue number of DSCP 29.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp3:
                                type: str
                                description: Queue number of DSCP 3.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp30:
                                type: str
                                description: Queue number of DSCP 30.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp31:
                                type: str
                                description: Queue number of DSCP 31.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp32:
                                type: str
                                description: Queue number of DSCP 32.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp33:
                                type: str
                                description: Queue number of DSCP 33.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp34:
                                type: str
                                description: Queue number of DSCP 34.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp35:
                                type: str
                                description: Queue number of DSCP 35.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp36:
                                type: str
                                description: Queue number of DSCP 36.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp37:
                                type: str
                                description: Queue number of DSCP 37.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp38:
                                type: str
                                description: Queue number of DSCP 38.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp39:
                                type: str
                                description: Queue number of DSCP 39.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp4:
                                type: str
                                description: Queue number of DSCP 4.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp40:
                                type: str
                                description: Queue number of DSCP 40.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp41:
                                type: str
                                description: Queue number of DSCP 41.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp42:
                                type: str
                                description: Queue number of DSCP 42.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp43:
                                type: str
                                description: Queue number of DSCP 43.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp44:
                                type: str
                                description: Queue number of DSCP 44.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp45:
                                type: str
                                description: Queue number of DSCP 45.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp46:
                                type: str
                                description: Queue number of DSCP 46.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp47:
                                type: str
                                description: Queue number of DSCP 47.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp48:
                                type: str
                                description: Queue number of DSCP 48.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp49:
                                type: str
                                description: Queue number of DSCP 49.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp5:
                                type: str
                                description: Queue number of DSCP 5.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp50:
                                type: str
                                description: Queue number of DSCP 50.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp51:
                                type: str
                                description: Queue number of DSCP 51.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp52:
                                type: str
                                description: Queue number of DSCP 52.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp53:
                                type: str
                                description: Queue number of DSCP 53.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp54:
                                type: str
                                description: Queue number of DSCP 54.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp55:
                                type: str
                                description: Queue number of DSCP 55.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp56:
                                type: str
                                description: Queue number of DSCP 56.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp57:
                                type: str
                                description: Queue number of DSCP 57.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp58:
                                type: str
                                description: Queue number of DSCP 58.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp59:
                                type: str
                                description: Queue number of DSCP 59.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp6:
                                type: str
                                description: Queue number of DSCP 6.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp60:
                                type: str
                                description: Queue number of DSCP 60.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp61:
                                type: str
                                description: Queue number of DSCP 61.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp62:
                                type: str
                                description: Queue number of DSCP 62.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp63:
                                type: str
                                description: Queue number of DSCP 63.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp7:
                                type: str
                                description: Queue number of DSCP 7.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp8:
                                type: str
                                description: Queue number of DSCP 8.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            dscp9:
                                type: str
                                description: Queue number of DSCP 9.
                                choices:
                                    - 'queue0'
                                    - 'queue1'
                                    - 'queue2'
                                    - 'queue3'
                                    - 'queue4'
                                    - 'queue5'
                                    - 'queue6'
                                    - 'queue7'
                            id:
                                type: int
                                description: Profile ID.
                            type:
                                type: str
                                description: Profile type.
                                choices:
                                    - 'cos'
                                    - 'dscp'
                            weight:
                                type: int
                                description: Class weight.
                    scheduler:
                        type: list
                        elements: dict
                        description: Scheduler.
                        suboptions:
                            mode:
                                type: str
                                description: Scheduler mode.
                                choices:
                                    - 'none'
                                    - 'priority'
                                    - 'round-robin'
                            name:
                                type: str
                                description: Scheduler name.
                    custom_etype_lookup:
                        aliases: ['custom-etype-lookup']
                        type: str
                        description: Enable/Disable np-queue lookup for custom Ethernet Types.
                        choices:
                            - 'disable'
                            - 'enable'
            udp_timeout_profile:
                aliases: ['udp-timeout-profile']
                type: list
                elements: dict
                description: Udp timeout profile.
                suboptions:
                    id:
                        type: int
                        description: Timeout profile ID
                    udp_idle:
                        aliases: ['udp-idle']
                        type: int
                        description: Set UDP idle timeout
            qtm_buf_mode:
                aliases: ['qtm-buf-mode']
                type: str
                description: QTM channel configuration for packet buffer.
                choices:
                    - '6ch'
                    - '4ch'
            default_qos_type:
                aliases: ['default-qos-type']
                type: str
                description: Set default QoS type.
                choices:
                    - 'policing'
                    - 'shaping'
                    - 'policing-enhanced'
            tcp_rst_timeout:
                aliases: ['tcp-rst-timeout']
                type: int
                description: TCP RST timeout in seconds
            ipsec_local_uesp_port:
                aliases: ['ipsec-local-uesp-port']
                type: int
                description: Ipsec local uesp port.
            htab_dedi_queue_nr:
                aliases: ['htab-dedi-queue-nr']
                type: int
                description: Set the number of dedicate queue for hash table messages.
            double_level_mcast_offload:
                aliases: ['double-level-mcast-offload']
                type: str
                description: Enable double level mcast offload.
                choices:
                    - 'disable'
                    - 'enable'
            dse_timeout:
                aliases: ['dse-timeout']
                type: int
                description: DSE timeout in seconds
            ippool_overload_low:
                aliases: ['ippool-overload-low']
                type: int
                description: Low threshold for overload ippool port reuse
            pba_eim:
                aliases: ['pba-eim']
                type: str
                description: Configure option for PBA
                choices:
                    - 'disallow'
                    - 'allow'
            policy_offload_level:
                aliases: ['policy-offload-level']
                type: str
                description: Configure firewall policy offload level
                choices:
                    - 'disable'
                    - 'dos-offload'
                    - 'full-offload'
            max_session_timeout:
                aliases: ['max-session-timeout']
                type: int
                description: Maximum time interval for refreshing NPU-offloaded sessions
            port_path_option:
                aliases: ['port-path-option']
                type: dict
                description: Port path option.
                suboptions:
                    ports_using_npu:
                        aliases: ['ports-using-npu']
                        type: raw
                        description: (list) Set ha/aux ports to handle traffic with NPU
            vlan_lookup_cache:
                aliases: ['vlan-lookup-cache']
                type: str
                description: Enable/disable vlan lookup cache
                choices:
                    - 'disable'
                    - 'enable'
            dos_options:
                aliases: ['dos-options']
                type: dict
                description: Dos options.
                suboptions:
                    npu_dos_meter_mode:
                        aliases: ['npu-dos-meter-mode']
                        type: str
                        description: Set DoS meter NPU offloading mode.
                        choices:
                            - 'local'
                            - 'global'
                    npu_dos_synproxy_mode:
                        aliases: ['npu-dos-synproxy-mode']
                        type: str
                        description: Set NPU DoS SYNPROXY mode.
                        choices:
                            - 'synack2ack'
                            - 'pass-synack'
                    npu_dos_tpe_mode:
                        aliases: ['npu-dos-tpe-mode']
                        type: str
                        description: Enable/disable insertion of DoS meter ID to session table.
                        choices:
                            - 'disable'
                            - 'enable'
            hash_tbl_spread:
                aliases: ['hash-tbl-spread']
                type: str
                description: Enable/disable hash table entry spread
                choices:
                    - 'disable'
                    - 'enable'
            tcp_timeout_profile:
                aliases: ['tcp-timeout-profile']
                type: list
                elements: dict
                description: Tcp timeout profile.
                suboptions:
                    close_wait:
                        aliases: ['close-wait']
                        type: int
                        description: Set close-wait timeout
                    fin_wait:
                        aliases: ['fin-wait']
                        type: int
                        description: Set fin-wait timeout
                    id:
                        type: int
                        description: Timeout profile ID
                    syn_sent:
                        aliases: ['syn-sent']
                        type: int
                        description: Set syn-sent timeout
                    syn_wait:
                        aliases: ['syn-wait']
                        type: int
                        description: Set syn-wait timeout
                    tcp_idle:
                        aliases: ['tcp-idle']
                        type: int
                        description: Set TCP establish timeout
                    time_wait:
                        aliases: ['time-wait']
                        type: int
                        description: Set time-wait timeout
            ip_reassembly:
                aliases: ['ip-reassembly']
                type: dict
                description: Ip reassembly.
                suboptions:
                    max_timeout:
                        aliases: ['max-timeout']
                        type: int
                        description: Maximum timeout value for IP reassembly
                    min_timeout:
                        aliases: ['min-timeout']
                        type: int
                        description: Minimum timeout value for IP reassembly
                    status:
                        type: str
                        description: Set IP reassembly processing status.
                        choices:
                            - 'disable'
                            - 'enable'
            gtp_support:
                aliases: ['gtp-support']
                type: str
                description: Enable/Disable NP7 GTP support
                choices:
                    - 'disable'
                    - 'enable'
            htx_icmp_csum_chk:
                aliases: ['htx-icmp-csum-chk']
                type: str
                description: Set HTX icmp csum checking mode.
                choices:
                    - 'pass'
                    - 'drop'
            hpe:
                type: dict
                description: Hpe.
                suboptions:
                    all_protocol:
                        aliases: ['all-protocol']
                        type: int
                        description: Maximum packet rate of each host queue except high priority traffic
                    arp_max:
                        aliases: ['arp-max']
                        type: int
                        description: Maximum ARP packet rate
                    enable_shaper:
                        aliases: ['enable-shaper']
                        type: str
                        description: Enable/Disable NPU Host Protection Engine
                        choices:
                            - 'disable'
                            - 'enable'
                    esp_max:
                        aliases: ['esp-max']
                        type: int
                        description: Maximum ESP packet rate
                    high_priority:
                        aliases: ['high-priority']
                        type: int
                        description: Maximum packet rate for high priority traffic packets
                    icmp_max:
                        aliases: ['icmp-max']
                        type: int
                        description: Maximum ICMP packet rate
                    ip_frag_max:
                        aliases: ['ip-frag-max']
                        type: int
                        description: Maximum fragmented IP packet rate
                    ip_others_max:
                        aliases: ['ip-others-max']
                        type: int
                        description: Maximum IP packet rate for other packets
                    l2_others_max:
                        aliases: ['l2-others-max']
                        type: int
                        description: Maximum L2 packet rate for L2 packets that are not ARP packets
                    pri_type_max:
                        aliases: ['pri-type-max']
                        type: int
                        description: Maximum overflow rate of priority type traffic
                    sctp_max:
                        aliases: ['sctp-max']
                        type: int
                        description: Maximum SCTP packet rate
                    tcp_max:
                        aliases: ['tcp-max']
                        type: int
                        description: Maximum TCP packet rate
                    tcpfin_rst_max:
                        aliases: ['tcpfin-rst-max']
                        type: int
                        description: Maximum TCP carries FIN or RST flags packet rate
                    tcpsyn_ack_max:
                        aliases: ['tcpsyn-ack-max']
                        type: int
                        description: Maximum TCP carries SYN and ACK flags packet rate
                    tcpsyn_max:
                        aliases: ['tcpsyn-max']
                        type: int
                        description: Maximum TCP SYN packet rate
                    udp_max:
                        aliases: ['udp-max']
                        type: int
                        description: Maximum UDP packet rate
                    enable_queue_shaper:
                        aliases: ['enable-queue-shaper']
                        type: str
                        description: Enable/Disable NPU host protection engine
                        choices:
                            - 'disable'
                            - 'enable'
                    exception_code:
                        aliases: ['exception-code']
                        type: int
                        description: Maximum exception code rate of traffic
                    fragment_with_sess:
                        aliases: ['fragment-with-sess']
                        type: int
                        description: Maximum fragment with session rate of traffic
                    fragment_without_session:
                        aliases: ['fragment-without-session']
                        type: int
                        description: Maximum fragment without session rate of traffic
                    queue_shaper_max:
                        aliases: ['queue-shaper-max']
                        type: int
                        description: Maximum per queue byte rate of traffic
            dsw_dts_profile:
                aliases: ['dsw-dts-profile']
                type: list
                elements: dict
                description: Dsw dts profile.
                suboptions:
                    action:
                        type: str
                        description: Set NPU DSW DTS profile action.
                        choices:
                            - 'wait'
                            - 'drop'
                            - 'drop_tmr_0'
                            - 'drop_tmr_1'
                            - 'enque'
                            - 'enque_0'
                            - 'enque_1'
                    min_limit:
                        aliases: ['min-limit']
                        type: int
                        description: Set NPU DSW DTS profile min-limt.
                    profile_id:
                        aliases: ['profile-id']
                        type: int
                        description: Set NPU DSW DTS profile profile id.
                    step:
                        type: int
                        description: Set NPU DSW DTS profile step.
            hash_config:
                aliases: ['hash-config']
                type: str
                description: Configure NPU trunk hash.
                choices:
                    - '5-tuple'
                    - 'src-ip'
                    - 'src-dst-ip'
            ipsec_ob_np_sel:
                aliases: ['ipsec-ob-np-sel']
                type: str
                description: IPsec NP selection for OB SA offloading.
                choices:
                    - 'RR'
                    - 'rr'
                    - 'Packet'
                    - 'Hash'
            napi_break_interval:
                aliases: ['napi-break-interval']
                type: int
                description: NAPI break interval
            background_sse_scan:
                aliases: ['background-sse-scan']
                type: dict
                description: Background sse scan.
                suboptions:
                    scan:
                        type: str
                        description: Enable/disable background SSE scan by driver thread
                        choices:
                            - 'disable'
                            - 'enable'
                    stats_update_interval:
                        aliases: ['stats-update-interval']
                        type: int
                        description: Stats update interval
                    udp_keepalive_interval:
                        aliases: ['udp-keepalive-interval']
                        type: int
                        description: UDP keepalive interval
                    scan_stale:
                        aliases: ['scan-stale']
                        type: int
                        description: Configure scanning of active or stale sessions
                    scan_vt:
                        aliases: ['scan-vt']
                        type: int
                        description: Select version/type to scan
                    stats_qual_access:
                        aliases: ['stats-qual-access']
                        type: int
                        description: Statistics update access qualification in seconds
                    stats_qual_duration:
                        aliases: ['stats-qual-duration']
                        type: int
                        description: Statistics update duration qualification in seconds
                    udp_qual_access:
                        aliases: ['udp-qual-access']
                        type: int
                        description: UDP keepalive access qualification in seconds
                    udp_qual_duration:
                        aliases: ['udp-qual-duration']
                        type: int
                        description: UDP keepalive duration qualification in seconds
            inbound_dscp_copy_port:
                aliases: ['inbound-dscp-copy-port']
                type: raw
                description: (list) Physical interfaces that support inbound-dscp-copy.
            session_acct_interval:
                aliases: ['session-acct-interval']
                type: int
                description: Session accounting update interval
            htab_msg_queue:
                aliases: ['htab-msg-queue']
                type: str
                description: Set hash table message queue mode.
                choices:
                    - 'idle'
                    - 'data'
                    - 'dedicated'
            dsw_queue_dts_profile:
                aliases: ['dsw-queue-dts-profile']
                type: list
                elements: dict
                description: Dsw queue dts profile.
                suboptions:
                    iport:
                        type: str
                        description: Set NPU DSW DTS in port.
                        choices:
                            - 'EIF0'
                            - 'eif0'
                            - 'EIF1'
                            - 'eif1'
                            - 'EIF2'
                            - 'eif2'
                            - 'EIF3'
                            - 'eif3'
                            - 'EIF4'
                            - 'eif4'
                            - 'EIF5'
                            - 'eif5'
                            - 'EIF6'
                            - 'eif6'
                            - 'EIF7'
                            - 'eif7'
                            - 'HTX0'
                            - 'htx0'
                            - 'HTX1'
                            - 'htx1'
                            - 'SSE0'
                            - 'sse0'
                            - 'SSE1'
                            - 'sse1'
                            - 'SSE2'
                            - 'sse2'
                            - 'SSE3'
                            - 'sse3'
                            - 'RLT'
                            - 'rlt'
                            - 'DFR'
                            - 'dfr'
                            - 'IPSECI'
                            - 'ipseci'
                            - 'IPSECO'
                            - 'ipseco'
                            - 'IPTI'
                            - 'ipti'
                            - 'IPTO'
                            - 'ipto'
                            - 'VEP0'
                            - 'vep0'
                            - 'VEP2'
                            - 'vep2'
                            - 'VEP4'
                            - 'vep4'
                            - 'VEP6'
                            - 'vep6'
                            - 'IVS'
                            - 'ivs'
                            - 'L2TI1'
                            - 'l2ti1'
                            - 'L2TO'
                            - 'l2to'
                            - 'L2TI0'
                            - 'l2ti0'
                            - 'PLE'
                            - 'ple'
                            - 'SPATH'
                            - 'spath'
                            - 'QTM'
                            - 'qtm'
                    name:
                        type: str
                        description: Name.
                    oport:
                        type: str
                        description: Set NPU DSW DTS out port.
                        choices:
                            - 'EIF0'
                            - 'eif0'
                            - 'EIF1'
                            - 'eif1'
                            - 'EIF2'
                            - 'eif2'
                            - 'EIF3'
                            - 'eif3'
                            - 'EIF4'
                            - 'eif4'
                            - 'EIF5'
                            - 'eif5'
                            - 'EIF6'
                            - 'eif6'
                            - 'EIF7'
                            - 'eif7'
                            - 'HRX'
                            - 'hrx'
                            - 'SSE0'
                            - 'sse0'
                            - 'SSE1'
                            - 'sse1'
                            - 'SSE2'
                            - 'sse2'
                            - 'SSE3'
                            - 'sse3'
                            - 'RLT'
                            - 'rlt'
                            - 'DFR'
                            - 'dfr'
                            - 'IPSECI'
                            - 'ipseci'
                            - 'IPSECO'
                            - 'ipseco'
                            - 'IPTI'
                            - 'ipti'
                            - 'IPTO'
                            - 'ipto'
                            - 'VEP0'
                            - 'vep0'
                            - 'VEP2'
                            - 'vep2'
                            - 'VEP4'
                            - 'vep4'
                            - 'VEP6'
                            - 'vep6'
                            - 'IVS'
                            - 'ivs'
                            - 'L2TI1'
                            - 'l2ti1'
                            - 'L2TO'
                            - 'l2to'
                            - 'L2TI0'
                            - 'l2ti0'
                            - 'PLE'
                            - 'ple'
                            - 'SYNK'
                            - 'sync'
                            - 'NSS'
                            - 'nss'
                            - 'TSK'
                            - 'tsk'
                            - 'QTM'
                            - 'qtm'
                            - 'l2tO'
                    profile_id:
                        aliases: ['profile-id']
                        type: int
                        description: Set NPU DSW DTS profile ID.
                    queue_select:
                        aliases: ['queue-select']
                        type: int
                        description: Set NPU DSW DTS queue ID select
            hw_ha_scan_interval:
                aliases: ['hw-ha-scan-interval']
                type: int
                description: HW HA periodical scan interval in seconds
            ippool_overload_high:
                aliases: ['ippool-overload-high']
                type: int
                description: High threshold for overload ippool port reuse
            nat46_force_ipv4_packet_forwarding:
                aliases: ['nat46-force-ipv4-packet-forwarding']
                type: str
                description: Enable/disable mandatory IPv4 packet forwarding in nat46.
                choices:
                    - 'disable'
                    - 'enable'
            prp_port_out:
                aliases: ['prp-port-out']
                type: raw
                description: (list or str) Egress port configured to allow the PRP trailer not be stripped off when the PRP packets go out.
            isf_np_rx_tr_distr:
                aliases: ['isf-np-rx-tr-distr']
                type: str
                description: Select ISF NP Rx trunk distribution
                choices:
                    - 'port-flow'
                    - 'round-robin'
                    - 'randomized'
            mcast_session_counting6:
                aliases: ['mcast-session-counting6']
                type: str
                description: Enable/disable traffic accounting for each multicast session6 through TAE counter.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'session-based'
                    - 'tpe-based'
            prp_port_in:
                aliases: ['prp-port-in']
                type: raw
                description: (list or str) Ingress port configured to allow the PRP trailer not be stripped off when the PRP packets come in.
            rps_mode:
                aliases: ['rps-mode']
                type: str
                description: Enable/disable receive packet steering
                choices:
                    - 'disable'
                    - 'enable'
            per_policy_accounting:
                aliases: ['per-policy-accounting']
                type: str
                description: Set per-policy accounting.
                choices:
                    - 'disable'
                    - 'enable'
            mcast_session_counting:
                aliases: ['mcast-session-counting']
                type: str
                description: Mcast session counting.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'session-based'
                    - 'tpe-based'
            inbound_dscp_copy:
                aliases: ['inbound-dscp-copy']
                type: str
                description: Enable/disable copying the DSCP field from outer IP header to inner IP Header.
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_host_dfclr:
                aliases: ['ipsec-host-dfclr']
                type: str
                description: Enable/disable DF clearing of NP4lite host IPsec offload.
                choices:
                    - 'disable'
                    - 'enable'
            process_icmp_by_host:
                aliases: ['process-icmp-by-host']
                type: str
                description: Enable/disable process ICMP by host when received from IPsec tunnel and payload size
                choices:
                    - 'disable'
                    - 'enable'
            dedicated_tx_npu:
                aliases: ['dedicated-tx-npu']
                type: str
                description: Enable/disable dedication of 3rd NPU for slow path TX.
                choices:
                    - 'disable'
                    - 'enable'
            ull_port_mode:
                aliases: ['ull-port-mode']
                type: str
                description: Set ULL ports speed to 10G/25G
                choices:
                    - '10G'
                    - '25G'
            sse_ha_scan:
                aliases: ['sse-ha-scan']
                type: dict
                description: Sse ha scan.
                suboptions:
                    gap:
                        type: int
                        description: Scanning message gap
                    max_session_cnt:
                        aliases: ['max-session-cnt']
                        type: int
                        description: If the session count
                    min_duration:
                        aliases: ['min-duration']
                        type: int
                        description: Scanning filter for minimum duration of the session.
            hash_ipv6_sel:
                aliases: ['hash-ipv6-sel']
                type: int
                description: Select which 4bytes of the IPv6 address are used for traffic hash
            ip_fragment_offload:
                aliases: ['ip-fragment-offload']
                type: str
                description: Enable/disable NP7 NPU IP fragment offload.
                choices:
                    - 'disable'
                    - 'enable'
            ple_non_syn_tcp_action:
                aliases: ['ple-non-syn-tcp-action']
                type: str
                description: Configure action for the PLE to take on TCP packets that have the SYN field unset.
                choices:
                    - 'forward'
                    - 'drop'
            npu_group_effective_scope:
                aliases: ['npu-group-effective-scope']
                type: int
                description: Npu-group-effective-scope defines under which npu-group cmds such as list/purge will be excecuted.
            ipsec_STS_timeout:
                aliases: ['ipsec-STS-timeout']
                type: str
                description: Set NP7Lite IPsec STS msg timeout.
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '6'
                    - '7'
                    - '8'
                    - '9'
                    - '10'
            ipsec_throughput_msg_frequency:
                aliases: ['ipsec-throughput-msg-frequency']
                type: str
                description: Set NP7Lite IPsec throughput msg frequency
                choices:
                    - 'disable'
                    - '32KB'
                    - '64KB'
                    - '128KB'
                    - '256KB'
                    - '512KB'
                    - '1MB'
                    - '2MB'
                    - '4MB'
                    - '8MB'
                    - '16MB'
                    - '32MB'
                    - '64MB'
                    - '128MB'
                    - '256MB'
                    - '512MB'
                    - '1GB'
            ipt_STS_timeout:
                aliases: ['ipt-STS-timeout']
                type: str
                description: Set NP7Lite IPT STS msg timeout.
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '6'
                    - '7'
                    - '8'
                    - '9'
                    - '10'
            ipt_throughput_msg_frequency:
                aliases: ['ipt-throughput-msg-frequency']
                type: str
                description: Set NP7Lite IPT throughput msg frequency
                choices:
                    - 'disable'
                    - '32KB'
                    - '64KB'
                    - '128KB'
                    - '256KB'
                    - '512KB'
                    - '1MB'
                    - '2MB'
                    - '4MB'
                    - '8MB'
                    - '16MB'
                    - '32MB'
                    - '64MB'
                    - '128MB'
                    - '256MB'
                    - '512MB'
                    - '1GB'
            default_tcp_refresh_dir:
                aliases: ['default-tcp-refresh-dir']
                type: str
                description: Default SSE timeout TCP refresh direction.
                choices:
                    - 'both'
                    - 'outgoing'
                    - 'incoming'
            default_udp_refresh_dir:
                aliases: ['default-udp-refresh-dir']
                type: str
                description: Default SSE timeout UDP refresh direction.
                choices:
                    - 'both'
                    - 'outgoing'
                    - 'incoming'
            nss_threads_option:
                aliases: ['nss-threads-option']
                type: str
                description: Configure thread options for the NP7s NSS module.
                choices:
                    - '4t-eif'
                    - '4t-noeif'
                    - '2t'
            prp_session_clear_mode:
                aliases: ['prp-session-clear-mode']
                type: str
                description: PRP session clear mode for excluded ip sessions.
                choices:
                    - 'blocking'
                    - 'non-blocking'
                    - 'do-not-clear'
            shaping_stats:
                aliases: ['shaping-stats']
                type: str
                description: Enable/disable NP7 traffic shaping statistics
                choices:
                    - 'disable'
                    - 'enable'
            sw_tr_hash:
                aliases: ['sw-tr-hash']
                type: dict
                description: Sw tr hash.
                suboptions:
                    draco15:
                        type: str
                        description: Enable/disable DRACO15 hashing.
                        choices:
                            - 'disable'
                            - 'enable'
                    tcp_udp_port:
                        aliases: ['tcp-udp-port']
                        type: str
                        description: Include/exclude TCP/UDP source and destination port for unicast trunk traffic.
                        choices:
                            - 'include'
                            - 'exclude'
            pba_port_select_mode:
                aliases: ['pba-port-select-mode']
                type: str
                description: Port selection mode for PBA IP pool.
                choices:
                    - 'random'
                    - 'direct'
            spa_port_select_mode:
                aliases: ['spa-port-select-mode']
                type: str
                description: Port selection mode for SPA IP pool.
                choices:
                    - 'random'
                    - 'direct'
            split_ipsec_engines:
                aliases: ['split-ipsec-engines']
                type: str
                description: Enable/disable Split IPsec Engines.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel_over_vlink:
                aliases: ['tunnel-over-vlink']
                type: str
                description: Enable/disable selection of which NP6 chip the tunnel uses
                choices:
                    - 'disable'
                    - 'enable'
            max_receive_unit:
                aliases: ['max-receive-unit']
                type: int
                description: Set the maximum packet size for receive, larger packets will be silently dropped.
            npu_tcam:
                aliases: ['npu-tcam']
                type: list
                elements: dict
                description: Npu tcam.
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
            icmp_rate_ctrl:
                aliases: ['icmp-rate-ctrl']
                type: dict
                description: Icmp rate ctrl.
                suboptions:
                    icmp_v4_bucket_size:
                        aliases: ['icmp-v4-bucket-size']
                        type: int
                        description: Bucket size used in the token bucket algorithm for controlling the flow of ICMPv4 packets
                    icmp_v4_rate:
                        aliases: ['icmp-v4-rate']
                        type: int
                        description: Average rate of ICMPv4 packets that allowed to be generated per second
                    icmp_v6_bucket_size:
                        aliases: ['icmp-v6-bucket-size']
                        type: int
                        description: Bucket size used in the token bucket algorithm for controlling the flow of ICMPv6 packets
                    icmp_v6_rate:
                        aliases: ['icmp-v6-rate']
                        type: int
                        description: Average rate of ICMPv6 packets that allowed to be generated per second
            vxlan_offload:
                aliases: ['vxlan-offload']
                type: str
                description: Enable/disable offloading vxlan.
                choices:
                    - 'disable'
                    - 'enable'
            icmp_error_rate_ctrl:
                aliases: ['icmp-error-rate-ctrl']
                type: dict
                description: Icmp error rate ctrl.
                suboptions:
                    icmpv4_error_bucket_size:
                        aliases: ['icmpv4-error-bucket-size']
                        type: int
                        description: Bucket size used in the token bucket algorithm for controlling the flow of ICMPv4 error packets
                    icmpv4_error_rate:
                        aliases: ['icmpv4-error-rate']
                        type: int
                        description: Average rate of ICMPv4 error packets that allowed to be generated per second
                    icmpv4_error_rate_limit:
                        aliases: ['icmpv4-error-rate-limit']
                        type: str
                        description: Enable to limit the ICMPv4 error packets generated by this FortiGate.
                        choices:
                            - 'disable'
                            - 'enable'
                    icmpv6_error_bucket_size:
                        aliases: ['icmpv6-error-bucket-size']
                        type: int
                        description: Bucket size used in the token bucket algorithm for controlling the flow of ICMPv6 error packets
                    icmpv6_error_rate:
                        aliases: ['icmpv6-error-rate']
                        type: int
                        description: Average rate of ICMPv6 error packets that allowed to be generated per second
                    icmpv6_error_rate_limit:
                        aliases: ['icmpv6-error-rate-limit']
                        type: str
                        description: Enable to limit the ICMPv6 error packets generated by this FortiGate.
                        choices:
                            - 'disable'
                            - 'enable'
            ipv4_session_quota:
                aliases: ['ipv4-session-quota']
                type: str
                description: Enable/Disable NoNAT IPv4 session quota for hyperscale VDOMs.
                choices:
                    - 'disable'
                    - 'enable'
            ipv4_session_quota_high:
                aliases: ['ipv4-session-quota-high']
                type: int
                description: Configure NoNAT IPv4 session quota high threshold.
            ipv4_session_quota_low:
                aliases: ['ipv4-session-quota-low']
                type: int
                description: Configure NoNAT IPv4 session quota low threshold.
            ipv6_prefix_session_quota:
                aliases: ['ipv6-prefix-session-quota']
                type: str
                description: Enable/Disable hardware IPv6 /64 prefix session quota for hyperscale VDOMs.
                choices:
                    - 'disable'
                    - 'enable'
            ipv6_prefix_session_quota_high:
                aliases: ['ipv6-prefix-session-quota-high']
                type: int
                description: Configure IPv6 prefix session quota high threshold.
            ipv6_prefix_session_quota_low:
                aliases: ['ipv6-prefix-session-quota-low']
                type: int
                description: Configure IPv6 prefix session quota low threshold.
            dedicated_lacp_queue:
                aliases: ['dedicated-lacp-queue']
                type: str
                description: Enable to dedicate one HIF queue for LACP.
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_ordering:
                aliases: ['ipsec-ordering']
                type: str
                description: Enable/disable IPsec ordering.
                choices:
                    - 'disable'
                    - 'enable'
            sw_np_pause:
                aliases: ['sw-np-pause']
                type: str
                description: Enable SP5 tx pause and marvell rx receive pause, for sw uplink only.
                choices:
                    - 'disable'
                    - 'enable'
            sw_np_rate:
                aliases: ['sw-np-rate']
                type: int
                description: Bandwidth from switch to NP, for sw uplink port.
            sw_np_rate_unit:
                aliases: ['sw-np-rate-unit']
                type: str
                description: Unit for bandwidth from switch to NP, for sw uplink port.
                choices:
                    - 'mbps'
                    - 'pps'
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
    - name: Configure NPU attributes.
      fortinet.fortimanager.fmgr_system_npu:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        system_npu:
          # capwap_offload: <value in [disable, enable]>
          # dedicated_management_affinity: <string>
          # dedicated_management_cpu: <value in [disable, enable]>
          # fastpath: <value in [disable, enable]>
          # fp_anomaly:
          #   esp_minlen_err: <value in [drop, trap-to-host]>
          #   icmp_csum_err: <value in [drop, trap-to-host]>
          #   icmp_minlen_err: <value in [drop, trap-to-host]>
          #   ipv4_csum_err: <value in [drop, trap-to-host]>
          #   ipv4_ihl_err: <value in [drop, trap-to-host]>
          #   ipv4_len_err: <value in [drop, trap-to-host]>
          #   ipv4_opt_err: <value in [drop, trap-to-host]>
          #   ipv4_ttlzero_err: <value in [drop, trap-to-host]>
          #   ipv4_ver_err: <value in [drop, trap-to-host]>
          #   ipv6_exthdr_len_err: <value in [drop, trap-to-host]>
          #   ipv6_exthdr_order_err: <value in [drop, trap-to-host]>
          #   ipv6_ihl_err: <value in [drop, trap-to-host]>
          #   ipv6_plen_zero: <value in [drop, trap-to-host]>
          #   ipv6_ver_err: <value in [drop, trap-to-host]>
          #   tcp_csum_err: <value in [drop, trap-to-host]>
          #   tcp_hlen_err: <value in [drop, trap-to-host]>
          #   tcp_plen_err: <value in [drop, trap-to-host]>
          #   udp_csum_err: <value in [drop, trap-to-host]>
          #   udp_hlen_err: <value in [drop, trap-to-host]>
          #   udp_len_err: <value in [drop, trap-to-host]>
          #   udp_plen_err: <value in [drop, trap-to-host]>
          #   udplite_cover_err: <value in [drop, trap-to-host]>
          #   udplite_csum_err: <value in [drop, trap-to-host, allow]>
          #   unknproto_minlen_err: <value in [drop, trap-to-host]>
          #   tcp_fin_only: <value in [allow, drop, trap-to-host]>
          #   ipv4_optsecurity: <value in [allow, drop, trap-to-host]>
          #   ipv6_optralert: <value in [allow, drop, trap-to-host]>
          #   tcp_syn_fin: <value in [allow, drop, trap-to-host]>
          #   ipv4_proto_err: <value in [allow, drop, trap-to-host]>
          #   ipv6_saddr_err: <value in [allow, drop, trap-to-host]>
          #   icmp_frag: <value in [allow, drop, trap-to-host]>
          #   ipv4_optssrr: <value in [allow, drop, trap-to-host]>
          #   ipv6_opthomeaddr: <value in [allow, drop, trap-to-host]>
          #   udp_land: <value in [allow, drop, trap-to-host]>
          #   ipv6_optinvld: <value in [allow, drop, trap-to-host]>
          #   tcp_fin_noack: <value in [allow, drop, trap-to-host]>
          #   ipv6_proto_err: <value in [allow, drop, trap-to-host]>
          #   tcp_land: <value in [allow, drop, trap-to-host]>
          #   ipv4_unknopt: <value in [allow, drop, trap-to-host]>
          #   ipv4_optstream: <value in [allow, drop, trap-to-host]>
          #   ipv6_optjumbo: <value in [allow, drop, trap-to-host]>
          #   icmp_land: <value in [allow, drop, trap-to-host]>
          #   tcp_winnuke: <value in [allow, drop, trap-to-host]>
          #   ipv6_daddr_err: <value in [allow, drop, trap-to-host]>
          #   ipv4_land: <value in [allow, drop, trap-to-host]>
          #   ipv6_opttunnel: <value in [allow, drop, trap-to-host]>
          #   tcp_no_flag: <value in [allow, drop, trap-to-host]>
          #   ipv6_land: <value in [allow, drop, trap-to-host]>
          #   ipv4_optlsrr: <value in [allow, drop, trap-to-host]>
          #   ipv4_opttimestamp: <value in [allow, drop, trap-to-host]>
          #   ipv4_optrr: <value in [allow, drop, trap-to-host]>
          #   ipv6_optnsap: <value in [allow, drop, trap-to-host]>
          #   ipv6_unknopt: <value in [allow, drop, trap-to-host]>
          #   tcp_syn_data: <value in [allow, drop, trap-to-host]>
          #   ipv6_optendpid: <value in [allow, drop, trap-to-host]>
          #   gtpu_plen_err: <value in [drop, trap-to-host]>
          #   vxlan_minlen_err: <value in [drop, trap-to-host]>
          #   capwap_minlen_err: <value in [drop, trap-to-host]>
          #   gre_csum_err: <value in [drop, trap-to-host, allow]>
          #   nvgre_minlen_err: <value in [drop, trap-to-host]>
          #   sctp_l4len_err: <value in [drop, trap-to-host]>
          #   tcp_hlenvsl4len_err: <value in [drop, trap-to-host]>
          #   sctp_crc_err: <value in [drop, trap-to-host]>
          #   sctp_clen_err: <value in [drop, trap-to-host]>
          #   uesp_minlen_err: <value in [drop, trap-to-host]>
          #   sctp_csum_err: <value in [allow, drop, trap-to-host]>
          # gtp_enhanced_cpu_range: <value in [0, 1, 2]>
          # gtp_enhanced_mode: <value in [disable, enable]>
          # host_shortcut_mode: <value in [bi-directional, host-shortcut]>
          # htx_gtse_quota: <value in [100Mbps, 200Mbps, 300Mbps, ...]>
          # intf_shaping_offload: <value in [disable, enable]>
          # iph_rsvd_re_cksum: <value in [disable, enable]>
          # ipsec_dec_subengine_mask: <string>
          # ipsec_enc_subengine_mask: <string>
          # ipsec_inbound_cache: <value in [disable, enable]>
          # ipsec_mtu_override: <value in [disable, enable]>
          # ipsec_over_vlink: <value in [disable, enable]>
          # isf_np_queues:
          #   cos0: <string>
          #   cos1: <string>
          #   cos2: <string>
          #   cos3: <string>
          #   cos4: <string>
          #   cos5: <string>
          #   cos6: <string>
          #   cos7: <string>
          # lag_out_port_select: <value in [disable, enable]>
          # mcast_session_accounting: <value in [disable, session-based, tpe-based]>
          # np6_cps_optimization_mode: <value in [disable, enable]>
          # per_session_accounting: <value in [enable, disable, enable-by-log, ...]>
          # port_cpu_map:
          #   - cpu_core: <string>
          #     interface: <string>
          # port_npu_map:
          #   - interface: <string>
          #     npu_group_index: <integer>
          # priority_protocol:
          #   bfd: <value in [disable, enable]>
          #   bgp: <value in [disable, enable]>
          #   slbc: <value in [disable, enable]>
          # qos_mode: <value in [disable, priority, round-robin]>
          # rdp_offload: <value in [disable, enable]>
          # recover_np6_link: <value in [disable, enable]>
          # session_denied_offload: <value in [disable, enable]>
          # sse_backpressure: <value in [disable, enable]>
          # strip_clear_text_padding: <value in [disable, enable]>
          # strip_esp_padding: <value in [disable, enable]>
          # sw_eh_hash:
          #   computation: <value in [xor16, xor8, xor4, ...]>
          #   destination_ip_lower_16: <value in [include, exclude]>
          #   destination_ip_upper_16: <value in [include, exclude]>
          #   destination_port: <value in [include, exclude]>
          #   ip_protocol: <value in [include, exclude]>
          #   netmask_length: <integer>
          #   source_ip_lower_16: <value in [include, exclude]>
          #   source_ip_upper_16: <value in [include, exclude]>
          #   source_port: <value in [include, exclude]>
          # sw_np_bandwidth: <value in [0G, 2G, 4G, ...]>
          # switch_np_hash: <value in [src-ip, dst-ip, src-dst-ip]>
          # uesp_offload: <value in [disable, enable]>
          # np_queues:
          #   ethernet_type:
          #     - name: <string>
          #       queue: <integer>
          #       type: <integer>
          #       weight: <integer>
          #   ip_protocol:
          #     - name: <string>
          #       protocol: <integer>
          #       queue: <integer>
          #       weight: <integer>
          #   ip_service:
          #     - dport: <integer>
          #       name: <string>
          #       protocol: <integer>
          #       queue: <integer>
          #       sport: <integer>
          #       weight: <integer>
          #   profile:
          #     - cos0: <value in [queue0, queue1, queue2, ...]>
          #       cos1: <value in [queue0, queue1, queue2, ...]>
          #       cos2: <value in [queue0, queue1, queue2, ...]>
          #       cos3: <value in [queue0, queue1, queue2, ...]>
          #       cos4: <value in [queue0, queue1, queue2, ...]>
          #       cos5: <value in [queue0, queue1, queue2, ...]>
          #       cos6: <value in [queue0, queue1, queue2, ...]>
          #       cos7: <value in [queue0, queue1, queue2, ...]>
          #       dscp0: <value in [queue0, queue1, queue2, ...]>
          #       dscp1: <value in [queue0, queue1, queue2, ...]>
          #       dscp10: <value in [queue0, queue1, queue2, ...]>
          #       dscp11: <value in [queue0, queue1, queue2, ...]>
          #       dscp12: <value in [queue0, queue1, queue2, ...]>
          #       dscp13: <value in [queue0, queue1, queue2, ...]>
          #       dscp14: <value in [queue0, queue1, queue2, ...]>
          #       dscp15: <value in [queue0, queue1, queue2, ...]>
          #       dscp16: <value in [queue0, queue1, queue2, ...]>
          #       dscp17: <value in [queue0, queue1, queue2, ...]>
          #       dscp18: <value in [queue0, queue1, queue2, ...]>
          #       dscp19: <value in [queue0, queue1, queue2, ...]>
          #       dscp2: <value in [queue0, queue1, queue2, ...]>
          #       dscp20: <value in [queue0, queue1, queue2, ...]>
          #       dscp21: <value in [queue0, queue1, queue2, ...]>
          #       dscp22: <value in [queue0, queue1, queue2, ...]>
          #       dscp23: <value in [queue0, queue1, queue2, ...]>
          #       dscp24: <value in [queue0, queue1, queue2, ...]>
          #       dscp25: <value in [queue0, queue1, queue2, ...]>
          #       dscp26: <value in [queue0, queue1, queue2, ...]>
          #       dscp27: <value in [queue0, queue1, queue2, ...]>
          #       dscp28: <value in [queue0, queue1, queue2, ...]>
          #       dscp29: <value in [queue0, queue1, queue2, ...]>
          #       dscp3: <value in [queue0, queue1, queue2, ...]>
          #       dscp30: <value in [queue0, queue1, queue2, ...]>
          #       dscp31: <value in [queue0, queue1, queue2, ...]>
          #       dscp32: <value in [queue0, queue1, queue2, ...]>
          #       dscp33: <value in [queue0, queue1, queue2, ...]>
          #       dscp34: <value in [queue0, queue1, queue2, ...]>
          #       dscp35: <value in [queue0, queue1, queue2, ...]>
          #       dscp36: <value in [queue0, queue1, queue2, ...]>
          #       dscp37: <value in [queue0, queue1, queue2, ...]>
          #       dscp38: <value in [queue0, queue1, queue2, ...]>
          #       dscp39: <value in [queue0, queue1, queue2, ...]>
          #       dscp4: <value in [queue0, queue1, queue2, ...]>
          #       dscp40: <value in [queue0, queue1, queue2, ...]>
          #       dscp41: <value in [queue0, queue1, queue2, ...]>
          #       dscp42: <value in [queue0, queue1, queue2, ...]>
          #       dscp43: <value in [queue0, queue1, queue2, ...]>
          #       dscp44: <value in [queue0, queue1, queue2, ...]>
          #       dscp45: <value in [queue0, queue1, queue2, ...]>
          #       dscp46: <value in [queue0, queue1, queue2, ...]>
          #       dscp47: <value in [queue0, queue1, queue2, ...]>
          #       dscp48: <value in [queue0, queue1, queue2, ...]>
          #       dscp49: <value in [queue0, queue1, queue2, ...]>
          #       dscp5: <value in [queue0, queue1, queue2, ...]>
          #       dscp50: <value in [queue0, queue1, queue2, ...]>
          #       dscp51: <value in [queue0, queue1, queue2, ...]>
          #       dscp52: <value in [queue0, queue1, queue2, ...]>
          #       dscp53: <value in [queue0, queue1, queue2, ...]>
          #       dscp54: <value in [queue0, queue1, queue2, ...]>
          #       dscp55: <value in [queue0, queue1, queue2, ...]>
          #       dscp56: <value in [queue0, queue1, queue2, ...]>
          #       dscp57: <value in [queue0, queue1, queue2, ...]>
          #       dscp58: <value in [queue0, queue1, queue2, ...]>
          #       dscp59: <value in [queue0, queue1, queue2, ...]>
          #       dscp6: <value in [queue0, queue1, queue2, ...]>
          #       dscp60: <value in [queue0, queue1, queue2, ...]>
          #       dscp61: <value in [queue0, queue1, queue2, ...]>
          #       dscp62: <value in [queue0, queue1, queue2, ...]>
          #       dscp63: <value in [queue0, queue1, queue2, ...]>
          #       dscp7: <value in [queue0, queue1, queue2, ...]>
          #       dscp8: <value in [queue0, queue1, queue2, ...]>
          #       dscp9: <value in [queue0, queue1, queue2, ...]>
          #       id: <integer>
          #       type: <value in [cos, dscp]>
          #       weight: <integer>
          #   scheduler:
          #     - mode: <value in [none, priority, round-robin]>
          #       name: <string>
          #   custom_etype_lookup: <value in [disable, enable]>
          # udp_timeout_profile:
          #   - id: <integer>
          #     udp_idle: <integer>
          # qtm_buf_mode: <value in [6ch, 4ch]>
          # default_qos_type: <value in [policing, shaping, policing-enhanced]>
          # tcp_rst_timeout: <integer>
          # ipsec_local_uesp_port: <integer>
          # htab_dedi_queue_nr: <integer>
          # double_level_mcast_offload: <value in [disable, enable]>
          # dse_timeout: <integer>
          # ippool_overload_low: <integer>
          # pba_eim: <value in [disallow, allow]>
          # policy_offload_level: <value in [disable, dos-offload, full-offload]>
          # max_session_timeout: <integer>
          # port_path_option:
          #   ports_using_npu: <list or string>
          # vlan_lookup_cache: <value in [disable, enable]>
          # dos_options:
          #   npu_dos_meter_mode: <value in [local, global]>
          #   npu_dos_synproxy_mode: <value in [synack2ack, pass-synack]>
          #   npu_dos_tpe_mode: <value in [disable, enable]>
          # hash_tbl_spread: <value in [disable, enable]>
          # tcp_timeout_profile:
          #   - close_wait: <integer>
          #     fin_wait: <integer>
          #     id: <integer>
          #     syn_sent: <integer>
          #     syn_wait: <integer>
          #     tcp_idle: <integer>
          #     time_wait: <integer>
          # ip_reassembly:
          #   max_timeout: <integer>
          #   min_timeout: <integer>
          #   status: <value in [disable, enable]>
          # gtp_support: <value in [disable, enable]>
          # htx_icmp_csum_chk: <value in [pass, drop]>
          # hpe:
          #   all_protocol: <integer>
          #   arp_max: <integer>
          #   enable_shaper: <value in [disable, enable]>
          #   esp_max: <integer>
          #   high_priority: <integer>
          #   icmp_max: <integer>
          #   ip_frag_max: <integer>
          #   ip_others_max: <integer>
          #   l2_others_max: <integer>
          #   pri_type_max: <integer>
          #   sctp_max: <integer>
          #   tcp_max: <integer>
          #   tcpfin_rst_max: <integer>
          #   tcpsyn_ack_max: <integer>
          #   tcpsyn_max: <integer>
          #   udp_max: <integer>
          #   enable_queue_shaper: <value in [disable, enable]>
          #   exception_code: <integer>
          #   fragment_with_sess: <integer>
          #   fragment_without_session: <integer>
          #   queue_shaper_max: <integer>
          # dsw_dts_profile:
          #   - action: <value in [wait, drop, drop_tmr_0, ...]>
          #     min_limit: <integer>
          #     profile_id: <integer>
          #     step: <integer>
          # hash_config: <value in [5-tuple, src-ip, src-dst-ip]>
          # ipsec_ob_np_sel: <value in [RR, rr, Packet, ...]>
          # napi_break_interval: <integer>
          # background_sse_scan:
          #   scan: <value in [disable, enable]>
          #   stats_update_interval: <integer>
          #   udp_keepalive_interval: <integer>
          #   scan_stale: <integer>
          #   scan_vt: <integer>
          #   stats_qual_access: <integer>
          #   stats_qual_duration: <integer>
          #   udp_qual_access: <integer>
          #   udp_qual_duration: <integer>
          # inbound_dscp_copy_port: <list or string>
          # session_acct_interval: <integer>
          # htab_msg_queue: <value in [idle, data, dedicated]>
          # dsw_queue_dts_profile:
          #   - iport: <value in [EIF0, eif0, EIF1, ...]>
          #     name: <string>
          #     oport: <value in [EIF0, eif0, EIF1, ...]>
          #     profile_id: <integer>
          #     queue_select: <integer>
          # hw_ha_scan_interval: <integer>
          # ippool_overload_high: <integer>
          # nat46_force_ipv4_packet_forwarding: <value in [disable, enable]>
          # prp_port_out: <list or string>
          # isf_np_rx_tr_distr: <value in [port-flow, round-robin, randomized]>
          # mcast_session_counting6: <value in [disable, enable, session-based, ...]>
          # prp_port_in: <list or string>
          # rps_mode: <value in [disable, enable]>
          # per_policy_accounting: <value in [disable, enable]>
          # mcast_session_counting: <value in [disable, enable, session-based, ...]>
          # inbound_dscp_copy: <value in [disable, enable]>
          # ipsec_host_dfclr: <value in [disable, enable]>
          # process_icmp_by_host: <value in [disable, enable]>
          # dedicated_tx_npu: <value in [disable, enable]>
          # ull_port_mode: <value in [10G, 25G]>
          # sse_ha_scan:
          #   gap: <integer>
          #   max_session_cnt: <integer>
          #   min_duration: <integer>
          # hash_ipv6_sel: <integer>
          # ip_fragment_offload: <value in [disable, enable]>
          # ple_non_syn_tcp_action: <value in [forward, drop]>
          # npu_group_effective_scope: <integer>
          # ipsec_STS_timeout: <value in [1, 2, 3, ...]>
          # ipsec_throughput_msg_frequency: <value in [disable, 32KB, 64KB, ...]>
          # ipt_STS_timeout: <value in [1, 2, 3, ...]>
          # ipt_throughput_msg_frequency: <value in [disable, 32KB, 64KB, ...]>
          # default_tcp_refresh_dir: <value in [both, outgoing, incoming]>
          # default_udp_refresh_dir: <value in [both, outgoing, incoming]>
          # nss_threads_option: <value in [4t-eif, 4t-noeif, 2t]>
          # prp_session_clear_mode: <value in [blocking, non-blocking, do-not-clear]>
          # shaping_stats: <value in [disable, enable]>
          # sw_tr_hash:
          #   draco15: <value in [disable, enable]>
          #   tcp_udp_port: <value in [include, exclude]>
          # pba_port_select_mode: <value in [random, direct]>
          # spa_port_select_mode: <value in [random, direct]>
          # split_ipsec_engines: <value in [disable, enable]>
          # tunnel_over_vlink: <value in [disable, enable]>
          # max_receive_unit: <integer>
          # npu_tcam:
          #   - data:
          #       df: <value in [disable, enable]>
          #       dstip: <string>
          #       dstipv6: <string>
          #       dstmac: <string>
          #       dstport: <integer>
          #       ethertype: <string>
          #       ext_tag: <value in [disable, enable]>
          #       frag_off: <integer>
          #       gen_buf_cnt: <integer>
          #       gen_iv: <value in [invalid, valid]>
          #       gen_l3_flags: <integer>
          #       gen_l4_flags: <integer>
          #       gen_pkt_ctrl: <integer>
          #       gen_pri: <integer>
          #       gen_pri_v: <value in [invalid, valid]>
          #       gen_tv: <value in [invalid, valid]>
          #       ihl: <integer>
          #       ip4_id: <integer>
          #       ip6_fl: <integer>
          #       ipver: <integer>
          #       l4_wd10: <integer>
          #       l4_wd11: <integer>
          #       l4_wd8: <integer>
          #       l4_wd9: <integer>
          #       mf: <value in [disable, enable]>
          #       protocol: <integer>
          #       slink: <integer>
          #       smac_change: <value in [disable, enable]>
          #       sp: <integer>
          #       src_cfi: <value in [disable, enable]>
          #       src_prio: <integer>
          #       src_updt: <value in [disable, enable]>
          #       srcip: <string>
          #       srcipv6: <string>
          #       srcmac: <string>
          #       srcport: <integer>
          #       svid: <integer>
          #       tcp_ack: <value in [disable, enable]>
          #       tcp_cwr: <value in [disable, enable]>
          #       tcp_ece: <value in [disable, enable]>
          #       tcp_fin: <value in [disable, enable]>
          #       tcp_push: <value in [disable, enable]>
          #       tcp_rst: <value in [disable, enable]>
          #       tcp_syn: <value in [disable, enable]>
          #       tcp_urg: <value in [disable, enable]>
          #       tgt_cfi: <value in [disable, enable]>
          #       tgt_prio: <integer>
          #       tgt_updt: <value in [disable, enable]>
          #       tgt_v: <value in [invalid, valid]>
          #       tos: <integer>
          #       tp: <integer>
          #       ttl: <integer>
          #       tvid: <integer>
          #       vdid: <integer>
          #     dbg_dump: <integer>
          #     mask:
          #       df: <value in [disable, enable]>
          #       dstip: <string>
          #       dstipv6: <string>
          #       dstmac: <string>
          #       dstport: <integer>
          #       ethertype: <string>
          #       ext_tag: <value in [disable, enable]>
          #       frag_off: <integer>
          #       gen_buf_cnt: <integer>
          #       gen_iv: <value in [invalid, valid]>
          #       gen_l3_flags: <integer>
          #       gen_l4_flags: <integer>
          #       gen_pkt_ctrl: <integer>
          #       gen_pri: <integer>
          #       gen_pri_v: <value in [invalid, valid]>
          #       gen_tv: <value in [invalid, valid]>
          #       ihl: <integer>
          #       ip4_id: <integer>
          #       ip6_fl: <integer>
          #       ipver: <integer>
          #       l4_wd10: <integer>
          #       l4_wd11: <integer>
          #       l4_wd8: <integer>
          #       l4_wd9: <integer>
          #       mf: <value in [disable, enable]>
          #       protocol: <integer>
          #       slink: <integer>
          #       smac_change: <value in [disable, enable]>
          #       sp: <integer>
          #       src_cfi: <value in [disable, enable]>
          #       src_prio: <integer>
          #       src_updt: <value in [disable, enable]>
          #       srcip: <string>
          #       srcipv6: <string>
          #       srcmac: <string>
          #       srcport: <integer>
          #       svid: <integer>
          #       tcp_ack: <value in [disable, enable]>
          #       tcp_cwr: <value in [disable, enable]>
          #       tcp_ece: <value in [disable, enable]>
          #       tcp_fin: <value in [disable, enable]>
          #       tcp_push: <value in [disable, enable]>
          #       tcp_rst: <value in [disable, enable]>
          #       tcp_syn: <value in [disable, enable]>
          #       tcp_urg: <value in [disable, enable]>
          #       tgt_cfi: <value in [disable, enable]>
          #       tgt_prio: <integer>
          #       tgt_updt: <value in [disable, enable]>
          #       tgt_v: <value in [invalid, valid]>
          #       tos: <integer>
          #       tp: <integer>
          #       ttl: <integer>
          #       tvid: <integer>
          #       vdid: <integer>
          #     mir_act:
          #       vlif: <integer>
          #     name: <string>
          #     oid: <integer>
          #     pri_act:
          #       priority: <integer>
          #       weight: <integer>
          #     sact:
          #       act: <integer>
          #       act_v: <value in [disable, enable]>
          #       bmproc: <integer>
          #       bmproc_v: <value in [disable, enable]>
          #       df_lif: <integer>
          #       df_lif_v: <value in [disable, enable]>
          #       dfr: <integer>
          #       dfr_v: <value in [disable, enable]>
          #       dmac_skip: <integer>
          #       dmac_skip_v: <value in [disable, enable]>
          #       dosen: <integer>
          #       dosen_v: <value in [disable, enable]>
          #       espff_proc: <integer>
          #       espff_proc_v: <value in [disable, enable]>
          #       etype_pid: <integer>
          #       etype_pid_v: <value in [disable, enable]>
          #       frag_proc: <integer>
          #       frag_proc_v: <value in [disable, enable]>
          #       fwd: <integer>
          #       fwd_lif: <integer>
          #       fwd_lif_v: <value in [disable, enable]>
          #       fwd_tvid: <integer>
          #       fwd_tvid_v: <value in [disable, enable]>
          #       fwd_v: <value in [disable, enable]>
          #       icpen: <integer>
          #       icpen_v: <value in [disable, enable]>
          #       igmp_mld_snp: <integer>
          #       igmp_mld_snp_v: <value in [disable, enable]>
          #       learn: <integer>
          #       learn_v: <value in [disable, enable]>
          #       m_srh_ctrl: <integer>
          #       m_srh_ctrl_v: <value in [disable, enable]>
          #       mac_id: <integer>
          #       mac_id_v: <value in [disable, enable]>
          #       mss: <integer>
          #       mss_v: <value in [disable, enable]>
          #       pleen: <integer>
          #       pleen_v: <value in [disable, enable]>
          #       prio_pid: <integer>
          #       prio_pid_v: <value in [disable, enable]>
          #       promis: <integer>
          #       promis_v: <value in [disable, enable]>
          #       rfsh: <integer>
          #       rfsh_v: <value in [disable, enable]>
          #       smac_skip: <integer>
          #       smac_skip_v: <value in [disable, enable]>
          #       tp_smchk_v: <value in [disable, enable]>
          #       tp_smchk: <integer>
          #       tpe_id: <integer>
          #       tpe_id_v: <value in [disable, enable]>
          #       vdm: <integer>
          #       vdm_v: <value in [disable, enable]>
          #       vdom_id: <integer>
          #       vdom_id_v: <value in [disable, enable]>
          #       x_mode: <integer>
          #       x_mode_v: <value in [disable, enable]>
          #     tact:
          #       act: <integer>
          #       act_v: <value in [disable, enable]>
          #       fmtuv4_s: <integer>
          #       fmtuv4_s_v: <value in [disable, enable]>
          #       fmtuv6_s: <integer>
          #       fmtuv6_s_v: <value in [disable, enable]>
          #       lnkid: <integer>
          #       lnkid_v: <value in [disable, enable]>
          #       mac_id: <integer>
          #       mac_id_v: <value in [disable, enable]>
          #       mss_t: <integer>
          #       mss_t_v: <value in [disable, enable]>
          #       mtuv4: <integer>
          #       mtuv4_v: <value in [disable, enable]>
          #       mtuv6: <integer>
          #       mtuv6_v: <value in [disable, enable]>
          #       slif_act: <integer>
          #       slif_act_v: <value in [disable, enable]>
          #       sublnkid: <integer>
          #       sublnkid_v: <value in [disable, enable]>
          #       tgtv_act: <integer>
          #       tgtv_act_v: <value in [disable, enable]>
          #       tlif_act: <integer>
          #       tlif_act_v: <value in [disable, enable]>
          #       tpeid: <integer>
          #       tpeid_v: <value in [disable, enable]>
          #       v6fe: <integer>
          #       v6fe_v: <value in [disable, enable]>
          #       vep_en_v: <value in [disable, enable]>
          #       vep_slid: <integer>
          #       vep_slid_v: <value in [disable, enable]>
          #       vep_en: <integer>
          #       xlt_lif: <integer>
          #       xlt_lif_v: <value in [disable, enable]>
          #       xlt_vid: <integer>
          #       xlt_vid_v: <value in [disable, enable]>
          #     type: <value in [L2_src_tc, L2_tgt_tc, L2_src_mir, ...]>
          #     vid: <integer>
          # icmp_rate_ctrl:
          #   icmp_v4_bucket_size: <integer>
          #   icmp_v4_rate: <integer>
          #   icmp_v6_bucket_size: <integer>
          #   icmp_v6_rate: <integer>
          # vxlan_offload: <value in [disable, enable]>
          # icmp_error_rate_ctrl:
          #   icmpv4_error_bucket_size: <integer>
          #   icmpv4_error_rate: <integer>
          #   icmpv4_error_rate_limit: <value in [disable, enable]>
          #   icmpv6_error_bucket_size: <integer>
          #   icmpv6_error_rate: <integer>
          #   icmpv6_error_rate_limit: <value in [disable, enable]>
          # ipv4_session_quota: <value in [disable, enable]>
          # ipv4_session_quota_high: <integer>
          # ipv4_session_quota_low: <integer>
          # ipv6_prefix_session_quota: <value in [disable, enable]>
          # ipv6_prefix_session_quota_high: <integer>
          # ipv6_prefix_session_quota_low: <integer>
          # dedicated_lacp_queue: <value in [disable, enable]>
          # ipsec_ordering: <value in [disable, enable]>
          # sw_np_pause: <value in [disable, enable]>
          # sw_np_rate: <integer>
          # sw_np_rate_unit: <value in [mbps, pps]>
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
        '/pm/config/adom/{adom}/obj/system/npu',
        '/pm/config/global/obj/system/npu'
    ]
    url_params = ['adom']
    module_primary_key = None
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_npu': {
            'type': 'dict',
            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
            'options': {
                'capwap-offload': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dedicated-management-affinity': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'dedicated-management-cpu': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fastpath': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fp-anomaly': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'esp-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'icmp-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'icmp-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-ihl-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-opt-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-ttlzero-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-ver-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-exthdr-len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-exthdr-order-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-ihl-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-plen-zero': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-ver-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-hlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-plen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'udp-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'udp-hlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'udp-len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'udp-plen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'udplite-cover-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'udplite-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host', 'allow'], 'type': 'str'},
                        'unknproto-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-fin-only': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-optsecurity': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-optralert': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-syn-fin': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-proto-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-saddr-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'icmp-frag': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-optssrr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-opthomeaddr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'udp-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-optinvld': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-fin-noack': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-proto-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-unknopt': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-optstream': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-optjumbo': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'icmp-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-winnuke': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-daddr-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-opttunnel': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-no-flag': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-land': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-optlsrr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv4-opttimestamp': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'choices': ['allow', 'drop', 'trap-to-host'],
                            'type': 'str'
                        },
                        'ipv4-optrr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-optnsap': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-unknopt': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-syn-data': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'ipv6-optendpid': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'},
                        'gtpu-plen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'vxlan-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'capwap-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'gre-csum-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['drop', 'trap-to-host', 'allow'], 'type': 'str'},
                        'nvgre-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'sctp-l4len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'tcp-hlenvsl4len-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'sctp-crc-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'sctp-clen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'uesp-minlen-err': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['drop', 'trap-to-host'], 'type': 'str'},
                        'sctp-csum-err': {'v_range': [['7.2.5', '7.2.11'], ['7.4.3', '']], 'choices': ['allow', 'drop', 'trap-to-host'], 'type': 'str'}
                    }
                },
                'gtp-enhanced-cpu-range': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['0', '1', '2'], 'type': 'str'},
                'gtp-enhanced-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'host-shortcut-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['bi-directional', 'host-shortcut'], 'type': 'str'},
                'htx-gtse-quota': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': [
                        '100Mbps', '200Mbps', '300Mbps', '400Mbps', '500Mbps', '600Mbps', '700Mbps', '800Mbps', '900Mbps', '1Gbps', '2Gbps', '4Gbps',
                        '8Gbps', '10Gbps'
                    ],
                    'type': 'str'
                },
                'intf-shaping-offload': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'iph-rsvd-re-cksum': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipsec-dec-subengine-mask': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                'ipsec-enc-subengine-mask': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                'ipsec-inbound-cache': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipsec-mtu-override': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipsec-over-vlink': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'isf-np-queues': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'cos0': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'cos1': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'cos2': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'cos3': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'cos4': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'cos5': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'cos6': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'cos7': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'}
                    }
                },
                'lag-out-port-select': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mcast-session-accounting': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['disable', 'session-based', 'tpe-based'],
                    'type': 'str'
                },
                'np6-cps-optimization-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'per-session-accounting': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['enable', 'disable', 'enable-by-log', 'all-enable', 'traffic-log-only'],
                    'type': 'str'
                },
                'port-cpu-map': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'cpu-core': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'interface': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'port-npu-map': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'interface': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'npu-group-index': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'priority-protocol': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'bfd': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'bgp': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'slbc': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'qos-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'priority', 'round-robin'], 'type': 'str'},
                'rdp-offload': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'recover-np6-link': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'session-denied-offload': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sse-backpressure': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'strip-clear-text-padding': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'strip-esp-padding': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sw-eh-hash': {
                    'v_range': [['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'computation': {'v_range': [['7.0.1', '']], 'choices': ['xor16', 'xor8', 'xor4', 'crc16'], 'type': 'str'},
                        'destination-ip-lower-16': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'destination-ip-upper-16': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'destination-port': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'ip-protocol': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'netmask-length': {'v_range': [['7.0.1', '']], 'type': 'int'},
                        'source-ip-lower-16': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'source-ip-upper-16': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'},
                        'source-port': {'v_range': [['7.0.1', '']], 'choices': ['include', 'exclude'], 'type': 'str'}
                    }
                },
                'sw-np-bandwidth': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['0G', '2G', '4G', '5G', '6G', '7G', '8G', '9G'],
                    'type': 'str'
                },
                'switch-np-hash': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['src-ip', 'dst-ip', 'src-dst-ip'], 'type': 'str'},
                'uesp-offload': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'np-queues': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'ethernet-type': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                                'queue': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'type': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'weight': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'ip-protocol': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'type': 'list',
                            'options': {
                                'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                                'protocol': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'queue': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'weight': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'ip-service': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'type': 'list',
                            'options': {
                                'dport': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                                'protocol': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'queue': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'sport': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'weight': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'profile': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'type': 'list',
                            'options': {
                                'cos0': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'cos1': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'cos2': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'cos3': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'cos4': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'cos5': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'cos6': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'cos7': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp0': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp1': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp10': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp11': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp12': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp13': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp14': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp15': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp16': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp17': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp18': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp19': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp2': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp20': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp21': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp22': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp23': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp24': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp25': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp26': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp27': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp28': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp29': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp3': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp30': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp31': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp32': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp33': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp34': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp35': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp36': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp37': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp38': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp39': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp4': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp40': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp41': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp42': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp43': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp44': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp45': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp46': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp47': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp48': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp49': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp5': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp50': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp51': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp52': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp53': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp54': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp55': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp56': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp57': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp58': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp59': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp6': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp60': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp61': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp62': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp63': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp7': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp8': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'dscp9': {
                                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                                    'choices': ['queue0', 'queue1', 'queue2', 'queue3', 'queue4', 'queue5', 'queue6', 'queue7'],
                                    'type': 'str'
                                },
                                'id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                                'type': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['cos', 'dscp'], 'type': 'str'},
                                'weight': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                            },
                            'elements': 'dict'
                        },
                        'scheduler': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'type': 'list',
                            'options': {
                                'mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['none', 'priority', 'round-robin'], 'type': 'str'},
                                'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'custom-etype-lookup': {'v_range': [['7.4.7', '7.4.7']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'udp-timeout-profile': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'udp-idle': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'qtm-buf-mode': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['6ch', '4ch'], 'type': 'str'},
                'default-qos-type': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['policing', 'shaping', 'policing-enhanced'],
                    'type': 'str'
                },
                'tcp-rst-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                'ipsec-local-uesp-port': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'htab-dedi-queue-nr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                'double-level-mcast-offload': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dse-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'ippool-overload-low': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'pba-eim': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disallow', 'allow'], 'type': 'str'},
                'policy-offload-level': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['disable', 'dos-offload', 'full-offload'],
                    'type': 'str'
                },
                'max-session-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'port-path-option': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {'ports-using-npu': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'raw'}}
                },
                'vlan-lookup-cache': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dos-options': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'npu-dos-meter-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['local', 'global'], 'type': 'str'},
                        'npu-dos-synproxy-mode': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'choices': ['synack2ack', 'pass-synack'],
                            'type': 'str'
                        },
                        'npu-dos-tpe-mode': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'hash-tbl-spread': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-timeout-profile': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'close-wait': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'fin-wait': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'syn-sent': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'syn-wait': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'tcp-idle': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'time-wait': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'ip-reassembly': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'max-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'min-timeout': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'status': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'gtp-support': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'htx-icmp-csum-chk': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['pass', 'drop'], 'type': 'str'},
                'hpe': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'dict',
                    'options': {
                        'all-protocol': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'arp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'enable-shaper': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'esp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'high-priority': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'icmp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'ip-frag-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'ip-others-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'l2-others-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'pri-type-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'sctp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'tcp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'tcpfin-rst-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'tcpsyn-ack-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'tcpsyn-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'udp-max': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'enable-queue-shaper': {
                            'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']],
                            'choices': ['disable', 'enable'],
                            'type': 'str'
                        },
                        'exception-code': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']], 'type': 'int'},
                        'fragment-with-sess': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']], 'type': 'int'},
                        'fragment-without-session': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']], 'type': 'int'},
                        'queue-shaper-max': {'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']], 'type': 'int'}
                    }
                },
                'dsw-dts-profile': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'action': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'choices': ['wait', 'drop', 'drop_tmr_0', 'drop_tmr_1', 'enque', 'enque_0', 'enque_1'],
                            'type': 'str'
                        },
                        'min-limit': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'profile-id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'step': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'hash-config': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['5-tuple', 'src-ip', 'src-dst-ip'], 'type': 'str'},
                'ipsec-ob-np-sel': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'choices': ['RR', 'rr', 'Packet', 'Hash'], 'type': 'str'},
                'napi-break-interval': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'type': 'int'},
                'background-sse-scan': {
                    'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']],
                    'type': 'dict',
                    'options': {
                        'scan': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'stats-update-interval': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                        'udp-keepalive-interval': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                        'scan-stale': {'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.1', '']], 'type': 'int'},
                        'scan-vt': {'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.1', '']], 'type': 'int'},
                        'stats-qual-access': {'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.1', '']], 'type': 'int'},
                        'stats-qual-duration': {'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.1', '']], 'type': 'int'},
                        'udp-qual-access': {'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.1', '']], 'type': 'int'},
                        'udp-qual-duration': {'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.1', '']], 'type': 'int'}
                    }
                },
                'inbound-dscp-copy-port': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'raw'},
                'session-acct-interval': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'htab-msg-queue': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'choices': ['idle', 'data', 'dedicated'], 'type': 'str'},
                'dsw-queue-dts-profile': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'type': 'list',
                    'options': {
                        'iport': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'choices': [
                                'EIF0', 'eif0', 'EIF1', 'eif1', 'EIF2', 'eif2', 'EIF3', 'eif3', 'EIF4', 'eif4', 'EIF5', 'eif5', 'EIF6', 'eif6', 'EIF7',
                                'eif7', 'HTX0', 'htx0', 'HTX1', 'htx1', 'SSE0', 'sse0', 'SSE1', 'sse1', 'SSE2', 'sse2', 'SSE3', 'sse3', 'RLT', 'rlt',
                                'DFR', 'dfr', 'IPSECI', 'ipseci', 'IPSECO', 'ipseco', 'IPTI', 'ipti', 'IPTO', 'ipto', 'VEP0', 'vep0', 'VEP2', 'vep2',
                                'VEP4', 'vep4', 'VEP6', 'vep6', 'IVS', 'ivs', 'L2TI1', 'l2ti1', 'L2TO', 'l2to', 'L2TI0', 'l2ti0', 'PLE', 'ple', 'SPATH',
                                'spath', 'QTM', 'qtm'
                            ],
                            'type': 'str'
                        },
                        'name': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'str'},
                        'oport': {
                            'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                            'choices': [
                                'EIF0', 'eif0', 'EIF1', 'eif1', 'EIF2', 'eif2', 'EIF3', 'eif3', 'EIF4', 'eif4', 'EIF5', 'eif5', 'EIF6', 'eif6', 'EIF7',
                                'eif7', 'HRX', 'hrx', 'SSE0', 'sse0', 'SSE1', 'sse1', 'SSE2', 'sse2', 'SSE3', 'sse3', 'RLT', 'rlt', 'DFR', 'dfr',
                                'IPSECI', 'ipseci', 'IPSECO', 'ipseco', 'IPTI', 'ipti', 'IPTO', 'ipto', 'VEP0', 'vep0', 'VEP2', 'vep2', 'VEP4', 'vep4',
                                'VEP6', 'vep6', 'IVS', 'ivs', 'L2TI1', 'l2ti1', 'L2TO', 'l2to', 'L2TI0', 'l2ti0', 'PLE', 'ple', 'SYNK', 'sync', 'NSS',
                                'nss', 'TSK', 'tsk', 'QTM', 'qtm', 'l2tO'
                            ],
                            'type': 'str'
                        },
                        'profile-id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                        'queue-select': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'hw-ha-scan-interval': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'type': 'int'},
                'ippool-overload-high': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'int'},
                'nat46-force-ipv4-packet-forwarding': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'prp-port-out': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'raw'},
                'isf-np-rx-tr-distr': {
                    'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '']],
                    'choices': ['port-flow', 'round-robin', 'randomized'],
                    'type': 'str'
                },
                'mcast-session-counting6': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']],
                    'choices': ['disable', 'enable', 'session-based', 'tpe-based'],
                    'type': 'str'
                },
                'prp-port-in': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '']], 'type': 'raw'},
                'rps-mode': {'v_range': [['6.4.8', '6.4.15'], ['7.0.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'per-policy-accounting': {'v_range': [['6.4.8', '6.4.15'], ['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mcast-session-counting': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']],
                    'choices': ['disable', 'enable', 'session-based', 'tpe-based'],
                    'type': 'str'
                },
                'inbound-dscp-copy': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipsec-host-dfclr': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'process-icmp-by-host': {'v_range': [['6.4.7', '6.4.15'], ['7.0.1', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dedicated-tx-npu': {'v_range': [['6.4.7', '6.4.15']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ull-port-mode': {'v_range': [['6.4.9', '6.4.15'], ['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['10G', '25G'], 'type': 'str'},
                'sse-ha-scan': {
                    'v_range': [['6.4.10', '6.4.15'], ['7.0.4', '7.0.14'], ['7.2.1', '']],
                    'type': 'dict',
                    'options': {
                        'gap': {'v_range': [['6.4.10', '6.4.15'], ['7.0.4', '7.0.14'], ['7.2.1', '']], 'type': 'int'},
                        'max-session-cnt': {'v_range': [['6.4.10', '6.4.15'], ['7.0.4', '7.0.14'], ['7.2.1', '']], 'type': 'int'},
                        'min-duration': {'v_range': [['6.4.10', '6.4.15'], ['7.0.4', '7.0.14'], ['7.2.1', '']], 'type': 'int'}
                    }
                },
                'hash-ipv6-sel': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'type': 'int'},
                'ip-fragment-offload': {'v_range': [['7.0.4', '7.0.14'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ple-non-syn-tcp-action': {'v_range': [['7.0.5', '7.0.14'], ['7.2.2', '']], 'choices': ['forward', 'drop'], 'type': 'str'},
                'npu-group-effective-scope': {'v_range': [['7.0.6', '7.0.14'], ['7.2.2', '']], 'type': 'int'},
                'ipsec-STS-timeout': {
                    'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']],
                    'choices': ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
                    'type': 'str'
                },
                'ipsec-throughput-msg-frequency': {
                    'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']],
                    'choices': [
                        'disable', '32KB', '64KB', '128KB', '256KB', '512KB', '1MB', '2MB', '4MB', '8MB', '16MB', '32MB', '64MB', '128MB', '256MB',
                        '512MB', '1GB'
                    ],
                    'type': 'str'
                },
                'ipt-STS-timeout': {
                    'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']],
                    'choices': ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
                    'type': 'str'
                },
                'ipt-throughput-msg-frequency': {
                    'v_range': [['7.0.9', '7.0.14'], ['7.2.4', '7.2.11'], ['7.4.2', '']],
                    'choices': [
                        'disable', '32KB', '64KB', '128KB', '256KB', '512KB', '1MB', '2MB', '4MB', '8MB', '16MB', '32MB', '64MB', '128MB', '256MB',
                        '512MB', '1GB'
                    ],
                    'type': 'str'
                },
                'default-tcp-refresh-dir': {
                    'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.1', '']],
                    'choices': ['both', 'outgoing', 'incoming'],
                    'type': 'str'
                },
                'default-udp-refresh-dir': {
                    'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.1', '']],
                    'choices': ['both', 'outgoing', 'incoming'],
                    'type': 'str'
                },
                'nss-threads-option': {
                    'v_range': [['7.0.12', '7.0.14'], ['7.2.6', '7.2.11'], ['7.4.2', '']],
                    'choices': ['4t-eif', '4t-noeif', '2t'],
                    'type': 'str'
                },
                'prp-session-clear-mode': {'v_range': [['7.2.2', '']], 'choices': ['blocking', 'non-blocking', 'do-not-clear'], 'type': 'str'},
                'shaping-stats': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sw-tr-hash': {
                    'v_range': [['7.2.4', '']],
                    'type': 'dict',
                    'options': {
                        'draco15': {'v_range': [['7.2.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'tcp-udp-port': {'v_range': [['7.2.4', '']], 'choices': ['include', 'exclude'], 'type': 'str'}
                    }
                },
                'pba-port-select-mode': {'v_range': [['7.2.5', '7.2.11'], ['7.4.2', '']], 'choices': ['random', 'direct'], 'type': 'str'},
                'spa-port-select-mode': {'v_range': [['7.2.5', '7.2.11'], ['7.4.2', '']], 'choices': ['random', 'direct'], 'type': 'str'},
                'split-ipsec-engines': {'v_range': [['7.2.5', '7.2.11'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-over-vlink': {'v_range': [['7.2.5', '7.2.11'], ['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'max-receive-unit': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'npu-tcam': {
                    'v_range': [['7.4.2', '']],
                    'type': 'list',
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
                        'name': {'v_range': [['7.4.2', '']], 'type': 'str'},
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
                                'L2_src_tc', 'L2_tgt_tc', 'L2_src_mir', 'L2_tgt_mir', 'L2_src_act', 'L2_tgt_act', 'IPv4_src_tc', 'IPv4_tgt_tc',
                                'IPv4_src_mir', 'IPv4_tgt_mir', 'IPv4_src_act', 'IPv4_tgt_act', 'IPv6_src_tc', 'IPv6_tgt_tc', 'IPv6_src_mir',
                                'IPv6_tgt_mir', 'IPv6_src_act', 'IPv6_tgt_act'
                            ],
                            'type': 'str'
                        },
                        'vid': {'v_range': [['7.4.2', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'icmp-rate-ctrl': {
                    'v_range': [['7.4.3', '']],
                    'type': 'dict',
                    'options': {
                        'icmp-v4-bucket-size': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'icmp-v4-rate': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'icmp-v6-bucket-size': {'v_range': [['7.4.3', '']], 'type': 'int'},
                        'icmp-v6-rate': {'v_range': [['7.4.3', '']], 'type': 'int'}
                    }
                },
                'vxlan-offload': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'icmp-error-rate-ctrl': {
                    'v_range': [['7.4.4', '']],
                    'type': 'dict',
                    'options': {
                        'icmpv4-error-bucket-size': {'v_range': [['7.4.4', '']], 'type': 'int'},
                        'icmpv4-error-rate': {'v_range': [['7.4.4', '']], 'type': 'int'},
                        'icmpv4-error-rate-limit': {'v_range': [['7.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'icmpv6-error-bucket-size': {'v_range': [['7.4.4', '']], 'type': 'int'},
                        'icmpv6-error-rate': {'v_range': [['7.4.4', '']], 'type': 'int'},
                        'icmpv6-error-rate-limit': {'v_range': [['7.4.4', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ipv4-session-quota': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv4-session-quota-high': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ipv4-session-quota-low': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ipv6-prefix-session-quota': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ipv6-prefix-session-quota-high': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'ipv6-prefix-session-quota-low': {'v_range': [['7.6.0', '']], 'type': 'int'},
                'dedicated-lacp-queue': {
                    'v_range': [['7.2.10', '7.2.11'], ['7.4.4', '7.4.7'], ['7.6.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'ipsec-ordering': {'v_range': [['7.4.7', '7.4.7']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sw-np-pause': {'v_range': [['7.2.11', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sw-np-rate': {'v_range': [['7.2.11', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'type': 'int'},
                'sw-np-rate-unit': {'v_range': [['7.2.11', '7.2.11'], ['7.4.7', '7.4.7'], ['7.6.3', '']], 'choices': ['mbps', 'pps'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_npu'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_partial_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
