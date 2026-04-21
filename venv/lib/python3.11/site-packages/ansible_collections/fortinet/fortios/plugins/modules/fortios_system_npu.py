#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_system_npu
short_description: Configure NPU attributes in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and npu category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    system_npu:
        description:
            - Configure NPU attributes.
        default: null
        type: dict
        suboptions:
            capwap_offload:
                description:
                    - Enable/disable offloading managed FortiAP and FortiLink CAPWAP sessions.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dedicated_management_affinity:
                description:
                    - Affinity setting for management daemons (hexadecimal value up to 256 bits in the format of xxxxxxxxxxxxxxxx).
                type: str
            dedicated_management_cpu:
                description:
                    - Enable to dedicate one CPU for GUI and CLI connections when NPs are busy.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            default_qos_type:
                description:
                    - Set default QoS type.
                type: str
                choices:
                    - 'policing'
                    - 'shaping'
                    - 'policing-enhanced'
            dos_options:
                description:
                    - NPU DoS configurations.
                type: dict
                suboptions:
                    npu_dos_meter_mode:
                        description:
                            - Set DoS meter NPU offloading mode.
                        type: str
                        choices:
                            - 'global'
                            - 'local'
                    npu_dos_tpe_mode:
                        description:
                            - Enable/disable insertion of DoS meter ID to session table.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            double_level_mcast_offload:
                description:
                    - Enable double level mcast offload.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            dsw_dts_profile:
                description:
                    - Configure NPU DSW DTS profile.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Set NPU DSW DTS profile action.
                        type: str
                        choices:
                            - 'wait'
                            - 'drop'
                            - 'drop_tmr_0'
                            - 'drop_tmr_1'
                            - 'enque'
                            - 'enque_0'
                            - 'enque_1'
                    min_limit:
                        description:
                            - Set NPU DSW DTS profile min-limt.
                        type: int
                    profile_id:
                        description:
                            - Set NPU DSW DTS profile profile id. see <a href='#notes'>Notes</a>.
                        required: true
                        type: int
                    step:
                        description:
                            - Set NPU DSW DTS profile step.
                        type: int
            dsw_queue_dts_profile:
                description:
                    - Configure NPU DSW Queue DTS profile.
                type: list
                elements: dict
                suboptions:
                    iport:
                        description:
                            - Set NPU DSW DTS in port.
                        type: str
                        choices:
                            - 'eif0'
                            - 'eif1'
                            - 'eif2'
                            - 'eif3'
                            - 'eif4'
                            - 'eif5'
                            - 'eif6'
                            - 'eif7'
                            - 'htx0'
                            - 'htx1'
                            - 'sse0'
                            - 'sse1'
                            - 'sse2'
                            - 'sse3'
                            - 'rlt'
                            - 'dfr'
                            - 'ipseci'
                            - 'ipseco'
                            - 'ipti'
                            - 'ipto'
                            - 'vep0'
                            - 'vep2'
                            - 'vep4'
                            - 'vep6'
                            - 'ivs'
                            - 'l2ti1'
                            - 'l2to'
                            - 'l2ti0'
                            - 'ple'
                            - 'spath'
                            - 'qtm'
                    name:
                        description:
                            - Name.
                        required: true
                        type: str
                    oport:
                        description:
                            - Set NPU DSW DTS out port.
                        type: str
                        choices:
                            - 'eif0'
                            - 'eif1'
                            - 'eif2'
                            - 'eif3'
                            - 'eif4'
                            - 'eif5'
                            - 'eif6'
                            - 'eif7'
                            - 'hrx'
                            - 'sse0'
                            - 'sse1'
                            - 'sse2'
                            - 'sse3'
                            - 'rlt'
                            - 'dfr'
                            - 'ipseci'
                            - 'ipseco'
                            - 'ipti'
                            - 'ipto'
                            - 'vep0'
                            - 'vep2'
                            - 'vep4'
                            - 'vep6'
                            - 'ivs'
                            - 'l2ti1'
                            - 'l2to'
                            - 'l2ti0'
                            - 'ple'
                            - 'sync'
                            - 'nss'
                            - 'tsk'
                            - 'qtm'
                    profile_id:
                        description:
                            - Set NPU DSW DTS profile ID.
                        type: int
                    queue_select:
                        description:
                            - Set NPU DSW DTS queue ID select (0 - reset to default).
                        type: int
            fastpath:
                description:
                    - Enable/disable NP6 offloading (also called fast path).
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            fp_anomaly:
                description:
                    - IPv4/IPv6 anomaly protection.
                type: dict
                suboptions:
                    icmp_csum_err:
                        description:
                            - Invalid IPv4 ICMP checksum anomalies.
                        type: str
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    icmp_frag:
                        description:
                            - Layer 3 fragmented packets that could be part of layer 4 ICMP anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    icmp_land:
                        description:
                            - ICMP land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_csum_err:
                        description:
                            - Invalid IPv4 IP checksum anomalies.
                        type: str
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_land:
                        description:
                            - Land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optlsrr:
                        description:
                            - Loose source record route option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optrr:
                        description:
                            - Record route option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optsecurity:
                        description:
                            - Security option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optssrr:
                        description:
                            - Strict source record route option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_optstream:
                        description:
                            - Stream option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_opttimestamp:
                        description:
                            - Timestamp option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_proto_err:
                        description:
                            - Invalid layer 4 protocol anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv4_unknopt:
                        description:
                            - Unknown option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_daddr_err:
                        description:
                            - Destination address as unspecified or loopback address anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_land:
                        description:
                            - Land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optendpid:
                        description:
                            - End point identification anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_opthomeaddr:
                        description:
                            - Home address option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optinvld:
                        description:
                            - Invalid option anomalies.Invalid option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optjumbo:
                        description:
                            - Jumbo options anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optnsap:
                        description:
                            - Network service access point address option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_optralert:
                        description:
                            - Router alert option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_opttunnel:
                        description:
                            - Tunnel encapsulation limit option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_proto_err:
                        description:
                            - Layer 4 invalid protocol anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_saddr_err:
                        description:
                            - Source address as multicast anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    ipv6_unknopt:
                        description:
                            - Unknown option anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_csum_err:
                        description:
                            - Invalid IPv4 TCP checksum anomalies.
                        type: str
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    tcp_fin_noack:
                        description:
                            - TCP SYN flood with FIN flag set without ACK setting anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_fin_only:
                        description:
                            - TCP SYN flood with only FIN flag set anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_land:
                        description:
                            - TCP land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_no_flag:
                        description:
                            - TCP SYN flood with no flag set anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_syn_data:
                        description:
                            - TCP SYN flood packets with data anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_syn_fin:
                        description:
                            - TCP SYN flood SYN/FIN flag set anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    tcp_winnuke:
                        description:
                            - TCP WinNuke anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
                    udp_csum_err:
                        description:
                            - Invalid IPv4 UDP checksum anomalies.
                        type: str
                        choices:
                            - 'drop'
                            - 'trap-to-host'
                    udp_land:
                        description:
                            - UDP land anomalies.
                        type: str
                        choices:
                            - 'allow'
                            - 'drop'
                            - 'trap-to-host'
            gtp_enhanced_cpu_range:
                description:
                    - GTP enhanced CPU range option.
                type: str
                choices:
                    - '0'
                    - '1'
                    - '2'
            gtp_enhanced_mode:
                description:
                    - Enable/disable GTP enhanced mode.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            gtp_support:
                description:
                    - Enable/Disable NP7 GTP support
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            hash_tbl_spread:
                description:
                    - Enable/disable hash table entry spread .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            hpe:
                description:
                    - Host protection engine configuration.
                type: dict
                suboptions:
                    all_protocol:
                        description:
                            - Maximum packet rate of each host queue except high priority traffic(1K - 32M pps), set 0 to disable.
                        type: int
                    arp_max:
                        description:
                            - Maximum ARP packet rate (1K - 32M pps). Entry is valid when ARP is removed from high-priority traffic.
                        type: int
                    enable_shaper:
                        description:
                            - Enable/Disable NPU Host Protection Engine (HPE) for packet type shaper.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    esp_max:
                        description:
                            - Maximum ESP packet rate (1K - 32M pps).
                        type: int
                    high_priority:
                        description:
                            - Maximum packet rate for high priority traffic packets (1K - 32M pps).
                        type: int
                    icmp_max:
                        description:
                            - Maximum ICMP packet rate (1K - 32M pps).
                        type: int
                    ip_frag_max:
                        description:
                            - Maximum fragmented IP packet rate (1K - 32M pps).
                        type: int
                    ip_others_max:
                        description:
                            - Maximum IP packet rate for other packets (packet types that cannot be set with other options) (1K - 32G pps).
                        type: int
                    l2_others_max:
                        description:
                            - Maximum L2 packet rate for L2 packets that are not ARP packets (1K - 32M pps).
                        type: int
                    sctp_max:
                        description:
                            - Maximum SCTP packet rate (1K - 32M pps).
                        type: int
                    tcp_max:
                        description:
                            - Maximum TCP packet rate (1K - 32M pps).
                        type: int
                    tcpfin_rst_max:
                        description:
                            - Maximum TCP carries FIN or RST flags packet rate (1K - 32M pps).
                        type: int
                    tcpsyn_ack_max:
                        description:
                            - Maximum TCP carries SYN and ACK flags packet rate (1K - 32M pps).
                        type: int
                    tcpsyn_max:
                        description:
                            - Maximum TCP SYN packet rate (1K - 40M pps).
                        type: int
                    udp_max:
                        description:
                            - Maximum UDP packet rate (1K - 32M pps).
                        type: int
            htab_dedi_queue_nr:
                description:
                    - Set the number of dedicate queue for hash table messages.
                type: int
            htab_msg_queue:
                description:
                    - Set hash table message queue mode.
                type: str
                choices:
                    - 'data'
                    - 'idle'
                    - 'dedicated'
            htx_icmp_csum_chk:
                description:
                    - Set HTX icmp csum checking mode.
                type: str
                choices:
                    - 'drop'
                    - 'pass'
            inbound_dscp_copy_port:
                description:
                    - Physical interfaces that support inbound-dscp-copy.
                type: list
                elements: dict
                suboptions:
                    interface:
                        description:
                            - Physical interface name.
                        required: true
                        type: str
            intf_shaping_offload:
                description:
                    - Enable/disable NPU offload when doing interface-based traffic shaping according to the egress-shaping-profile.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ip_fragment_offload:
                description:
                    - Enable/disable NP7 NPU IP fragment offload.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ip_reassembly:
                description:
                    - IP reassebmly engine configuration.
                type: dict
                suboptions:
                    max_timeout:
                        description:
                            - Maximum timeout value for IP reassembly (5 us - 600,000,000 us).
                        type: int
                    min_timeout:
                        description:
                            - Minimum timeout value for IP reassembly (5 us - 600,000,000 us).
                        type: int
                    status:
                        description:
                            - Set IP reassembly processing status.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            ipsec_dec_subengine_mask:
                description:
                    - IPsec decryption subengine mask (0x1 - 0xff).
                type: str
            ipsec_enc_subengine_mask:
                description:
                    - IPsec encryption subengine mask (0x1 - 0xff).
                type: str
            ipsec_inbound_cache:
                description:
                    - Enable/disable IPsec inbound cache for anti-replay.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ipsec_mtu_override:
                description:
                    - Enable/disable NP6 IPsec MTU override.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ipsec_ob_np_sel:
                description:
                    - IPsec NP selection for OB SA offloading.
                type: str
                choices:
                    - 'rr'
                    - 'Packet'
                    - 'Hash'
            ipsec_over_vlink:
                description:
                    - Enable/disable IPsec over vlink.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            isf_np_queues:
                description:
                    - Configure queues of switch port connected to NP6 XAUI on ingress path.
                type: dict
                suboptions:
                    cos0:
                        description:
                            - CoS profile name for CoS 0. Source system.isf-queue-profile.name.
                        type: str
                    cos1:
                        description:
                            - CoS profile name for CoS 1. Source system.isf-queue-profile.name.
                        type: str
                    cos2:
                        description:
                            - CoS profile name for CoS 2. Source system.isf-queue-profile.name.
                        type: str
                    cos3:
                        description:
                            - CoS profile name for CoS 3. Source system.isf-queue-profile.name.
                        type: str
                    cos4:
                        description:
                            - CoS profile name for CoS 4. Source system.isf-queue-profile.name.
                        type: str
                    cos5:
                        description:
                            - CoS profile name for CoS 5. Source system.isf-queue-profile.name.
                        type: str
                    cos6:
                        description:
                            - CoS profile name for CoS 6. Source system.isf-queue-profile.name.
                        type: str
                    cos7:
                        description:
                            - CoS profile name for CoS 7. Source system.isf-queue-profile.name.
                        type: str
            lag_out_port_select:
                description:
                    - Enable/disable LAG outgoing port selection based on incoming traffic port.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            max_receive_unit:
                description:
                    - Set the maximum packet size for receive, larger packets will be silently dropped.
                type: int
            max_session_timeout:
                description:
                    - Maximum time interval for refreshing NPU-offloaded sessions (10 - 1000 sec).
                type: int
            mcast_session_accounting:
                description:
                    - Enable/disable traffic accounting for each multicast session through TAE counter.
                type: str
                choices:
                    - 'tpe-based'
                    - 'session-based'
                    - 'disable'
            napi_break_interval:
                description:
                    -  NAPI break interval .
                type: int
            np_queues:
                description:
                    - Configure queue assignment on NP7.
                type: dict
                suboptions:
                    ethernet_type:
                        description:
                            - Configure a NP7 QoS Ethernet Type.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Ethernet Type Name.
                                required: true
                                type: str
                            queue:
                                description:
                                    - Queue Number.
                                type: int
                            type:
                                description:
                                    - Ethernet Type.
                                type: str
                            weight:
                                description:
                                    - Class Weight.
                                type: int
                    ip_protocol:
                        description:
                            - Configure a NP7 QoS IP Protocol.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - IP Protocol Name.
                                required: true
                                type: str
                            protocol:
                                description:
                                    - IP Protocol.
                                type: int
                            queue:
                                description:
                                    - Queue Number.
                                type: int
                            weight:
                                description:
                                    - Class Weight.
                                type: int
                    ip_service:
                        description:
                            - Configure a NP7 QoS IP Service.
                        type: list
                        elements: dict
                        suboptions:
                            dport:
                                description:
                                    - Destination port.
                                type: int
                            name:
                                description:
                                    - IP service name.
                                required: true
                                type: str
                            protocol:
                                description:
                                    - IP protocol.
                                type: int
                            queue:
                                description:
                                    - Queue number.
                                type: int
                            sport:
                                description:
                                    - Source port.
                                type: int
                            weight:
                                description:
                                    - Class weight.
                                type: int
                    profile:
                        description:
                            - Configure a NP7 class profile.
                        type: list
                        elements: dict
                        suboptions:
                            cos0:
                                description:
                                    - Queue number of CoS 0.
                                type: str
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
                                description:
                                    - Queue number of CoS 1.
                                type: str
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
                                description:
                                    - Queue number of CoS 2.
                                type: str
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
                                description:
                                    - Queue number of CoS 3.
                                type: str
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
                                description:
                                    - Queue number of CoS 4.
                                type: str
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
                                description:
                                    - Queue number of CoS 5.
                                type: str
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
                                description:
                                    - Queue number of CoS 6.
                                type: str
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
                                description:
                                    - Queue number of CoS 7.
                                type: str
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
                                description:
                                    - Queue number of DSCP 0.
                                type: str
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
                                description:
                                    - Queue number of DSCP 1.
                                type: str
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
                                description:
                                    - Queue number of DSCP 10.
                                type: str
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
                                description:
                                    - Queue number of DSCP 11.
                                type: str
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
                                description:
                                    - Queue number of DSCP 12.
                                type: str
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
                                description:
                                    - Queue number of DSCP 13.
                                type: str
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
                                description:
                                    - Queue number of DSCP 14.
                                type: str
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
                                description:
                                    - Queue number of DSCP 15.
                                type: str
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
                                description:
                                    - Queue number of DSCP 16.
                                type: str
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
                                description:
                                    - Queue number of DSCP 17.
                                type: str
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
                                description:
                                    - Queue number of DSCP 18.
                                type: str
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
                                description:
                                    - Queue number of DSCP 19.
                                type: str
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
                                description:
                                    - Queue number of DSCP 2.
                                type: str
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
                                description:
                                    - Queue number of DSCP 20.
                                type: str
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
                                description:
                                    - Queue number of DSCP 21.
                                type: str
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
                                description:
                                    - Queue number of DSCP 22.
                                type: str
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
                                description:
                                    - Queue number of DSCP 23.
                                type: str
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
                                description:
                                    - Queue number of DSCP 24.
                                type: str
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
                                description:
                                    - Queue number of DSCP 25.
                                type: str
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
                                description:
                                    - Queue number of DSCP 26.
                                type: str
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
                                description:
                                    - Queue number of DSCP 27.
                                type: str
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
                                description:
                                    - Queue number of DSCP 28.
                                type: str
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
                                description:
                                    - Queue number of DSCP 29.
                                type: str
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
                                description:
                                    - Queue number of DSCP 3.
                                type: str
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
                                description:
                                    - Queue number of DSCP 30.
                                type: str
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
                                description:
                                    - Queue number of DSCP 31.
                                type: str
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
                                description:
                                    - Queue number of DSCP 32.
                                type: str
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
                                description:
                                    - Queue number of DSCP 33.
                                type: str
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
                                description:
                                    - Queue number of DSCP 34.
                                type: str
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
                                description:
                                    - Queue number of DSCP 35.
                                type: str
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
                                description:
                                    - Queue number of DSCP 36.
                                type: str
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
                                description:
                                    - Queue number of DSCP 37.
                                type: str
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
                                description:
                                    - Queue number of DSCP 38.
                                type: str
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
                                description:
                                    - Queue number of DSCP 39.
                                type: str
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
                                description:
                                    - Queue number of DSCP 4.
                                type: str
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
                                description:
                                    - Queue number of DSCP 40.
                                type: str
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
                                description:
                                    - Queue number of DSCP 41.
                                type: str
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
                                description:
                                    - Queue number of DSCP 42.
                                type: str
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
                                description:
                                    - Queue number of DSCP 43.
                                type: str
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
                                description:
                                    - Queue number of DSCP 44.
                                type: str
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
                                description:
                                    - Queue number of DSCP 45.
                                type: str
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
                                description:
                                    - Queue number of DSCP 46.
                                type: str
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
                                description:
                                    - Queue number of DSCP 47.
                                type: str
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
                                description:
                                    - Queue number of DSCP 48.
                                type: str
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
                                description:
                                    - Queue number of DSCP 49.
                                type: str
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
                                description:
                                    - Queue number of DSCP 5.
                                type: str
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
                                description:
                                    - Queue number of DSCP 50.
                                type: str
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
                                description:
                                    - Queue number of DSCP 51.
                                type: str
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
                                description:
                                    - Queue number of DSCP 52.
                                type: str
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
                                description:
                                    - Queue number of DSCP 53.
                                type: str
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
                                description:
                                    - Queue number of DSCP 54.
                                type: str
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
                                description:
                                    - Queue number of DSCP 55.
                                type: str
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
                                description:
                                    - Queue number of DSCP 56.
                                type: str
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
                                description:
                                    - Queue number of DSCP 57.
                                type: str
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
                                description:
                                    - Queue number of DSCP 58.
                                type: str
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
                                description:
                                    - Queue number of DSCP 59.
                                type: str
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
                                description:
                                    - Queue number of DSCP 6.
                                type: str
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
                                description:
                                    - Queue number of DSCP 60.
                                type: str
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
                                description:
                                    - Queue number of DSCP 61.
                                type: str
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
                                description:
                                    - Queue number of DSCP 62.
                                type: str
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
                                description:
                                    - Queue number of DSCP 63.
                                type: str
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
                                description:
                                    - Queue number of DSCP 7.
                                type: str
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
                                description:
                                    - Queue number of DSCP 8.
                                type: str
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
                                description:
                                    - Queue number of DSCP 9.
                                type: str
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
                                description:
                                    - Profile ID. see <a href='#notes'>Notes</a>.
                                required: true
                                type: int
                            type:
                                description:
                                    - Profile type.
                                type: str
                                choices:
                                    - 'cos'
                                    - 'dscp'
                            weight:
                                description:
                                    - Class weight.
                                type: int
                    scheduler:
                        description:
                            - Configure a NP7 QoS Scheduler.
                        type: list
                        elements: dict
                        suboptions:
                            mode:
                                description:
                                    - Scheduler mode.
                                type: str
                                choices:
                                    - 'none'
                                    - 'priority'
                                    - 'round-robin'
                            name:
                                description:
                                    - Scheduler name.
                                required: true
                                type: str
            npu_group_effective_scope:
                description:
                    - npu-group-effective-scope defines under which npu-group cmds such as list/purge will be excecuted. Default scope is for all four HS-ok
                       groups. (0-3).
                type: int
            npu_tcam:
                description:
                    - Configure NPU TCAM policies.
                type: list
                elements: dict
                suboptions:
                    data:
                        description:
                            - Data fields of TCAM.
                        type: dict
                        suboptions:
                            df:
                                description:
                                    - tcam data ip flag df.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            dstip:
                                description:
                                    - tcam data dst ipv4 address.
                                type: str
                            dstipv6:
                                description:
                                    - tcam data dst ipv6 address.
                                type: str
                            dstmac:
                                description:
                                    - tcam data dst macaddr.
                                type: str
                            dstport:
                                description:
                                    - tcam data L4 dst port.
                                type: int
                            ethertype:
                                description:
                                    - tcam data ethertype.
                                type: str
                            ext_tag:
                                description:
                                    - tcam data extension tag.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            frag_off:
                                description:
                                    - tcam data ip flag fragment offset.
                                type: int
                            gen_buf_cnt:
                                description:
                                    - tcam data gen info buffer count.
                                type: int
                            gen_iv:
                                description:
                                    - tcam data gen info iv.
                                type: str
                                choices:
                                    - 'valid'
                                    - 'invalid'
                            gen_l3_flags:
                                description:
                                    - tcam data gen info L3 flags.
                                type: int
                            gen_l4_flags:
                                description:
                                    - tcam data gen info L4 flags.
                                type: int
                            gen_pkt_ctrl:
                                description:
                                    - tcam data gen info packet control.
                                type: int
                            gen_pri:
                                description:
                                    - tcam data gen info priority.
                                type: int
                            gen_pri_v:
                                description:
                                    - tcam data gen info priority valid.
                                type: str
                                choices:
                                    - 'valid'
                                    - 'invalid'
                            gen_tv:
                                description:
                                    - tcam data gen info tv.
                                type: str
                                choices:
                                    - 'valid'
                                    - 'invalid'
                            ihl:
                                description:
                                    - tcam data ipv4 IHL.
                                type: int
                            ip4_id:
                                description:
                                    - tcam data ipv4 id.
                                type: int
                            ip6_fl:
                                description:
                                    - tcam data ipv6 flow label.
                                type: int
                            ipver:
                                description:
                                    - tcam data ip header version.
                                type: int
                            l4_wd10:
                                description:
                                    - tcam data L4 word10.
                                type: int
                            l4_wd11:
                                description:
                                    - tcam data L4 word11.
                                type: int
                            l4_wd8:
                                description:
                                    - tcam data L4 word8.
                                type: int
                            l4_wd9:
                                description:
                                    - tcam data L4 word9.
                                type: int
                            mf:
                                description:
                                    - tcam data ip flag mf.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            protocol:
                                description:
                                    - tcam data ip protocol.
                                type: int
                            slink:
                                description:
                                    - tcam data sublink.
                                type: int
                            smac_change:
                                description:
                                    - tcam data source MAC change.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            sp:
                                description:
                                    - tcam data source port.
                                type: int
                            src_cfi:
                                description:
                                    - tcam data source cfi.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            src_prio:
                                description:
                                    - tcam data source priority.
                                type: int
                            src_updt:
                                description:
                                    - tcam data source update.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            srcip:
                                description:
                                    - tcam data src ipv4 address.
                                type: str
                            srcipv6:
                                description:
                                    - tcam data src ipv6 address.
                                type: str
                            srcmac:
                                description:
                                    - tcam data src macaddr.
                                type: str
                            srcport:
                                description:
                                    - tcam data L4 src port.
                                type: int
                            svid:
                                description:
                                    - tcam data source vid.
                                type: int
                            tcp_ack:
                                description:
                                    - tcam data tcp flag ack.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_cwr:
                                description:
                                    - tcam data tcp flag cwr.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_ece:
                                description:
                                    - tcam data tcp flag ece.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_fin:
                                description:
                                    - tcam data tcp flag fin.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_push:
                                description:
                                    - tcam data tcp flag push.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_rst:
                                description:
                                    - tcam data tcp flag rst.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_syn:
                                description:
                                    - tcam data tcp flag syn.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_urg:
                                description:
                                    - tcam data tcp flag urg.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tgt_cfi:
                                description:
                                    - tcam data target cfi.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tgt_prio:
                                description:
                                    - tcam data target priority.
                                type: int
                            tgt_updt:
                                description:
                                    - tcam data target port update.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tgt_v:
                                description:
                                    - tcam data target valid.
                                type: str
                                choices:
                                    - 'valid'
                                    - 'invalid'
                            tos:
                                description:
                                    - tcam data ip tos.
                                type: int
                            tp:
                                description:
                                    - tcam data target port.
                                type: int
                            ttl:
                                description:
                                    - tcam data ip ttl.
                                type: int
                            tvid:
                                description:
                                    - tcam data target vid.
                                type: int
                            vdid:
                                description:
                                    - tcam data vdom id.
                                type: int
                    mask:
                        description:
                            - Mask fields of TCAM.
                        type: dict
                        suboptions:
                            df:
                                description:
                                    - tcam mask ip flag df.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            dstip:
                                description:
                                    - tcam mask dst ipv4 address.
                                type: str
                            dstipv6:
                                description:
                                    - tcam mask dst ipv6 address.
                                type: str
                            dstmac:
                                description:
                                    - tcam mask dst macaddr.
                                type: str
                            dstport:
                                description:
                                    - tcam mask L4 dst port.
                                type: int
                            ethertype:
                                description:
                                    - tcam mask ethertype.
                                type: str
                            ext_tag:
                                description:
                                    - tcam mask extension tag.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            frag_off:
                                description:
                                    - tcam data ip flag fragment offset.
                                type: int
                            gen_buf_cnt:
                                description:
                                    - tcam mask gen info buffer count.
                                type: int
                            gen_iv:
                                description:
                                    - tcam mask gen info iv.
                                type: str
                                choices:
                                    - 'valid'
                                    - 'invalid'
                            gen_l3_flags:
                                description:
                                    - tcam mask gen info L3 flags.
                                type: int
                            gen_l4_flags:
                                description:
                                    - tcam mask gen info L4 flags.
                                type: int
                            gen_pkt_ctrl:
                                description:
                                    - tcam mask gen info packet control.
                                type: int
                            gen_pri:
                                description:
                                    - tcam mask gen info priority.
                                type: int
                            gen_pri_v:
                                description:
                                    - tcam mask gen info priority valid.
                                type: str
                                choices:
                                    - 'valid'
                                    - 'invalid'
                            gen_tv:
                                description:
                                    - tcam mask gen info tv.
                                type: str
                                choices:
                                    - 'valid'
                                    - 'invalid'
                            ihl:
                                description:
                                    - tcam mask ipv4 IHL.
                                type: int
                            ip4_id:
                                description:
                                    - tcam mask ipv4 id.
                                type: int
                            ip6_fl:
                                description:
                                    - tcam mask ipv6 flow label.
                                type: int
                            ipver:
                                description:
                                    - tcam mask ip header version.
                                type: int
                            l4_wd10:
                                description:
                                    - tcam mask L4 word10.
                                type: int
                            l4_wd11:
                                description:
                                    - tcam mask L4 word11.
                                type: int
                            l4_wd8:
                                description:
                                    - tcam mask L4 word8.
                                type: int
                            l4_wd9:
                                description:
                                    - tcam mask L4 word9.
                                type: int
                            mf:
                                description:
                                    - tcam mask ip flag mf.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            protocol:
                                description:
                                    - tcam mask ip protocol.
                                type: int
                            slink:
                                description:
                                    - tcam mask sublink.
                                type: int
                            smac_change:
                                description:
                                    - tcam mask source MAC change.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            sp:
                                description:
                                    - tcam mask source port.
                                type: int
                            src_cfi:
                                description:
                                    - tcam mask source cfi.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            src_prio:
                                description:
                                    - tcam mask source priority.
                                type: int
                            src_updt:
                                description:
                                    - tcam mask source update.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            srcip:
                                description:
                                    - tcam mask src ipv4 address.
                                type: str
                            srcipv6:
                                description:
                                    - tcam mask src ipv6 address.
                                type: str
                            srcmac:
                                description:
                                    - tcam mask src macaddr.
                                type: str
                            srcport:
                                description:
                                    - tcam mask L4 src port.
                                type: int
                            svid:
                                description:
                                    - tcam mask source vid.
                                type: int
                            tcp_ack:
                                description:
                                    - tcam mask tcp flag ack.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_cwr:
                                description:
                                    - tcam mask tcp flag cwr.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_ece:
                                description:
                                    - tcam mask tcp flag ece.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_fin:
                                description:
                                    - tcam mask tcp flag fin.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_push:
                                description:
                                    - tcam mask tcp flag push.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_rst:
                                description:
                                    - tcam mask tcp flag rst.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_syn:
                                description:
                                    - tcam mask tcp flag syn.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tcp_urg:
                                description:
                                    - tcam mask tcp flag urg.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tgt_cfi:
                                description:
                                    - tcam mask target cfi.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tgt_prio:
                                description:
                                    - tcam mask target priority.
                                type: int
                            tgt_updt:
                                description:
                                    - tcam mask target port update.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tgt_v:
                                description:
                                    - tcam mask target valid.
                                type: str
                                choices:
                                    - 'valid'
                                    - 'invalid'
                            tos:
                                description:
                                    - tcam mask ip tos.
                                type: int
                            tp:
                                description:
                                    - tcam mask target port.
                                type: int
                            ttl:
                                description:
                                    - tcam mask ip ttl.
                                type: int
                            tvid:
                                description:
                                    - tcam mask target vid.
                                type: int
                            vdid:
                                description:
                                    - tcam mask vdom id.
                                type: int
                    mir_act:
                        description:
                            - Mirror action of TCAM.
                        type: dict
                        suboptions:
                            vlif:
                                description:
                                    - tcam mirror action vlif.
                                type: int
                    name:
                        description:
                            - NPU TCAM policies name.
                        required: true
                        type: str
                    oid:
                        description:
                            - NPU TCAM OID.
                        type: int
                    pri_act:
                        description:
                            - Priority action of TCAM.
                        type: dict
                        suboptions:
                            priority:
                                description:
                                    - tcam priority action priority.
                                type: int
                            weight:
                                description:
                                    - tcam priority action weight.
                                type: int
                    sact:
                        description:
                            - Source action of TCAM.
                        type: dict
                        suboptions:
                            act:
                                description:
                                    - tcam sact act.
                                type: int
                            act_v:
                                description:
                                    - Enable to set sact act.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            bmproc:
                                description:
                                    - tcam sact bmproc.
                                type: int
                            bmproc_v:
                                description:
                                    - Enable to set sact bmproc.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            df_lif:
                                description:
                                    - tcam sact df-lif.
                                type: int
                            df_lif_v:
                                description:
                                    - Enable to set sact df-lif.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            dfr:
                                description:
                                    - tcam sact dfr.
                                type: int
                            dfr_v:
                                description:
                                    - Enable to set sact dfr.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            dmac_skip:
                                description:
                                    - tcam sact dmac-skip.
                                type: int
                            dmac_skip_v:
                                description:
                                    - Enable to set sact dmac-skip.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            dosen:
                                description:
                                    - tcam sact dosen.
                                type: int
                            dosen_v:
                                description:
                                    - Enable to set sact dosen.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            espff_proc:
                                description:
                                    - tcam sact espff-proc.
                                type: int
                            espff_proc_v:
                                description:
                                    - Enable to set sact espff-proc.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            etype_pid:
                                description:
                                    - tcam sact etype-pid.
                                type: int
                            etype_pid_v:
                                description:
                                    - Enable to set sact etype-pid.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            frag_proc:
                                description:
                                    - tcam sact frag-proc.
                                type: int
                            frag_proc_v:
                                description:
                                    - Enable to set sact frag-proc.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            fwd:
                                description:
                                    - tcam sact fwd.
                                type: int
                            fwd_lif:
                                description:
                                    - tcam sact fwd-lif.
                                type: int
                            fwd_lif_v:
                                description:
                                    - Enable to set sact fwd-lif.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            fwd_tvid:
                                description:
                                    - tcam sact fwd-tvid.
                                type: int
                            fwd_tvid_v:
                                description:
                                    - Enable to set sact fwd-vid.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            fwd_v:
                                description:
                                    - Enable to set sact fwd.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            icpen:
                                description:
                                    - tcam sact icpen.
                                type: int
                            icpen_v:
                                description:
                                    - Enable to set sact icpen.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            igmp_mld_snp:
                                description:
                                    - tcam sact igmp-mld-snp.
                                type: int
                            igmp_mld_snp_v:
                                description:
                                    - Enable to set sact igmp-mld-snp.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            learn:
                                description:
                                    - tcam sact learn.
                                type: int
                            learn_v:
                                description:
                                    - Enable to set sact learn.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            m_srh_ctrl:
                                description:
                                    - tcam sact m-srh-ctrl.
                                type: int
                            m_srh_ctrl_v:
                                description:
                                    - Enable to set sact m-srh-ctrl.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            mac_id:
                                description:
                                    - tcam sact mac-id.
                                type: int
                            mac_id_v:
                                description:
                                    - Enable to set sact mac-id.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            mss:
                                description:
                                    - tcam sact mss.
                                type: int
                            mss_v:
                                description:
                                    - Enable to set sact mss.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            pleen:
                                description:
                                    - tcam sact pleen.
                                type: int
                            pleen_v:
                                description:
                                    - Enable to set sact pleen.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            prio_pid:
                                description:
                                    - tcam sact prio-pid.
                                type: int
                            prio_pid_v:
                                description:
                                    - Enable to set sact prio-pid.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            promis:
                                description:
                                    - tcam sact promis.
                                type: int
                            promis_v:
                                description:
                                    - Enable to set sact promis.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            rfsh:
                                description:
                                    - tcam sact rfsh.
                                type: int
                            rfsh_v:
                                description:
                                    - Enable to set sact rfsh.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            smac_skip:
                                description:
                                    - tcam sact smac-skip.
                                type: int
                            smac_skip_v:
                                description:
                                    - Enable to set sact smac-skip.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tp_smchk:
                                description:
                                    - tcam sact tp mode.
                                type: int
                            tp_smchk_v:
                                description:
                                    - Enable to set sact tp mode.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tpe_id:
                                description:
                                    - tcam sact tpe-id.
                                type: int
                            tpe_id_v:
                                description:
                                    - Enable to set sact tpe-id.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            vdm:
                                description:
                                    - tcam sact vdm.
                                type: int
                            vdm_v:
                                description:
                                    - Enable to set sact vdm.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            vdom_id:
                                description:
                                    - tcam sact vdom-id.
                                type: int
                            vdom_id_v:
                                description:
                                    - Enable to set sact vdom-id.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            x_mode:
                                description:
                                    - tcam sact x-mode.
                                type: int
                            x_mode_v:
                                description:
                                    - Enable to set sact x-mode.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    tact:
                        description:
                            - Target action of TCAM.
                        type: dict
                        suboptions:
                            act:
                                description:
                                    - tcam tact act.
                                type: int
                            act_v:
                                description:
                                    - Enable to set tact act.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            fmtuv4_s:
                                description:
                                    - tcam tact fmtuv4-s.
                                type: int
                            fmtuv4_s_v:
                                description:
                                    - Enable to set tact fmtuv4-s.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            fmtuv6_s:
                                description:
                                    - tcam tact fmtuv6-s.
                                type: int
                            fmtuv6_s_v:
                                description:
                                    - Enable to set tact fmtuv6-s.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            lnkid:
                                description:
                                    - tcam tact lnkid.
                                type: int
                            lnkid_v:
                                description:
                                    - Enable to set tact lnkid.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            mac_id:
                                description:
                                    - tcam tact mac-id.
                                type: int
                            mac_id_v:
                                description:
                                    - Enable to set tact mac-id.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            mss_t:
                                description:
                                    - tcam tact mss.
                                type: int
                            mss_t_v:
                                description:
                                    - Enable to set tact mss.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            mtuv4:
                                description:
                                    - tcam tact mtuv4.
                                type: int
                            mtuv4_v:
                                description:
                                    - Enable to set tact mtuv4.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            mtuv6:
                                description:
                                    - tcam tact mtuv6.
                                type: int
                            mtuv6_v:
                                description:
                                    - Enable to set tact mtuv6.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            slif_act:
                                description:
                                    - tcam tact slif-act.
                                type: int
                            slif_act_v:
                                description:
                                    - Enable to set tact slif-act.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            sublnkid:
                                description:
                                    - tcam tact sublnkid.
                                type: int
                            sublnkid_v:
                                description:
                                    - Enable to set tact sublnkid.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tgtv_act:
                                description:
                                    - tcam tact tgtv-act.
                                type: int
                            tgtv_act_v:
                                description:
                                    - Enable to set tact tgtv-act.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tlif_act:
                                description:
                                    - tcam tact tlif-act.
                                type: int
                            tlif_act_v:
                                description:
                                    - Enable to set tact tlif-act.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            tpeid:
                                description:
                                    - tcam tact tpeid.
                                type: int
                            tpeid_v:
                                description:
                                    - Enable to set tact tpeid.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            v6fe:
                                description:
                                    - tcam tact v6fe.
                                type: int
                            v6fe_v:
                                description:
                                    - Enable to set tact v6fe.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            vep_en:
                                description:
                                    - tcam tact vep_en.
                                type: int
                            vep_en_v:
                                description:
                                    - Enable to set tact vep-en.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            vep_slid:
                                description:
                                    - tcam tact vep_slid.
                                type: int
                            vep_slid_v:
                                description:
                                    - Enable to set tact vep-slid.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            xlt_lif:
                                description:
                                    - tcam tact xlt-lif.
                                type: int
                            xlt_lif_v:
                                description:
                                    - Enable to set tact xlt-lif.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                            xlt_vid:
                                description:
                                    - tcam tact xlt-vid.
                                type: int
                            xlt_vid_v:
                                description:
                                    - Enable to set tact xlt-vid.
                                type: str
                                choices:
                                    - 'enable'
                                    - 'disable'
                    type:
                        description:
                            - TCAM policy type.
                        type: str
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
                        description:
                            - NPU TCAM VID.
                        type: int
            per_session_accounting:
                description:
                    - Set per-session accounting.
                type: str
                choices:
                    - 'traffic-log-only'
                    - 'disable'
                    - 'enable'
            port_cpu_map:
                description:
                    - Configure NPU interface to CPU core mapping.
                type: list
                elements: dict
                suboptions:
                    cpu_core:
                        description:
                            - The CPU core to map to an interface.
                        type: str
                    interface:
                        description:
                            - The interface to map to a CPU core.
                        required: true
                        type: str
            port_npu_map:
                description:
                    - Configure port to NPU group mapping.
                type: list
                elements: dict
                suboptions:
                    interface:
                        description:
                            - Set NPU interface port for NPU group mapping.
                        required: true
                        type: str
                    npu_group_index:
                        description:
                            - Mapping NPU group index.
                        type: int
            port_path_option:
                description:
                    - Configure port using NPU or Intel-NIC.
                type: dict
                suboptions:
                    ports_using_npu:
                        description:
                            - Set ha/aux ports to handle traffic with NPU (otherwise traffic goes to Intel-NIC and then CPU).
                        type: list
                        elements: dict
                        suboptions:
                            interface_name:
                                description:
                                    - Available interfaces for NPU path.
                                required: true
                                type: str
            priority_protocol:
                description:
                    - Configure NPU priority protocol.
                type: dict
                suboptions:
                    bfd:
                        description:
                            - Enable/disable NPU BFD priority protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    bgp:
                        description:
                            - Enable/disable NPU BGP priority protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    slbc:
                        description:
                            - Enable/disable NPU SLBC priority protocol.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            qos_mode:
                description:
                    - QoS mode on switch and NP.
                type: str
                choices:
                    - 'disable'
                    - 'priority'
                    - 'round-robin'
            qtm_buf_mode:
                description:
                    - QTM channel configuration for packet buffer.
                type: str
                choices:
                    - '6ch'
                    - '4ch'
            rdp_offload:
                description:
                    - Enable/disable RDP offload.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            session_acct_interval:
                description:
                    - Session accounting update interval (1 - 10 sec).
                type: int
            session_denied_offload:
                description:
                    - Enable/disable offloading of denied sessions. Requires ses-denied-traffic to be set.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            shaping_stats:
                description:
                    - Enable/disable NP7 traffic shaping statistics .
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            sse_backpressure:
                description:
                    - Enable/disable SSE backpressure.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strip_clear_text_padding:
                description:
                    - Enable/disable stripping clear text padding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            strip_esp_padding:
                description:
                    - Enable/disable stripping ESP padding.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sw_eh_hash:
                description:
                    - Configure switch enhanced hashing.
                type: dict
                suboptions:
                    computation:
                        description:
                            - Set hashing computation.
                        type: str
                        choices:
                            - 'xor16'
                            - 'xor8'
                            - 'xor4'
                            - 'crc16'
                    destination_ip_lower_16:
                        description:
                            - Include/exclude destination IP address lower 16 bits.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
                    destination_ip_upper_16:
                        description:
                            - Include/exclude destination IP address upper 16 bits.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
                    destination_port:
                        description:
                            - Include/exclude destination port if TCP/UDP.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
                    ip_protocol:
                        description:
                            - Include/exclude IP protocol.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
                    netmask_length:
                        description:
                            - Network mask length.
                        type: int
                    source_ip_lower_16:
                        description:
                            - Include/exclude source IP address lower 16 bits.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
                    source_ip_upper_16:
                        description:
                            - Include/exclude source IP address upper 16 bits.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
                    source_port:
                        description:
                            - Include/exclude source port if TCP/UDP.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
            sw_np_bandwidth:
                description:
                    - Bandwidth from switch to NP.
                type: str
                choices:
                    - '0G'
                    - '2G'
                    - '4G'
                    - '5G'
                    - '6G'
                    - '7G'
                    - '8G'
                    - '9G'
            sw_tr_hash:
                description:
                    - Configure switch traditional hashing.
                type: dict
                suboptions:
                    draco15:
                        description:
                            - Enable/disable DRACO15 hashing.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    tcp_udp_port:
                        description:
                            - Include/exclude TCP/UDP source and destination port for unicast trunk traffic.
                        type: str
                        choices:
                            - 'include'
                            - 'exclude'
            tunnel_over_vlink:
                description:
                    - Enable/disable selection of which NP6 chip the tunnel uses .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            uesp_offload:
                description:
                    - Enable/disable UDP-encapsulated ESP offload .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            ull_port_mode:
                description:
                    - Set ULL port"s speed to 10G/25G .
                type: str
                choices:
                    - '10G'
                    - '25G'
            vlan_lookup_cache:
                description:
                    - Enable/disable vlan lookup cache .
                type: str
                choices:
                    - 'enable'
                    - 'disable'
"""

EXAMPLES = """
- name: Configure NPU attributes.
  fortinet.fortios.fortios_system_npu:
      vdom: "{{ vdom }}"
      system_npu:
          capwap_offload: "enable"
          dedicated_management_affinity: "<your_own_value>"
          dedicated_management_cpu: "enable"
          default_qos_type: "policing"
          dos_options:
              npu_dos_meter_mode: "global"
              npu_dos_tpe_mode: "enable"
          double_level_mcast_offload: "enable"
          dsw_dts_profile:
              -
                  action: "wait"
                  min_limit: "0"
                  profile_id: "<you_own_value>"
                  step: "0"
          dsw_queue_dts_profile:
              -
                  iport: "eif0"
                  name: "default_name_18"
                  oport: "eif0"
                  profile_id: "0"
                  queue_select: "0"
          fastpath: "disable"
          fp_anomaly:
              icmp_csum_err: "drop"
              icmp_frag: "allow"
              icmp_land: "allow"
              ipv4_csum_err: "drop"
              ipv4_land: "allow"
              ipv4_optlsrr: "allow"
              ipv4_optrr: "allow"
              ipv4_optsecurity: "allow"
              ipv4_optssrr: "allow"
              ipv4_optstream: "allow"
              ipv4_opttimestamp: "allow"
              ipv4_proto_err: "allow"
              ipv4_unknopt: "allow"
              ipv6_daddr_err: "allow"
              ipv6_land: "allow"
              ipv6_optendpid: "allow"
              ipv6_opthomeaddr: "allow"
              ipv6_optinvld: "allow"
              ipv6_optjumbo: "allow"
              ipv6_optnsap: "allow"
              ipv6_optralert: "allow"
              ipv6_opttunnel: "allow"
              ipv6_proto_err: "allow"
              ipv6_saddr_err: "allow"
              ipv6_unknopt: "allow"
              tcp_csum_err: "drop"
              tcp_fin_noack: "allow"
              tcp_fin_only: "allow"
              tcp_land: "allow"
              tcp_no_flag: "allow"
              tcp_syn_data: "allow"
              tcp_syn_fin: "allow"
              tcp_winnuke: "allow"
              udp_csum_err: "drop"
              udp_land: "allow"
          gtp_enhanced_cpu_range: "0"
          gtp_enhanced_mode: "enable"
          gtp_support: "enable"
          hash_tbl_spread: "enable"
          hpe:
              all_protocol: "400000"
              arp_max: "5000"
              enable_shaper: "disable"
              esp_max: "5000"
              high_priority: "400000"
              icmp_max: "5000"
              ip_frag_max: "5000"
              ip_others_max: "5000"
              l2_others_max: "5000"
              sctp_max: "5000"
              tcp_max: "40000"
              tcpfin_rst_max: "40000"
              tcpsyn_ack_max: "40000"
              tcpsyn_max: "40000"
              udp_max: "40000"
          htab_dedi_queue_nr: "4"
          htab_msg_queue: "data"
          htx_icmp_csum_chk: "drop"
          inbound_dscp_copy_port:
              -
                  interface: "<your_own_value>"
          intf_shaping_offload: "enable"
          ip_fragment_offload: "disable"
          ip_reassembly:
              max_timeout: "200000"
              min_timeout: "64"
              status: "disable"
          ipsec_dec_subengine_mask: "<your_own_value>"
          ipsec_enc_subengine_mask: "<your_own_value>"
          ipsec_inbound_cache: "enable"
          ipsec_mtu_override: "disable"
          ipsec_ob_np_sel: "rr"
          ipsec_over_vlink: "enable"
          isf_np_queues:
              cos0: "<your_own_value> (source system.isf-queue-profile.name)"
              cos1: "<your_own_value> (source system.isf-queue-profile.name)"
              cos2: "<your_own_value> (source system.isf-queue-profile.name)"
              cos3: "<your_own_value> (source system.isf-queue-profile.name)"
              cos4: "<your_own_value> (source system.isf-queue-profile.name)"
              cos5: "<your_own_value> (source system.isf-queue-profile.name)"
              cos6: "<your_own_value> (source system.isf-queue-profile.name)"
              cos7: "<your_own_value> (source system.isf-queue-profile.name)"
          lag_out_port_select: "disable"
          max_receive_unit: "0"
          max_session_timeout: "40"
          mcast_session_accounting: "tpe-based"
          napi_break_interval: "0"
          np_queues:
              ethernet_type:
                  -
                      name: "default_name_112"
                      queue: "0"
                      type: "<your_own_value>"
                      weight: "15"
              ip_protocol:
                  -
                      name: "default_name_117"
                      protocol: "0"
                      queue: "0"
                      weight: "14"
              ip_service:
                  -
                      dport: "0"
                      name: "default_name_123"
                      protocol: "0"
                      queue: "0"
                      sport: "0"
                      weight: "13"
              profile:
                  -
                      cos0: "queue0"
                      cos1: "queue0"
                      cos2: "queue0"
                      cos3: "queue0"
                      cos4: "queue0"
                      cos5: "queue0"
                      cos6: "queue0"
                      cos7: "queue0"
                      dscp0: "queue0"
                      dscp1: "queue0"
                      dscp10: "queue0"
                      dscp11: "queue0"
                      dscp12: "queue0"
                      dscp13: "queue0"
                      dscp14: "queue0"
                      dscp15: "queue0"
                      dscp16: "queue0"
                      dscp17: "queue0"
                      dscp18: "queue0"
                      dscp19: "queue0"
                      dscp2: "queue0"
                      dscp20: "queue0"
                      dscp21: "queue0"
                      dscp22: "queue0"
                      dscp23: "queue0"
                      dscp24: "queue0"
                      dscp25: "queue0"
                      dscp26: "queue0"
                      dscp27: "queue0"
                      dscp28: "queue0"
                      dscp29: "queue0"
                      dscp3: "queue0"
                      dscp30: "queue0"
                      dscp31: "queue0"
                      dscp32: "queue0"
                      dscp33: "queue0"
                      dscp34: "queue0"
                      dscp35: "queue0"
                      dscp36: "queue0"
                      dscp37: "queue0"
                      dscp38: "queue0"
                      dscp39: "queue0"
                      dscp4: "queue0"
                      dscp40: "queue0"
                      dscp41: "queue0"
                      dscp42: "queue0"
                      dscp43: "queue0"
                      dscp44: "queue0"
                      dscp45: "queue0"
                      dscp46: "queue0"
                      dscp47: "queue0"
                      dscp48: "queue0"
                      dscp49: "queue0"
                      dscp5: "queue0"
                      dscp50: "queue0"
                      dscp51: "queue0"
                      dscp52: "queue0"
                      dscp53: "queue0"
                      dscp54: "queue0"
                      dscp55: "queue0"
                      dscp56: "queue0"
                      dscp57: "queue0"
                      dscp58: "queue0"
                      dscp59: "queue0"
                      dscp6: "queue0"
                      dscp60: "queue0"
                      dscp61: "queue0"
                      dscp62: "queue0"
                      dscp63: "queue0"
                      dscp7: "queue0"
                      dscp8: "queue0"
                      dscp9: "queue0"
                      id: "201"
                      type: "cos"
                      weight: "6"
              scheduler:
                  -
                      mode: "none"
                      name: "default_name_206"
          npu_group_effective_scope: "255"
          npu_tcam:
              -
                  data:
                      df: "enable"
                      dstip: "<your_own_value>"
                      dstipv6: "<your_own_value>"
                      dstmac: "<your_own_value>"
                      dstport: "0"
                      ethertype: "<your_own_value>"
                      ext_tag: "enable"
                      frag_off: "0"
                      gen_buf_cnt: "0"
                      gen_iv: "valid"
                      gen_l3_flags: "0"
                      gen_l4_flags: "0"
                      gen_pkt_ctrl: "0"
                      gen_pri: "0"
                      gen_pri_v: "valid"
                      gen_tv: "valid"
                      ihl: "0"
                      ip4_id: "0"
                      ip6_fl: "0"
                      ipver: "0"
                      l4_wd10: "0"
                      l4_wd11: "0"
                      l4_wd8: "0"
                      l4_wd9: "0"
                      mf: "enable"
                      protocol: "0"
                      slink: "0"
                      smac_change: "enable"
                      sp: "0"
                      src_cfi: "enable"
                      src_prio: "0"
                      src_updt: "enable"
                      srcip: "<your_own_value>"
                      srcipv6: "<your_own_value>"
                      srcmac: "<your_own_value>"
                      srcport: "0"
                      svid: "0"
                      tcp_ack: "enable"
                      tcp_cwr: "enable"
                      tcp_ece: "enable"
                      tcp_fin: "enable"
                      tcp_push: "enable"
                      tcp_rst: "enable"
                      tcp_syn: "enable"
                      tcp_urg: "enable"
                      tgt_cfi: "enable"
                      tgt_prio: "0"
                      tgt_updt: "enable"
                      tgt_v: "valid"
                      tos: "0"
                      tp: "0"
                      ttl: "0"
                      tvid: "0"
                      vdid: "0"
                  mask:
                      df: "enable"
                      dstip: "<your_own_value>"
                      dstipv6: "<your_own_value>"
                      dstmac: "<your_own_value>"
                      dstport: "0"
                      ethertype: "<your_own_value>"
                      ext_tag: "enable"
                      frag_off: "0"
                      gen_buf_cnt: "0"
                      gen_iv: "valid"
                      gen_l3_flags: "0"
                      gen_l4_flags: "0"
                      gen_pkt_ctrl: "0"
                      gen_pri: "0"
                      gen_pri_v: "valid"
                      gen_tv: "valid"
                      ihl: "0"
                      ip4_id: "0"
                      ip6_fl: "0"
                      ipver: "0"
                      l4_wd10: "0"
                      l4_wd11: "0"
                      l4_wd8: "0"
                      l4_wd9: "0"
                      mf: "enable"
                      protocol: "0"
                      slink: "0"
                      smac_change: "enable"
                      sp: "0"
                      src_cfi: "enable"
                      src_prio: "0"
                      src_updt: "enable"
                      srcip: "<your_own_value>"
                      srcipv6: "<your_own_value>"
                      srcmac: "<your_own_value>"
                      srcport: "0"
                      svid: "0"
                      tcp_ack: "enable"
                      tcp_cwr: "enable"
                      tcp_ece: "enable"
                      tcp_fin: "enable"
                      tcp_push: "enable"
                      tcp_rst: "enable"
                      tcp_syn: "enable"
                      tcp_urg: "enable"
                      tgt_cfi: "enable"
                      tgt_prio: "0"
                      tgt_updt: "enable"
                      tgt_v: "valid"
                      tos: "0"
                      tp: "0"
                      ttl: "0"
                      tvid: "0"
                      vdid: "0"
                  mir_act:
                      vlif: "0"
                  name: "default_name_321"
                  oid: "0"
                  pri_act:
                      priority: "0"
                      weight: "0"
                  sact:
                      act: "0"
                      act_v: "enable"
                      bmproc: "0"
                      bmproc_v: "enable"
                      df_lif: "0"
                      df_lif_v: "enable"
                      dfr: "0"
                      dfr_v: "enable"
                      dmac_skip: "0"
                      dmac_skip_v: "enable"
                      dosen: "0"
                      dosen_v: "enable"
                      espff_proc: "0"
                      espff_proc_v: "enable"
                      etype_pid: "0"
                      etype_pid_v: "enable"
                      frag_proc: "0"
                      frag_proc_v: "enable"
                      fwd: "0"
                      fwd_lif: "0"
                      fwd_lif_v: "enable"
                      fwd_tvid: "0"
                      fwd_tvid_v: "enable"
                      fwd_v: "enable"
                      icpen: "0"
                      icpen_v: "enable"
                      igmp_mld_snp: "0"
                      igmp_mld_snp_v: "enable"
                      learn: "0"
                      learn_v: "enable"
                      m_srh_ctrl: "0"
                      m_srh_ctrl_v: "enable"
                      mac_id: "0"
                      mac_id_v: "enable"
                      mss: "0"
                      mss_v: "enable"
                      pleen: "0"
                      pleen_v: "enable"
                      prio_pid: "0"
                      prio_pid_v: "enable"
                      promis: "0"
                      promis_v: "enable"
                      rfsh: "0"
                      rfsh_v: "enable"
                      smac_skip: "0"
                      smac_skip_v: "enable"
                      tp_smchk: "0"
                      tp_smchk_v: "enable"
                      tpe_id: "0"
                      tpe_id_v: "enable"
                      vdm: "0"
                      vdm_v: "enable"
                      vdom_id: "0"
                      vdom_id_v: "enable"
                      x_mode: "0"
                      x_mode_v: "enable"
                  tact:
                      act: "0"
                      act_v: "enable"
                      fmtuv4_s: "0"
                      fmtuv4_s_v: "enable"
                      fmtuv6_s: "0"
                      fmtuv6_s_v: "enable"
                      lnkid: "0"
                      lnkid_v: "enable"
                      mac_id: "0"
                      mac_id_v: "enable"
                      mss_t: "0"
                      mss_t_v: "enable"
                      mtuv4: "0"
                      mtuv4_v: "enable"
                      mtuv6: "0"
                      mtuv6_v: "enable"
                      slif_act: "0"
                      slif_act_v: "enable"
                      sublnkid: "0"
                      sublnkid_v: "enable"
                      tgtv_act: "0"
                      tgtv_act_v: "enable"
                      tlif_act: "0"
                      tlif_act_v: "enable"
                      tpeid: "0"
                      tpeid_v: "enable"
                      v6fe: "0"
                      v6fe_v: "enable"
                      vep_en: "0"
                      vep_en_v: "enable"
                      vep_slid: "0"
                      vep_slid_v: "enable"
                      xlt_lif: "0"
                      xlt_lif_v: "enable"
                      xlt_vid: "0"
                      xlt_vid_v: "enable"
                  type: "L2_src_tc"
                  vid: "0"
          per_session_accounting: "traffic-log-only"
          port_cpu_map:
              -
                  cpu_core: "<your_own_value>"
                  interface: "<your_own_value>"
          port_npu_map:
              -
                  interface: "<your_own_value>"
                  npu_group_index: "0"
          port_path_option:
              ports_using_npu:
                  -
                      interface_name: "<your_own_value>"
          priority_protocol:
              bfd: "enable"
              bgp: "enable"
              slbc: "enable"
          qos_mode: "disable"
          qtm_buf_mode: "6ch"
          rdp_offload: "enable"
          session_acct_interval: "5"
          session_denied_offload: "disable"
          shaping_stats: "disable"
          sse_backpressure: "enable"
          strip_clear_text_padding: "enable"
          strip_esp_padding: "enable"
          sw_eh_hash:
              computation: "xor16"
              destination_ip_lower_16: "include"
              destination_ip_upper_16: "include"
              destination_port: "include"
              ip_protocol: "include"
              netmask_length: "32"
              source_ip_lower_16: "include"
              source_ip_upper_16: "include"
              source_port: "include"
          sw_np_bandwidth: "0G"
          sw_tr_hash:
              draco15: "enable"
              tcp_udp_port: "include"
          tunnel_over_vlink: "enable"
          uesp_offload: "enable"
          ull_port_mode: "10G"
          vlan_lookup_cache: "enable"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_system_npu_data(json):
    option_list = [
        "capwap_offload",
        "dedicated_management_affinity",
        "dedicated_management_cpu",
        "default_qos_type",
        "dos_options",
        "double_level_mcast_offload",
        "dsw_dts_profile",
        "dsw_queue_dts_profile",
        "fastpath",
        "fp_anomaly",
        "gtp_enhanced_cpu_range",
        "gtp_enhanced_mode",
        "gtp_support",
        "hash_tbl_spread",
        "hpe",
        "htab_dedi_queue_nr",
        "htab_msg_queue",
        "htx_icmp_csum_chk",
        "inbound_dscp_copy_port",
        "intf_shaping_offload",
        "ip_fragment_offload",
        "ip_reassembly",
        "ipsec_dec_subengine_mask",
        "ipsec_enc_subengine_mask",
        "ipsec_inbound_cache",
        "ipsec_mtu_override",
        "ipsec_ob_np_sel",
        "ipsec_over_vlink",
        "isf_np_queues",
        "lag_out_port_select",
        "max_receive_unit",
        "max_session_timeout",
        "mcast_session_accounting",
        "napi_break_interval",
        "np_queues",
        "npu_group_effective_scope",
        "npu_tcam",
        "per_session_accounting",
        "port_cpu_map",
        "port_npu_map",
        "port_path_option",
        "priority_protocol",
        "qos_mode",
        "qtm_buf_mode",
        "rdp_offload",
        "session_acct_interval",
        "session_denied_offload",
        "shaping_stats",
        "sse_backpressure",
        "strip_clear_text_padding",
        "strip_esp_padding",
        "sw_eh_hash",
        "sw_np_bandwidth",
        "sw_tr_hash",
        "tunnel_over_vlink",
        "uesp_offload",
        "ull_port_mode",
        "vlan_lookup_cache",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def system_npu(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    system_npu_data = data["system_npu"]

    filtered_data = filter_system_npu_data(system_npu_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("system", "npu", filtered_data, vdom=vdom)
        current_data = fos.get("system", "npu", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["system_npu"] = filtered_data
    fos.do_member_operation(
        "system",
        "npu",
        data_copy,
    )

    return fos.set("system", "npu", data=converted_data, vdom=vdom)


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_system(data, fos, check_mode):

    if data["system_npu"]:
        resp = system_npu(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_npu"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "v_range": [["v6.0.0", ""]],
    "type": "dict",
    "children": {
        "dedicated_management_cpu": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "dedicated_management_affinity": {
            "v_range": [["v7.0.1", ""]],
            "type": "string",
        },
        "port_cpu_map": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "required": True,
                },
                "cpu_core": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
            },
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v7.2.0", "v7.2.0"],
                ["v7.4.0", "v7.4.1"],
                ["v7.4.3", ""],
            ],
        },
        "fastpath": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "capwap_offload": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipsec_enc_subengine_mask": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
        },
        "ipsec_dec_subengine_mask": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
        },
        "sw_np_bandwidth": {
            "v_range": [["v6.2.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [
                {"value": "0G"},
                {"value": "2G"},
                {"value": "4G"},
                {"value": "5G"},
                {"value": "6G"},
                {"value": "7G", "v_range": [["v7.4.0", "v7.4.1"], ["v7.4.3", ""]]},
                {"value": "8G", "v_range": [["v7.4.0", "v7.4.1"], ["v7.4.3", ""]]},
                {"value": "9G", "v_range": [["v7.4.0", "v7.4.1"], ["v7.4.3", ""]]},
            ],
        },
        "gtp_enhanced_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "gtp_enhanced_cpu_range": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "0"}, {"value": "1"}, {"value": "2"}],
        },
        "intf_shaping_offload": {
            "v_range": [["v6.4.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "strip_esp_padding": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "strip_clear_text_padding": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipsec_inbound_cache": {
            "v_range": [["v6.2.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "sse_backpressure": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "rdp_offload": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ipsec_over_vlink": {
            "v_range": [["v6.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "uesp_offload": {
            "v_range": [["v7.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "qos_mode": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v7.2.0", "v7.2.0"],
                ["v7.4.0", "v7.4.1"],
                ["v7.4.3", ""],
            ],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "priority"},
                {"value": "round-robin"},
            ],
        },
        "isf_np_queues": {
            "v_range": [
                ["v6.4.0", "v6.4.0"],
                ["v7.2.0", "v7.2.0"],
                ["v7.4.0", "v7.4.1"],
                ["v7.4.3", ""],
            ],
            "type": "dict",
            "children": {
                "cos0": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos1": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos2": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos3": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos4": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos5": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos6": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
                "cos7": {
                    "v_range": [
                        ["v6.4.0", "v6.4.0"],
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                },
            },
        },
        "mcast_session_accounting": {
            "v_range": [
                ["v6.0.0", "v6.0.0"],
                ["v6.0.11", "v6.2.0"],
                ["v6.2.5", "v6.2.7"],
                ["v6.4.4", "v7.4.1"],
                ["v7.4.3", ""],
            ],
            "type": "string",
            "options": [
                {"value": "tpe-based"},
                {"value": "session-based"},
                {"value": "disable"},
            ],
        },
        "ipsec_mtu_override": {
            "v_range": [
                ["v6.2.0", "v6.2.0"],
                ["v6.2.7", "v6.2.7"],
                ["v6.4.4", "v7.4.1"],
                ["v7.4.3", ""],
            ],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "lag_out_port_select": {
            "v_range": [["v6.2.0", "v6.2.7"], ["v6.4.1", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "sw_eh_hash": {
            "v_range": [["v7.2.0", "v7.2.0"], ["v7.4.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "computation": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [
                        {"value": "xor16"},
                        {"value": "xor8"},
                        {"value": "xor4"},
                        {"value": "crc16"},
                    ],
                },
                "ip_protocol": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
                "source_ip_upper_16": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
                "source_ip_lower_16": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
                "destination_ip_upper_16": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
                "destination_ip_lower_16": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
                "source_port": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
                "destination_port": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
                "netmask_length": {
                    "v_range": [
                        ["v7.2.0", "v7.2.0"],
                        ["v7.4.0", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "integer",
                },
            },
        },
        "sw_tr_hash": {
            "v_range": [["v7.4.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "draco15": {
                    "v_range": [["v7.4.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "tcp_udp_port": {
                    "v_range": [["v7.4.0", "v7.4.1"], ["v7.4.3", ""]],
                    "type": "string",
                    "options": [{"value": "include"}, {"value": "exclude"}],
                },
            },
        },
        "session_denied_offload": {
            "v_range": [["v7.0.0", "v7.4.1"], ["v7.4.3", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "tunnel_over_vlink": {
            "v_range": [["v7.4.4", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "priority_protocol": {
            "v_range": [["v6.0.0", "v6.0.0"], ["v6.0.11", "v7.4.1"], ["v7.4.3", ""]],
            "type": "dict",
            "children": {
                "bgp": {
                    "v_range": [
                        ["v6.0.0", "v6.0.0"],
                        ["v6.0.11", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "slbc": {
                    "v_range": [
                        ["v6.0.0", "v6.0.0"],
                        ["v6.0.11", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "bfd": {
                    "v_range": [
                        ["v6.0.0", "v6.0.0"],
                        ["v6.0.11", "v7.4.1"],
                        ["v7.4.3", ""],
                    ],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "port_path_option": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "dict",
            "children": {
                "ports_using_npu": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "interface_name": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "required": True,
                        }
                    },
                    "v_range": [["v7.4.2", "v7.4.2"]],
                }
            },
        },
        "port_npu_map": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface": {
                    "v_range": [
                        ["v6.0.0", "v6.2.7"],
                        ["v6.4.1", "v7.0.12"],
                        ["v7.2.1", "v7.2.4"],
                        ["v7.4.2", "v7.4.2"],
                    ],
                    "type": "string",
                    "required": True,
                },
                "npu_group_index": {
                    "v_range": [
                        ["v6.0.0", "v6.2.7"],
                        ["v6.4.1", "v7.0.12"],
                        ["v7.2.1", "v7.2.4"],
                        ["v7.4.2", "v7.4.2"],
                    ],
                    "type": "integer",
                },
            },
            "v_range": [
                ["v6.0.0", "v6.2.7"],
                ["v6.4.1", "v7.0.12"],
                ["v7.2.1", "v7.2.4"],
                ["v7.4.2", "v7.4.2"],
            ],
        },
        "ipsec_ob_np_sel": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "rr"}, {"value": "Packet"}, {"value": "Hash"}],
        },
        "npu_group_effective_scope": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "integer",
        },
        "dos_options": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "dict",
            "children": {
                "npu_dos_meter_mode": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "global"}, {"value": "local"}],
                },
                "npu_dos_tpe_mode": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "napi_break_interval": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
        "hpe": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "dict",
            "children": {
                "all_protocol": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "tcpsyn_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "tcpsyn_ack_max": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "integer",
                },
                "tcpfin_rst_max": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "integer",
                },
                "tcp_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "udp_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "icmp_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "sctp_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "esp_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "ip_frag_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "ip_others_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "arp_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "l2_others_max": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "high_priority": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "enable_shaper": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
        },
        "default_qos_type": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [
                {"value": "policing"},
                {"value": "shaping"},
                {"value": "policing-enhanced"},
            ],
        },
        "shaping_stats": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "gtp_support": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "per_session_accounting": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [
                {"value": "traffic-log-only"},
                {"value": "disable"},
                {"value": "enable"},
            ],
        },
        "session_acct_interval": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
        "max_session_timeout": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
        "fp_anomaly": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "dict",
            "children": {
                "tcp_syn_fin": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_fin_noack": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_fin_only": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_no_flag": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_syn_data": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_winnuke": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "tcp_land": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "udp_land": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "icmp_land": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "icmp_frag": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_land": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_proto_err": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_unknopt": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optrr": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optssrr": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optlsrr": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optstream": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_optsecurity": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_opttimestamp": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv4_csum_err": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "drop"}, {"value": "trap-to-host"}],
                },
                "tcp_csum_err": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "drop"}, {"value": "trap-to-host"}],
                },
                "udp_csum_err": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "drop"}, {"value": "trap-to-host"}],
                },
                "icmp_csum_err": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "drop"}, {"value": "trap-to-host"}],
                },
                "ipv6_land": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_proto_err": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_unknopt": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_saddr_err": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_daddr_err": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optralert": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optjumbo": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_opttunnel": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_opthomeaddr": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optnsap": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optendpid": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
                "ipv6_optinvld": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "allow"},
                        {"value": "drop"},
                        {"value": "trap-to-host"},
                    ],
                },
            },
        },
        "ip_reassembly": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "dict",
            "children": {
                "min_timeout": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "max_timeout": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "status": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
        },
        "hash_tbl_spread": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "vlan_lookup_cache": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ip_fragment_offload": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "htx_icmp_csum_chk": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "drop"}, {"value": "pass"}],
        },
        "htab_msg_queue": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "data"}, {"value": "idle"}, {"value": "dedicated"}],
        },
        "htab_dedi_queue_nr": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
        "dsw_dts_profile": {
            "type": "list",
            "elements": "dict",
            "children": {
                "profile_id": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "integer",
                    "required": True,
                },
                "min_limit": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "step": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "action": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "wait"},
                        {"value": "drop"},
                        {"value": "drop_tmr_0"},
                        {"value": "drop_tmr_1"},
                        {"value": "enque"},
                        {"value": "enque_0"},
                        {"value": "enque_1"},
                    ],
                },
            },
            "v_range": [["v7.4.2", "v7.4.2"]],
        },
        "dsw_queue_dts_profile": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "required": True,
                },
                "iport": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "eif0"},
                        {"value": "eif1"},
                        {"value": "eif2"},
                        {"value": "eif3"},
                        {"value": "eif4"},
                        {"value": "eif5"},
                        {"value": "eif6"},
                        {"value": "eif7"},
                        {"value": "htx0"},
                        {"value": "htx1"},
                        {"value": "sse0"},
                        {"value": "sse1"},
                        {"value": "sse2"},
                        {"value": "sse3"},
                        {"value": "rlt"},
                        {"value": "dfr"},
                        {"value": "ipseci"},
                        {"value": "ipseco"},
                        {"value": "ipti"},
                        {"value": "ipto"},
                        {"value": "vep0"},
                        {"value": "vep2"},
                        {"value": "vep4"},
                        {"value": "vep6"},
                        {"value": "ivs"},
                        {"value": "l2ti1"},
                        {"value": "l2to"},
                        {"value": "l2ti0"},
                        {"value": "ple"},
                        {"value": "spath"},
                        {"value": "qtm"},
                    ],
                },
                "oport": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "eif0"},
                        {"value": "eif1"},
                        {"value": "eif2"},
                        {"value": "eif3"},
                        {"value": "eif4"},
                        {"value": "eif5"},
                        {"value": "eif6"},
                        {"value": "eif7"},
                        {"value": "hrx"},
                        {"value": "sse0"},
                        {"value": "sse1"},
                        {"value": "sse2"},
                        {"value": "sse3"},
                        {"value": "rlt"},
                        {"value": "dfr"},
                        {"value": "ipseci"},
                        {"value": "ipseco"},
                        {"value": "ipti"},
                        {"value": "ipto"},
                        {"value": "vep0"},
                        {"value": "vep2"},
                        {"value": "vep4"},
                        {"value": "vep6"},
                        {"value": "ivs"},
                        {"value": "l2ti1"},
                        {"value": "l2to"},
                        {"value": "l2ti0"},
                        {"value": "ple"},
                        {"value": "sync"},
                        {"value": "nss"},
                        {"value": "tsk"},
                        {"value": "qtm"},
                    ],
                },
                "profile_id": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "queue_select": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
            },
            "v_range": [["v7.4.2", "v7.4.2"]],
        },
        "npu_tcam": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "required": True,
                },
                "type": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "options": [
                        {"value": "L2_src_tc"},
                        {"value": "L2_tgt_tc"},
                        {"value": "L2_src_mir"},
                        {"value": "L2_tgt_mir"},
                        {"value": "L2_src_act"},
                        {"value": "L2_tgt_act"},
                        {"value": "IPv4_src_tc"},
                        {"value": "IPv4_tgt_tc"},
                        {"value": "IPv4_src_mir"},
                        {"value": "IPv4_tgt_mir"},
                        {"value": "IPv4_src_act"},
                        {"value": "IPv4_tgt_act"},
                        {"value": "IPv6_src_tc"},
                        {"value": "IPv6_tgt_tc"},
                        {"value": "IPv6_src_mir"},
                        {"value": "IPv6_tgt_mir"},
                        {"value": "IPv6_src_act"},
                        {"value": "IPv6_tgt_act"},
                    ],
                },
                "oid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "vid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                "data": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "dict",
                    "children": {
                        "gen_buf_cnt": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "gen_pri": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "gen_pri_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "valid"}, {"value": "invalid"}],
                        },
                        "gen_iv": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "valid"}, {"value": "invalid"}],
                        },
                        "gen_tv": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "valid"}, {"value": "invalid"}],
                        },
                        "gen_pkt_ctrl": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "gen_l3_flags": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "gen_l4_flags": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "vdid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "tp": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "tgt_updt": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "smac_change": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "ext_tag": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tgt_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "valid"}, {"value": "invalid"}],
                        },
                        "tvid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "tgt_cfi": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tgt_prio": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "sp": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "src_updt": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "slink": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "svid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "src_cfi": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "src_prio": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "srcmac": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "dstmac": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "ethertype": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                        },
                        "ipver": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "ihl": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "ip4_id": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "srcip": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "dstip": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "ip6_fl": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "srcipv6": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                        },
                        "dstipv6": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                        },
                        "ttl": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "protocol": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "tos": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "frag_off": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "mf": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "df": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "srcport": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "dstport": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "tcp_fin": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_syn": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_rst": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_push": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_ack": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_urg": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_ece": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_cwr": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "l4_wd8": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "l4_wd9": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "l4_wd10": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "l4_wd11": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                    },
                },
                "mask": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "dict",
                    "children": {
                        "gen_buf_cnt": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "gen_pri": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "gen_pri_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "valid"}, {"value": "invalid"}],
                        },
                        "gen_iv": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "valid"}, {"value": "invalid"}],
                        },
                        "gen_tv": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "valid"}, {"value": "invalid"}],
                        },
                        "gen_pkt_ctrl": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "gen_l3_flags": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "gen_l4_flags": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "vdid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "tp": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "tgt_updt": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "smac_change": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "ext_tag": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tgt_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "valid"}, {"value": "invalid"}],
                        },
                        "tvid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "tgt_cfi": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tgt_prio": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "sp": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "src_updt": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "slink": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "svid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "src_cfi": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "src_prio": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "srcmac": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "dstmac": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "ethertype": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                        },
                        "ipver": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "ihl": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "ip4_id": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "srcip": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "dstip": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "ip6_fl": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "srcipv6": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                        },
                        "dstipv6": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                        },
                        "ttl": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "protocol": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "tos": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "frag_off": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "mf": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "df": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "srcport": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "dstport": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "tcp_fin": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_syn": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_rst": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_push": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_ack": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_urg": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_ece": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tcp_cwr": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "l4_wd8": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "l4_wd9": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "l4_wd10": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "l4_wd11": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                    },
                },
                "mir_act": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "dict",
                    "children": {
                        "vlif": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"}
                    },
                },
                "pri_act": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "dict",
                    "children": {
                        "priority": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "weight": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                    },
                },
                "sact": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "dict",
                    "children": {
                        "fwd_lif_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "fwd_lif": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "fwd_tvid_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "fwd_tvid": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "df_lif_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "df_lif": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "act_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "act": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "pleen_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "pleen": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "icpen_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "icpen": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "vdm_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "vdm": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "learn_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "learn": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "rfsh_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "rfsh": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "fwd_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "fwd": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "x_mode_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "x_mode": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "promis_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "promis": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "bmproc_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "bmproc": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "mac_id_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "mac_id": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "dosen_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "dosen": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "dfr_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "dfr": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "m_srh_ctrl_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "m_srh_ctrl": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "tpe_id_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tpe_id": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "vdom_id_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "vdom_id": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "mss_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "mss": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "tp_smchk_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tp_smchk": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "etype_pid_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "etype_pid": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "frag_proc_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "frag_proc": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "espff_proc_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "espff_proc": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "prio_pid_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "prio_pid": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "igmp_mld_snp_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "igmp_mld_snp": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "smac_skip_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "smac_skip": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "dmac_skip_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "dmac_skip": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                    },
                },
                "tact": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "dict",
                    "children": {
                        "act_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "act": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "mtuv4_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "mtuv4": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "mtuv6_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "mtuv6": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "mac_id_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "mac_id": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "slif_act_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "slif_act": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "tlif_act_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tlif_act": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "tgtv_act_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tgtv_act": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "tpeid_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "tpeid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "v6fe_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "v6fe": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "xlt_vid_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "xlt_vid": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "xlt_lif_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "xlt_lif": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "mss_t_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "mss_t": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "lnkid_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "lnkid": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "sublnkid_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "sublnkid": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "fmtuv4_s_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "fmtuv4_s": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "fmtuv6_s_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "fmtuv6_s": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "vep_en_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "vep_en": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "vep_slid_v": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "enable"}, {"value": "disable"}],
                        },
                        "vep_slid": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                    },
                },
            },
            "v_range": [["v7.4.2", "v7.4.2"]],
        },
        "np_queues": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "dict",
            "children": {
                "profile": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                            "required": True,
                        },
                        "type": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [{"value": "cos"}, {"value": "dscp"}],
                        },
                        "weight": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "cos0": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "cos1": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "cos2": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "cos3": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "cos4": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "cos5": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "cos6": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "cos7": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp0": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp1": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp2": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp3": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp4": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp5": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp6": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp7": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp8": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp9": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp10": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp11": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp12": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp13": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp14": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp15": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp16": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp17": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp18": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp19": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp20": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp21": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp22": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp23": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp24": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp25": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp26": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp27": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp28": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp29": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp30": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp31": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp32": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp33": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp34": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp35": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp36": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp37": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp38": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp39": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp40": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp41": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp42": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp43": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp44": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp45": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp46": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp47": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp48": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp49": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp50": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp51": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp52": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp53": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp54": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp55": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp56": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp57": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp58": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp59": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp60": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp61": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp62": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                        "dscp63": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "queue0"},
                                {"value": "queue1"},
                                {"value": "queue2"},
                                {"value": "queue3"},
                                {"value": "queue4"},
                                {"value": "queue5"},
                                {"value": "queue6"},
                                {"value": "queue7"},
                            ],
                        },
                    },
                    "v_range": [["v7.4.2", "v7.4.2"]],
                },
                "ethernet_type": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "required": True,
                        },
                        "type": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "string"},
                        "queue": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "weight": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.4.2", "v7.4.2"]],
                },
                "ip_protocol": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "required": True,
                        },
                        "protocol": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "queue": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "weight": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.4.2", "v7.4.2"]],
                },
                "ip_service": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "required": True,
                        },
                        "protocol": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                        "sport": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "dport": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "queue": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
                        "weight": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "integer",
                        },
                    },
                    "v_range": [["v7.4.2", "v7.4.2"]],
                },
                "scheduler": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "required": True,
                        },
                        "mode": {
                            "v_range": [["v7.4.2", "v7.4.2"]],
                            "type": "string",
                            "options": [
                                {"value": "none"},
                                {"value": "priority"},
                                {"value": "round-robin"},
                            ],
                        },
                    },
                    "v_range": [["v7.4.2", "v7.4.2"]],
                },
            },
        },
        "inbound_dscp_copy_port": {
            "type": "list",
            "elements": "dict",
            "children": {
                "interface": {
                    "v_range": [["v7.4.2", "v7.4.2"]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.4.2", "v7.4.2"]],
        },
        "double_level_mcast_offload": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "qtm_buf_mode": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "6ch"}, {"value": "4ch"}],
        },
        "ull_port_mode": {
            "v_range": [["v7.4.2", "v7.4.2"]],
            "type": "string",
            "options": [{"value": "10G"}, {"value": "25G"}],
        },
        "max_receive_unit": {"v_range": [["v7.4.2", "v7.4.2"]], "type": "integer"},
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "system_npu": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_npu"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_npu"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_npu"
        )

        is_error, has_changed, result, diff = fortios_system(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
