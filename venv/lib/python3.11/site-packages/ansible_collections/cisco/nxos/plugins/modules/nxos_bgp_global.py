#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for nxos_bgp_global
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: nxos_bgp_global
short_description: BGP Global resource module.
description:
- This module manages global BGP configuration on devices running Cisco NX-OS.
version_added: 1.4.0
notes:
- Tested against NX-OS 9.3.6.
- Unsupported for Cisco MDS
- This module works with connection C(network_cli) and C(httpapi).
author: Nilashish Chakraborty (@NilashishC)
options:
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the NX-OS device
      by executing the command B(show running-config | section '^router bgp').
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  config:
    description: A list of BGP process configuration.
    type: dict
    suboptions:
      as_number:
        description: Autonomous System Number of the router.
        type: str
      affinity_group:
        description: Configure an affinity group.
        type: dict
        suboptions:
          group_id:
            description: Affinity Group ID.
            type: int
      bestpath: &bestpath
        description: Define the default bestpath selection algorithm.
        type: dict
        suboptions:
          always_compare_med:
            description: Compare MED on paths from different AS.
            type: bool
          as_path:
            description: AS-Path.
            type: dict
            suboptions:
              ignore:
                description: Ignore AS-Path during bestpath selection.
                type: bool
              multipath_relax:
                description: Relax AS-Path restriction when choosing multipaths.
                type: bool
          compare_neighborid:
            description: When more paths are available than max path config, use neighborid as tie-breaker.
            type: bool
          compare_routerid:
            description: Compare router-id for identical EBGP paths.
            type: bool
          cost_community_ignore:
            description: Ignore cost communities in bestpath selection.
            type: bool
          igp_metric_ignore:
            description: Ignore IGP metric for next-hop during bestpath selection.
            type: bool
          med:
            description: MED
            type: dict
            suboptions:
              confed:
                description: Compare MED only from paths originated from within a confederation.
                type: bool
              missing_as_worst:
                description: Treat missing MED as highest MED.
                type: bool
              non_deterministic:
                description: Not always pick the best-MED path among paths from same AS.
                type: bool
      cluster_id: &cluster_id
        description: Configure Route Reflector Cluster-ID.
        type: str
      confederation: &confederation
        description: AS confederation parameters.
        type: dict
        suboptions:
          identifier:
            description: Set routing domain confederation AS.
            type: str
          peers:
            description: Peer ASs in BGP confederation.
            type: list
            elements: str
      disable_policy_batching:
        description: Disable batching evaluation of outbound policy for a peer.
        type: dict
        suboptions:
          set:
            description: Set policy batching.
            type: bool
          ipv4:
            description: IPv4 address-family settings.
            type: dict
            suboptions:
              prefix_list:
                description: Name of prefix-list to apply.
                type: str
          ipv6:
            description: IPv6 address-family settings.
            type: dict
            suboptions:
              prefix_list:
                description: Name of prefix-list to apply.
                type: str
          nexthop:
            description: Batching based on nexthop.
            type: bool
      dynamic_med_interval:
        description: Sets the interval for dampening of med changes.
        type: int
      enforce_first_as:
        description: Enforce neighbor AS is the first AS in AS-PATH attribute (EBGP).
        type: bool
      enhanced_error:
        description: Enable BGP Enhanced error handling.
        type: bool
      fabric_soo:
        description: Fabric site of origin.
        type: str
      fast_external_fallover:
        description: Immediately reset the session if the link to a directly connected BGP peer goes down.
        type: bool
      flush_routes:
        description: Flush routes in RIB upon controlled restart.
        type: bool
      graceful_restart: &graceful_restart
        description: Configure Graceful Restart functionality.
        type: dict
        suboptions:
          set:
            description: Enable graceful-restart.
            type: bool
          restart_time:
            description: Maximum time for restart advertised to peers.
            type: int
          stalepath_time:
            description: Maximum time to keep a restarting peer's stale routes.
            type: int
          helper:
            description: Configure Graceful Restart Helper mode functionality.
            type: bool
      graceful_shutdown:
        description: Graceful-shutdown for BGP protocol.
        type: dict
        suboptions:
          activate:
            description: Send graceful-shutdown community on all routes.
            type: dict
            suboptions:
              set:
                description: Activate graceful-shutdown.
                type: bool
              route_map:
                description: Apply route-map to modify attributes for outbound.
                type: str
          aware:
            description: Lower preference of routes carrying graceful-shutdown community.
            type: bool
      isolate:
        description: Isolate this router from BGP perspective.
        type: dict
        suboptions:
          set:
            description: Withdraw remote BGP routes to isolate this router.
            type: bool
          include_local:
            description: Withdraw both local and remote BGP routes.
            type: bool
      log_neighbor_changes: &log_nbr
        description: Log a message for neighbor up/down event.
        type: bool
      maxas_limit: &maxas_limit
        description: Allow AS-PATH attribute from EBGP neighbor imposing a limit on number of ASes.
        type: int
      neighbors: &nbr
        description: Configure BGP neighbors.
        type: list
        elements: dict
        suboptions:
          neighbor_address:
            description: IP address/Prefix of the neighbor or interface.
            type: str
            required: true
          bfd:
            description: Bidirectional Fast Detection for the neighbor.
            type: dict
            suboptions:
              set:
                description: Set BFD for this neighbor.
                type: bool
              singlehop:
                description: Single-hop session.
                type: bool
              multihop:
                description: Multihop session.
                type: dict
                suboptions:
                  set:
                    description: Set BFD multihop.
                    type: bool
                  interval:
                    description: Configure BFD session interval parameters.
                    type: dict
                    suboptions:
                      tx_interval:
                        description: TX interval in milliseconds.
                        type: int
                      min_rx_interval:
                        description: Minimum RX interval.
                        type: int
                      multiplier:
                        description: Detect Multiplier.
                        type: int
          neighbor_affinity_group:
            description: Configure an affinity group.
            type: dict
            suboptions:
              group_id:
                description: Affinity Group ID.
                type: int
          bmp_activate_server:
            description: Specify server ID for activating BMP monitoring for the peer.
            type: int
          capability:
            description: Capability.
            type: dict
            suboptions:
              suppress_4_byte_as:
                description: Suppress 4-byte AS Capability.
                type: bool
          description:
            description: Neighbor specific description.
            type: str
          disable_connected_check:
            description: Disable check for directly connected peer.
            type: bool
          dont_capability_negotiate:
            description: Don't negotiate capability with this neighbor.
            type: bool
          dscp:
            description: Set dscp value for tcp transport.
            type: str
          dynamic_capability:
            description: Dynamic Capability
            type: bool
          ebgp_multihop:
            description: Specify multihop TTL for remote peer.
            type: int
          graceful_shutdown:
            description: Graceful-shutdown for this neighbor.
            type: dict
            suboptions:
              activate:
                description: Send graceful-shutdown community.
                type: dict
                suboptions:
                  set:
                    description: Set activate.
                    type: bool
                  route_map:
                    description: Apply route-map to modify attributes for outbound.
                    type: str
          inherit:
            description: Inherit a template.
            type: dict
            suboptions:
              peer:
                description: Peer template to inherit.
                type: str
              peer_session:
                description: Peer-session template to inherit.
                type: str
          local_as:
            description:
            - Specify the local-as number for the eBGP neighbor.
            - B(Deprecated), Use local_as_config instead, the facts would always render local_as information as a part of local_as_config as_number
            - This option has been deprecated and will be removed in a release after 2027-01-01.
            type: str
          local_as_config:
            description: Local Autonomous System Number options.
            type: dict
            suboptions:
              as_number:
                description:
                - Set Specify the local-as number for the eBGP neighbor.
                type: str
              no_prepend:
                description:
                - Do not prepend the local-as number to updates from the eBGP neighbor.
                type: bool
              replace_as:
                description:
                - Prepend only the local-as number to updates to eBGP neighbor.
                type: bool
              dual_as:
                description:
                - Connect using either the local-as number or the real as.
                type: bool
          log_neighbor_changes:
            description: Log message for neighbor up/down event.
            type: dict
            suboptions:
              set:
                description:
                - Set log-neighbor-changes.
                type: bool
              disable:
                description:
                - Disable logging of neighbor up/down event.
                type: bool
          low_memory:
            description: Behavior in low memory situations.
            type: dict
            suboptions:
              exempt:
                description: Do not shutdown this peer when under memory pressure.
                type: bool
          password:
            description: Configure a password for neighbor.
            type: dict
            suboptions:
              encryption:
                description:
                - 0 specifies an UNENCRYPTED neighbor password.
                - 3 specifies an 3DES ENCRYPTED neighbor password will follow.
                - 7 specifies a Cisco type 7  ENCRYPTED neighbor password will follow.
                type: int
              key:
                description: Authentication password.
                type: str
          path_attribute:
            description: BGP path attribute optional filtering.
            type: list
            elements: dict
            suboptions:
              action:
                description: Action.
                type: str
                choices: ["discard", "treat-as-withdraw"]
              type:
                description: Path attribute type
                type: int
              range:
                description: Path attribute range.
                type: dict
                suboptions:
                  start:
                    description: Path attribute range start value.
                    type: int
                  end:
                    description: Path attribute range end value.
                    type: int
          peer_type:
            description: Neighbor facing
            type: str
            choices: ["fabric-border-leaf", "fabric-external"]
          remote_as:
            description: Specify Autonomous System Number of the neighbor.
            type: str
          remote_as_route_map:
            description: Route-map to match prefix peer AS number.
            type: str
          remove_private_as:
            description: Remove private AS number from outbound updates.
            type: dict
            suboptions:
              set:
                description: Remove private AS.
                type: bool
              replace_as:
                description: Replace.
                type: bool
              all:
                description: All.
                type: bool
          shutdown:
            description: Administratively shutdown this neighbor.
            type: bool
          timers:
            description: Configure keepalive and hold timers.
            type: dict
            suboptions:
              keepalive:
                description: Keepalive interval (seconds).
                type: int
              holdtime:
                description: Holdtime (seconds).
                type: int
          transport:
            description: BGP transport connection.
            type: dict
            suboptions:
              connection_mode:
                description: Specify type of connection.
                type: dict
                suboptions:
                  passive:
                    description: Allow passive connection setup only.
                    type: bool
          ttl_security:
            description: Enable TTL Security Mechanism.
            type: dict
            suboptions:
              hops:
                description: Specify hop count for remote peer.
                type: int
          update_source:
            description: Specify source of BGP session and updates.
            type: str
      neighbor_down: &nbr_down
        description: Handle BGP neighbor down event, due to various reasons.
        type: dict
        suboptions:
          fib_accelerate:
            description: Accelerate the hardware updates for IP/IPv6 adjacencies for neighbor.
            type: bool
      nexthop:
        description: Nexthop resolution options.
        type: dict
        suboptions:
          suppress_default_resolution:
            description: Prohibit use of default route for nexthop address resolution.
            type: bool
      rd:
        description: Secondary Route Distinguisher for vxlan multisite border gateway.
        type: dict
        suboptions:
          dual:
            description: Generate Secondary RD for all VRFs and L2VNIs.
            type: bool
          id:
            description: Specify 2 byte value for ID.
            type: int
      reconnect_interval: &reconn_intv
        description: Configure connection reconnect interval.
        type: int
      router_id: &rtr_id
        description: Specify the IP address to use as router-id.
        type: str
      shutdown: &shtdwn
        description: Administratively shutdown BGP protocol.
        type: bool
      suppress_fib_pending: &suppr
        description: Advertise only routes that are programmed in hardware to peers.
        type: bool
      timers: &timers
        description: Configure bgp related timers.
        type: dict
        suboptions:
          bestpath_limit:
            description: Configure timeout for first bestpath after restart.
            type: dict
            suboptions:
              timeout:
                description: Bestpath timeout (seconds).
                type: int
              always:
                description: Configure update-delay-always option.
                type: bool
          bgp:
            description: Configure different bgp keepalive and holdtimes.
            type: dict
            suboptions:
              keepalive:
                description: Keepalive interval (seconds).
                type: int
              holdtime:
                description: Holdtime (seconds).
                type: int
          prefix_peer_timeout:
            description: Prefix Peer timeout (seconds).
            type: int
          prefix_peer_wait:
            description: Configure wait timer for a prefix peer.
            type: int
      vrfs:
        description: Virtual Router Context configurations.
        type: list
        elements: dict
        suboptions:
          vrf:
            description: VRF name.
            type: str
          allocate_index:
            description: Configure allocate-index.
            type: int
          bestpath: *bestpath
          cluster_id: *cluster_id
          confederation: *confederation
          graceful_restart: *graceful_restart
          local_as:
            description: Specify the local-as for this vrf.
            type: str
          log_neighbor_changes: *log_nbr
          maxas_limit: *maxas_limit
          neighbors: *nbr
          neighbor_down: *nbr_down
          reconnect_interval: *reconn_intv
          router_id: *rtr_id
          timers: *timers
  state:
    description:
    - The state the configuration should be left in.
    - State I(purged) removes all the BGP configurations from the
      target device. Use caution with this state.
    - State I(deleted) only removes BGP attributes that this modules
      manages and does not negate the BGP process completely. Thereby, preserving
      address-family related configurations under BGP context.
    - Running states I(deleted) and I(replaced) will result in an error if there
      are address-family configuration lines present under a neighbor,
      or a vrf context that is to be removed. Please use the
      M(cisco.nxos.nxos_bgp_af) or M(cisco.nxos.nxos_bgp_neighbor_af)
      modules for prior cleanup.
    - States C(merged) and C(replaced) will result in a failure if BGP is already configured
      with a different ASN than what is provided in the task. In such cases, please use
      state C(purged) to remove the existing BGP process and proceed further.
    - States C(replaced) and C(overridden) have the same behaviour for this module.
    - Refer to examples for more details.
    type: str
    choices:
    - merged
    - replaced
    - overridden
    - deleted
    - purged
    - parsed
    - gathered
    - rendered
    default: merged
"""
EXAMPLES = """
# Using merged

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# Nexus9000v#

- name: Merge the provided configuration with the existing running configuration
  cisco.nxos.nxos_bgp_global:
    config:
      as_number: 65563
      router_id: 192.168.1.1
      bestpath:
        as_path:
          multipath_relax: true
        compare_neighborid: true
        cost_community_ignore: true
      confederation:
        identifier: 42
        peers:
          - 65020
          - 65030
          - 65040
      log_neighbor_changes: true
      maxas_limit: 20
      neighbors:
        - neighbor_address: 192.168.1.100
          neighbor_affinity_group:
            group_id: 160
          bmp_activate_server: 1
          remote_as: 65563
          description: NBR-1
          low_memory:
            exempt: true
        - neighbor_address: 192.168.1.101
          remote_as: 65563
          password:
            encryption: 7
            key: 12090404011C03162E
      neighbor_down:
        fib_accelerate: true
      vrfs:
        - vrf: site-1
          allocate_index: 5000
          local_as: 200
          log_neighbor_changes: true
          neighbors:
            - neighbor_address: 198.51.100.1
              description: site-1-nbr-1
              password:
                encryption: 3
                key: 13D4D3549493D2877B1DC116EE27A6BE
              remote_as: 65562
            - neighbor_address: 198.51.100.2
              remote_as: 65562
              description: site-1-nbr-2
        - vrf: site-2
          local_as: 300
          log_neighbor_changes: true
          neighbors:
            - neighbor_address: 203.0.113.2
              description: site-2-nbr-1
              password:
                encryption: 3
                key: AF92F4C16A0A0EC5BDF56CF58BC030F6
              remote_as: 65568
          neighbor_down:
            fib_accelerate: true

# Task output:
# ------------
# before: {}
#
# commands:
#  - router bgp 65563
#  - bestpath as-path multipath-relax
#  - bestpath compare-neighborid
#  - bestpath cost-community ignore
#  - confederation identifier 42
#  - log-neighbor-changes
#  - maxas-limit 20
#  - neighbor-down fib-accelerate
#  - router-id 192.168.1.1
#  - confederation peers 65020 65030 65040
#  - neighbor 192.168.1.100
#  - remote-as 65563
#  - affinity-group 160
#  - bmp-activate-server 1
#  - description NBR-1
#  - low-memory exempt
#  - neighbor 192.168.1.101
#  - remote-as 65563
#  - password 7 12090404011C03162E
#  - vrf site-1
#  - allocate-index 5000
#  - local-as 200
#  - log-neighbor-changes
#  - neighbor 198.51.100.1
#  - remote-as 65562
#  - description site-1-nbr-1
#  - password 3 13D4D3549493D2877B1DC116EE27A6BE
#  - neighbor 198.51.100.2
#  - remote-as 65562
#  - description site-1-nbr-2
#  - vrf site-2
#  - local-as 300
#  - log-neighbor-changes
#  - neighbor-down fib-accelerate
#  - neighbor 203.0.113.2
#  - remote-as 65568
#  - description site-2-nbr-1
#  - password 3 AF92F4C16A0A0EC5BDF56CF58BC030F6
#
# after:
#    as_number: '65563'
#    bestpath:
#      as_path:
#        multipath_relax: true
#      compare_neighborid: true
#      cost_community_ignore: true
#    confederation:
#      identifier: '42'
#      peers:
#      - '65020'
#      - '65030'
#      - '65040'
#    log_neighbor_changes: true
#    maxas_limit: 20
#    neighbor_down:
#      fib_accelerate: true
#    neighbors:
#    - bmp_activate_server: 1
#      description: NBR-1
#      low_memory:
#        exempt: true
#      neighbor_address: 192.168.1.100
#      neighbor_affinity_group:
#        group_id: 160
#      remote_as: '65563'
#    - neighbor_address: 192.168.1.101
#      password:
#        encryption: 7
#        key: 12090404011C03162E
#      remote_as: '65563'
#    router_id: 192.168.1.1
#    vrfs:
#    - allocate_index: 5000
#      local_as: '200'
#      log_neighbor_changes: true
#      neighbors:
#      - description: site-1-nbr-1
#        neighbor_address: 198.51.100.1
#        password:
#          encryption: 3
#          key: 13D4D3549493D2877B1DC116EE27A6BE
#        remote_as: '65562'
#      - description: site-1-nbr-2
#        neighbor_address: 198.51.100.2
#        remote_as: '65562'
#      vrf: site-1
#    - local_as: '300'
#      log_neighbor_changes: true
#      neighbor_down:
#        fib_accelerate: true
#      neighbors:
#      - description: site-2-nbr-1
#        neighbor_address: 203.0.113.2
#        password:
#          encryption: 3
#          key: AF92F4C16A0A0EC5BDF56CF58BC030F6
#        remote_as: '65568'
#      vrf: site-2


# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65563
#   router-id 192.168.1.1
#   confederation identifier 42
#   confederation peers 65020 65030 65040
#   bestpath as-path multipath-relax
#   bestpath cost-community ignore
#   bestpath compare-neighborid
#   neighbor-down fib-accelerate
#   maxas-limit 20
#   log-neighbor-changes
#   neighbor 192.168.1.100
#     low-memory exempt
#     bmp-activate-server 1
#     remote-as 65563
#     description NBR-1
#     affinity-group 160
#   neighbor 192.168.1.101
#     remote-as 65563
#     password 7 12090404011C03162E
#   vrf site-1
#     local-as 200
#     log-neighbor-changes
#     allocate-index 5000
#     neighbor 198.51.100.1
#       remote-as 65562
#       description site-1-nbr-1
#       password 3 13D4D3549493D2877B1DC116EE27A6BE
#     neighbor 198.51.100.2
#       remote-as 65562
#       description site-1-nbr-2
#   vrf site-2
#     local-as 300
#     neighbor-down fib-accelerate
#     log-neighbor-changes
#     neighbor 203.0.113.2
#       remote-as 65568
#       description site-2-nbr-1
#       password 3 AF92F4C16A0A0EC5BDF56CF58BC030F6

# Using replaced

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65563
#   router-id 192.168.1.1
#   confederation identifier 42
#   confederation peers 65020 65030 65040
#   bestpath as-path multipath-relax
#   bestpath cost-community ignore
#   bestpath compare-neighborid
#   neighbor-down fib-accelerate
#   maxas-limit 20
#   log-neighbor-changes
#   neighbor 192.168.1.100
#     low-memory exempt
#     bmp-activate-server 1
#     remote-as 65563
#     description NBR-1
#     affinity-group 160
#   neighbor 192.168.1.101
#     remote-as 65563
#     password 7 12090404011C03162E
#   vrf site-1
#     local-as 200
#     log-neighbor-changes
#     allocate-index 5000
#     neighbor 198.51.100.1
#       remote-as 65562
#       description site-1-nbr-1
#       password 3 13D4D3549493D2877B1DC116EE27A6BE
#     neighbor 198.51.100.2
#       remote-as 65562
#       description site-1-nbr-2
#   vrf site-2
#     local-as 300
#     neighbor-down fib-accelerate
#     log-neighbor-changes
#     neighbor 203.0.113.2
#       remote-as 65568
#       description site-2-nbr-1
#       password 3 AF92F4C16A0A0EC5BDF56CF58BC030F6

- name: Replace BGP configuration with provided configuration
  cisco.nxos.nxos_bgp_global:
    config:
      as_number: 65563
      router_id: 192.168.1.1
      bestpath:
        compare_neighborid: true
        cost_community_ignore: true
      confederation:
        identifier: 42
        peers:
          - 65020
          - 65030
          - 65050
      maxas_limit: 40
      neighbors:
        - neighbor_address: 192.168.1.100
          neighbor_affinity_group:
            group_id: 160
          bmp_activate_server: 1
          remote_as: 65563
          description: NBR-1
          low_memory:
            exempt: true
      neighbor_down:
        fib_accelerate: true
      vrfs:
        - vrf: site-2
          local_as: 300
          log_neighbor_changes: true
          neighbors:
            - neighbor_address: 203.0.113.2
              password:
                encryption: 7
                key: 12090404011C03162E
          neighbor_down:
            fib_accelerate: true
    state: replaced

# Task output:
# ------------
#  before:
#    as_number: '65563'
#    bestpath:
#      as_path:
#        multipath_relax: true
#      compare_neighborid: true
#      cost_community_ignore: true
#    confederation:
#      identifier: '42'
#      peers:
#      - '65020'
#      - '65030'
#      - '65040'
#    log_neighbor_changes: true
#    maxas_limit: 20
#    neighbor_down:
#      fib_accelerate: true
#    neighbors:
#    - bmp_activate_server: 1
#      description: NBR-1
#      low_memory:
#        exempt: true
#      neighbor_address: 192.168.1.100
#      neighbor_affinity_group:
#        group_id: 160
#      remote_as: '65563'
#    - neighbor_address: 192.168.1.101
#      password:
#        encryption: 7
#        key: 12090404011C03162E
#      remote_as: '65563'
#    router_id: 192.168.1.1
#    vrfs:
#    - allocate_index: 5000
#      local_as: '200'
#      log_neighbor_changes: true
#      neighbors:
#      - description: site-1-nbr-1
#        neighbor_address: 198.51.100.1
#        password:
#          encryption: 3
#          key: 13D4D3549493D2877B1DC116EE27A6BE
#        remote_as: '65562'
#      - description: site-1-nbr-2
#        neighbor_address: 198.51.100.2
#        remote_as: '65562'
#      vrf: site-1
#    - local_as: '300'
#      log_neighbor_changes: true
#      neighbor_down:
#        fib_accelerate: true
#      neighbors:
#      - description: site-2-nbr-1
#        neighbor_address: 203.0.113.2
#        password:
#          encryption: 3
#          key: AF92F4C16A0A0EC5BDF56CF58BC030F6
#        remote_as: '65568'
#      vrf: site-2
#
# commands:
#  - router bgp 65563
#  - no bestpath as-path multipath-relax
#  - no log-neighbor-changes
#  - maxas-limit 40
#  - no confederation peers 65020 65030 65040
#  - confederation peers 65020 65030 65050
#  - no neighbor 192.168.1.101
#  - vrf site-2
#  - neighbor 203.0.113.2
#  - no remote-as 65568
#  - no description site-2-nbr-1
#  - password 7 12090404011C03162E
#  - no vrf site-1

#  after:
#    as_number: '65563'
#    bestpath:
#      compare_neighborid: true
#      cost_community_ignore: true
#    confederation:
#      identifier: '42'
#      peers:
#      - '65020'
#      - '65030'
#      - '65050'
#    maxas_limit: 40
#    neighbor_down:
#      fib_accelerate: true
#    neighbors:
#    - bmp_activate_server: 1
#      description: NBR-1
#      low_memory:
#        exempt: true
#      neighbor_address: 192.168.1.100
#      neighbor_affinity_group:
#        group_id: 160
#      remote_as: '65563'
#    router_id: 192.168.1.1
#    vrfs:
#    - local_as: '300'
#      log_neighbor_changes: true
#      neighbor_down:
#        fib_accelerate: true
#      neighbors:
#      - neighbor_address: 203.0.113.2
#        password:
#          encryption: 7
#          key: 12090404011C03162E
#      vrf: site-2
#
# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65563
#   router-id 192.168.1.1
#   confederation identifier 42
#   confederation peers 65020 65030 65050
#   bestpath cost-community ignore
#   bestpath compare-neighborid
#   neighbor-down fib-accelerate
#   maxas-limit 40
#   neighbor 192.168.1.100
#     low-memory exempt
#     bmp-activate-server 1
#     remote-as 65563
#     description NBR-1
#     affinity-group 160
#   vrf site-2
#     local-as 300
#     neighbor-down fib-accelerate
#     log-neighbor-changes
#     neighbor 203.0.113.2
#       password 7 12090404011C03162E

# Using deleted

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65563
#   router-id 192.168.1.1
#   confederation identifier 42
#   confederation peers 65020 65030 65040
#   bestpath as-path multipath-relax
#   bestpath cost-community ignore
#   bestpath compare-neighborid
#   neighbor-down fib-accelerate
#   maxas-limit 20
#   log-neighbor-changes
#   address-family ipv4 unicast
#     default-metric 400
#     suppress-inactive
#     default-information originate
#   address-family ipv6 multicast
#     wait-igp-convergence
#     redistribute eigrp eigrp-1 route-map site-1-rmap
#   neighbor 192.168.1.100
#     low-memory exempt
#     bmp-activate-server 1
#     remote-as 65563
#     description NBR-1
#     affinity-group 160
#   neighbor 192.168.1.101
#     remote-as 65563
#     password 7 12090404011C03162E
#   vrf site-1
#     local-as 200
#     log-neighbor-changes
#     allocate-index 5000
#     address-family ipv4 multicast
#       maximum-paths 40
#       dampen-igp-metric 1200
#     neighbor 198.51.100.1
#       remote-as 65562
#       description site-1-nbr-1
#       password 3 13D4D3549493D2877B1DC116EE27A6BE
#     neighbor 198.51.100.2
#       remote-as 65562
#       description site-1-nbr-2
#   vrf site-2
#     local-as 300
#     neighbor-down fib-accelerate
#     log-neighbor-changes
#     neighbor 203.0.113.2
#       remote-as 65568
#       description site-1-nbr-1
#       password 3 AF92F4C16A0A0EC5BDF56CF58BC030F6

- name: Delete BGP configurations handled by this module
  cisco.nxos.nxos_bgp_global:
    state: deleted

# Task output:
# ------------

# before:
#    as_number: '65563'
#    bestpath:
#      as_path:
#        multipath_relax: true
#      compare_neighborid: true
#      cost_community_ignore: true
#    confederation:
#      identifier: '42'
#      peers:
#      - '65020'
#      - '65030'
#      - '65040'
#    log_neighbor_changes: true
#    maxas_limit: 20
#    neighbor_down:
#      fib_accelerate: true
#    neighbors:
#    - bmp_activate_server: 1
#      description: NBR-1
#      low_memory:
#        exempt: true
#      neighbor_address: 192.168.1.100
#      neighbor_affinity_group:
#        group_id: 160
#      remote_as: '65563'
#    - neighbor_address: 192.168.1.101
#      password:
#        encryption: 7
#        key: 12090404011C03162E
#      remote_as: '65563'
#    router_id: 192.168.1.1
#    vrfs:
#    - allocate_index: 5000
#      local_as: '200'
#      log_neighbor_changes: true
#      neighbors:
#      - description: site-1-nbr-1
#        neighbor_address: 198.51.100.1
#        password:
#          encryption: 3
#          key: 13D4D3549493D2877B1DC116EE27A6BE
#        remote_as: '65562'
#      - description: site-1-nbr-2
#        neighbor_address: 198.51.100.2
#        remote_as: '65562'
#      vrf: site-1
#    - local_as: '300'
#      log_neighbor_changes: true
#      neighbor_down:
#        fib_accelerate: true
#      neighbors:
#      - description: site-1-nbr-1
#        neighbor_address: 203.0.113.2
#        password:
#          encryption: 3
#          key: AF92F4C16A0A0EC5BDF56CF58BC030F6
#        remote_as: '65568'
#      vrf: site-2
#
# commands:
#   - router bgp 65563
#   - no bestpath as-path multipath-relax
#   - no bestpath compare-neighborid
#   - no bestpath cost-community ignore
#   - no confederation identifier 42
#   - no log-neighbor-changes
#   - no maxas-limit 20
#   - no neighbor-down fib-accelerate
#   - no router-id 192.168.1.1
#   - no confederation peers 65020 65030 65040
#   - no neighbor 192.168.1.100
#   - no neighbor 192.168.1.101
#   - no vrf site-1
#   - no vrf site-2
#
#  after:
#    as_number: '65563'
#
# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65563
#   address-family ipv4 unicast
#     default-metric 400
#     suppress-inactive
#     default-information originate
#   address-family ipv6 multicast
#     wait-igp-convergence
#     redistribute eigrp eigrp-1 route-map site-1-rmap
#

# Using purged

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65563
#   router-id 192.168.1.1
#   confederation identifier 42
#   confederation peers 65020 65030 65040
#   bestpath as-path multipath-relax
#   bestpath cost-community ignore
#   bestpath compare-neighborid
#   neighbor-down fib-accelerate
#   maxas-limit 20
#   log-neighbor-changes
#   address-family ipv4 unicast
#     default-metric 400
#     suppress-inactive
#     default-information originate
#   address-family ipv6 multicast
#     wait-igp-convergence
#     redistribute eigrp eigrp-1 route-map site-1-rmap
#   neighbor 192.168.1.100
#     low-memory exempt
#     bmp-activate-server 1
#     remote-as 65563
#     description NBR-1
#     affinity-group 160
#   neighbor 192.168.1.101
#     remote-as 65563
#     password 7 12090404011C03162E
#   vrf site-1
#     local-as 200
#     log-neighbor-changes
#     allocate-index 5000
#     address-family ipv4 multicast
#       maximum-paths 40
#       dampen-igp-metric 1200
#     neighbor 198.51.100.1
#       remote-as 65562
#       description site-1-nbr-1
#       password 3 13D4D3549493D2877B1DC116EE27A6BE
#     neighbor 198.51.100.2
#       remote-as 65562
#       description site-1-nbr-2
#   vrf site-2
#     local-as 300
#     neighbor-down fib-accelerate
#     log-neighbor-changes
#     neighbor 203.0.113.2
#       remote-as 65568
#       description site-1-nbr-1
#       password 3 AF92F4C16A0A0EC5BDF56CF58BC030F6

- name: Purge all BGP configurations from the device
  cisco.nxos.nxos_bgp_global:
    state: purged

# Task output:
# ------------

# before:
#    as_number: '65563'
#    bestpath:
#      as_path:
#        multipath_relax: true
#      compare_neighborid: true
#      cost_community_ignore: true
#    confederation:
#      identifier: '42'
#      peers:
#      - '65020'
#      - '65030'
#      - '65040'
#    log_neighbor_changes: true
#    maxas_limit: 20
#    neighbor_down:
#      fib_accelerate: true
#    neighbors:
#    - bmp_activate_server: 1
#      description: NBR-1
#      low_memory:
#        exempt: true
#      neighbor_address: 192.168.1.100
#      neighbor_affinity_group:
#        group_id: 160
#      remote_as: '65563'
#    - neighbor_address: 192.168.1.101
#      password:
#        encryption: 7
#        key: 12090404011C03162E
#      remote_as: '65563'
#    router_id: 192.168.1.1
#    vrfs:
#    - allocate_index: 5000
#      local_as: '200'
#      log_neighbor_changes: true
#      neighbors:
#      - description: site-1-nbr-1
#        neighbor_address: 198.51.100.1
#        password:
#          encryption: 3
#          key: 13D4D3549493D2877B1DC116EE27A6BE
#        remote_as: '65562'
#      - description: site-1-nbr-2
#        neighbor_address: 198.51.100.2
#        remote_as: '65562'
#      vrf: site-1
#    - local_as: '300'
#      log_neighbor_changes: true
#      neighbor_down:
#        fib_accelerate: true
#      neighbors:
#      - description: site-1-nbr-1
#        neighbor_address: 203.0.113.2
#        password:
#          encryption: 3
#          key: AF92F4C16A0A0EC5BDF56CF58BC030F6
#        remote_as: '65568'
#      vrf: site-2
#
# commands:
#   - no router bgp 65563
#
#  after: {}
#
# After state:
# ------------
# Nexus9000v# show running-config | section "^router bgp"
# Nexus9000v#

# Using rendered

- name: Render platform specific configuration lines (without connecting to the device)
  cisco.nxos.nxos_bgp_global:
    config:
      as_number: 65563
      router_id: 192.168.1.1
      bestpath:
        as_path:
          multipath_relax: true
        compare_neighborid: true
        cost_community_ignore: true
      confederation:
        identifier: 42
        peers:
          - 65020
          - 65030
          - 65040
      log_neighbor_changes: true
      maxas_limit: 20
      neighbors:
        - neighbor_address: 192.168.1.100
          neighbor_affinity_group:
            group_id: 160
          bmp_activate_server: 1
          remote_as: 65563
          description: NBR-1
          low_memory:
            exempt: true
        - neighbor_address: 192.168.1.101
          remote_as: 65563
          password:
            encryption: 7
            key: 12090404011C03162E
      neighbor_down:
        fib_accelerate: true
      vrfs:
        - vrf: site-1
          allocate_index: 5000
          local_as: 200
          log_neighbor_changes: true
          neighbors:
            - neighbor_address: 198.51.100.1
              description: site-1-nbr-1
              password:
                encryption: 3
                key: 13D4D3549493D2877B1DC116EE27A6BE
              remote_as: 65562
            - neighbor_address: 198.51.100.2
              remote_as: 65562
              description: site-1-nbr-2
        - vrf: site-2
          local_as: 300
          log_neighbor_changes: true
          neighbors:
            - neighbor_address: 203.0.113.2
              description: site-1-nbr-1
              password:
                encryption: 3
                key: AF92F4C16A0A0EC5BDF56CF58BC030F6
              remote_as: 65568
          neighbor_down:
            fib_accelerate: true

# Task output:
# ------------
# rendered:
#   - router bgp 65563
#   - bestpath as-path multipath-relax
#   - bestpath compare-neighborid
#   - bestpath cost-community ignore
#   - confederation identifier 42
#   - log-neighbor-changes
#   - maxas-limit 20
#   - neighbor-down fib-accelerate
#   - router-id 192.168.1.1
#   - confederation peers 65020 65030 65040
#   - neighbor 192.168.1.100
#   - remote-as 65563
#   - affinity-group 160
#   - bmp-activate-server 1
#   - description NBR-1
#   - low-memory exempt
#   - neighbor 192.168.1.101
#   - remote-as 65563
#   - password 7 12090404011C03162E
#   - vrf site-1
#   - allocate-index 5000
#   - local-as 200
#   - log-neighbor-changes
#   - neighbor 198.51.100.1
#   - remote-as 65562
#   - description site-1-nbr-1
#   - password 3 13D4D3549493D2877B1DC116EE27A6BE
#   - neighbor 198.51.100.2
#   - remote-as 65562
#   - description site-1-nbr-2
#   - vrf site-2
#   - local-as 300
#   - log-neighbor-changes
#   - neighbor-down fib-accelerate
#   - neighbor 203.0.113.2
#   - remote-as 65568
#   - description site-1-nbr-1
#   - password 3 AF92F4C16A0A0EC5BDF56CF58BC030F6

# Using parsed

# parsed.cfg
# ------------
# router bgp 65563
#   router-id 192.168.1.1
#   confederation identifier 42
#   confederation peers 65020 65030 65040
#   bestpath as-path multipath-relax
#   bestpath cost-community ignore
#   bestpath compare-neighborid
#   neighbor-down fib-accelerate
#   maxas-limit 20
#   log-neighbor-changes
#   neighbor 192.168.1.100
#     low-memory exempt
#     bmp-activate-server 1
#     remote-as 65563
#     description NBR-1
#     affinity-group 160
#   neighbor 192.168.1.101
#     remote-as 65563
#     password 7 12090404011C03162E
#   vrf site-1
#     local-as 200
#     log-neighbor-changes
#     allocate-index 5000
#     neighbor 198.51.100.1
#       remote-as 65562
#       description site-1-nbr-1
#       password 3 13D4D3549493D2877B1DC116EE27A6BE
#     neighbor 198.51.100.2
#       remote-as 65562
#       description site-1-nbr-2
#   vrf site-2
#     local-as 300
#     neighbor-down fib-accelerate
#     log-neighbor-changes
#     neighbor 203.0.113.2
#       remote-as 65568
#       description site-1-nbr-1
#       password 3 AF92F4C16A0A0EC5BDF56CF58BC030F6

- name: Parse externally provided BGP config
  cisco.nxos.nxos_bgp_global:
    running_config: "{{ lookup('file', 'parsed.cfg') }}"
    state: parsed

# Task output:
# ------------
#  parsed:
#    as_number: '65563'
#    bestpath:
#      as_path:
#        multipath_relax: true
#      compare_neighborid: true
#      cost_community_ignore: true
#    confederation:
#      identifier: '42'
#      peers:
#      - '65020'
#      - '65030'
#      - '65040'
#    log_neighbor_changes: true
#    maxas_limit: 20
#    neighbor_down:
#      fib_accelerate: true
#    neighbors:
#    - bmp_activate_server: 1
#      description: NBR-1
#      low_memory:
#        exempt: true
#      neighbor_address: 192.168.1.100
#      neighbor_affinity_group:
#        group_id: 160
#      remote_as: '65563'
#    - neighbor_address: 192.168.1.101
#      password:
#        encryption: 7
#        key: 12090404011C03162E
#      remote_as: '65563'
#    router_id: 192.168.1.1
#    vrfs:
#    - allocate_index: 5000
#      local_as: '200'
#      log_neighbor_changes: true
#      neighbors:
#      - description: site-1-nbr-1
#        neighbor_address: 198.51.100.1
#        password:
#          encryption: 3
#          key: 13D4D3549493D2877B1DC116EE27A6BE
#        remote_as: '65562'
#      - description: site-1-nbr-2
#        neighbor_address: 198.51.100.2
#        remote_as: '65562'
#      vrf: site-1
#    - local_as: '300'
#      log_neighbor_changes: true
#      neighbor_down:
#        fib_accelerate: true
#      neighbors:
#      - description: site-1-nbr-1
#        neighbor_address: 203.0.113.2
#        password:
#          encryption: 3
#          key: AF92F4C16A0A0EC5BDF56CF58BC030F6
#        remote_as: '65568'
#      vrf: site-2

# Using gathered

# existing config
#
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65563
#   router-id 192.168.1.1
#   confederation identifier 42
#   confederation peers 65020 65030 65050
#   bestpath cost-community ignore
#   bestpath compare-neighborid
#   neighbor-down fib-accelerate
#   maxas-limit 40
#   neighbor 192.168.1.100
#     low-memory exempt
#     bmp-activate-server 1
#     remote-as 65563
#     description NBR-1
#     affinity-group 160
#   vrf site-1
#   vrf site-2
#     local-as 300
#     neighbor-down fib-accelerate
#     log-neighbor-changes
#     neighbor 203.0.113.2
#       password 7 12090404011C03162E

- name: Gather BGP facts using gathered
  cisco.nxos.nxos_bgp_global:
    state: gathered

# Task output:
# ------------
#  gathered:
#    as_number: '65563'
#    bestpath:
#      compare_neighborid: true
#      cost_community_ignore: true
#    confederation:
#      identifier: '42'
#      peers:
#      - '65020'
#      - '65030'
#      - '65050'
#    maxas_limit: 40
#    neighbor_down:
#      fib_accelerate: true
#    neighbors:
#    - bmp_activate_server: 1
#      description: NBR-1
#      low_memory:
#        exempt: true
#      neighbor_address: 192.168.1.100
#      neighbor_affinity_group:
#        group_id: 160
#      remote_as: '65563'
#    router_id: 192.168.1.1
#    vrfs:
#    - vrf: site-1
#    - local_as: '300'
#      log_neighbor_changes: true
#      neighbor_down:
#        fib_accelerate: true
#      neighbors:
#      - neighbor_address: 203.0.113.2
#        password:
#          encryption: 7
#          key: 12090404011C03162E
#      vrf: site-2

# Remove a neighbor having AF configurations with state replaced (will fail)

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   log-neighbor-changes
#   maxas-limit 20
#   router-id 198.51.100.2
#   neighbor 203.0.113.2
#     address-family ipv4 unicast
#       next-hop-self
#     remote-as 65538
#     affinity-group 160
#     description NBR-1
#     low-memory exempt
#   neighbor 192.0.2.1
#     remote-as 65537
#     password 7 12090404011C03162E

- name: Remove a neighbor having AF configurations (should fail)
  cisco.nxos.nxos_bgp_global:
    config:
      as_number: 65536
      router_id: 198.51.100.2
      maxas_limit: 20
      log_neighbor_changes: true
      neighbors:
        - neighbor_address: 192.0.2.1
          remote_as: 65537
          password:
            encryption: 7
            key: 12090404011C03162E
    state: replaced

# Task output:
# ------------
# fatal: [Nexus9000v]: FAILED! => changed=false
#    msg: Neighbor 203.0.113.2 has address-family configurations.
#         Please use the nxos_bgp_neighbor_af module to remove those first.

# Remove a VRF having AF configurations with state replaced (will fail)

# Before state:
# -------------
# Nexus9000v# show running-config | section "^router bgp"
# router bgp 65536
#   log-neighbor-changes
#   maxas-limit 20
#   router-id 198.51.100.2
#   neighbor 192.0.2.1
#     remote-as 65537
#     password 7 12090404011C03162E
#   vrf site-1
#     address-family ipv4 unicast
#       default-information originate
#     neighbor 203.0.113.2
#       remote-as 65538
#       affinity-group 160
#       description NBR-1
#       low-memory exempt
#   vrf site-2
#     neighbor-down fib-accelerate

- name: Remove a VRF having AF configurations (should fail)
  cisco.nxos.nxos_bgp_global:
    config:
      as_number: 65536
      router_id: 198.51.100.2
      maxas_limit: 20
      log_neighbor_changes: true
      neighbors:
        - neighbor_address: 192.0.2.1
          remote_as: 65537
          password:
            encryption: 7
            key: 12090404011C03162E
      vrfs:
        - vrf: site-2
          neighbor_down:
            fib_accelerate: true
    state: replaced

# Task output:
# ------------
# fatal: [Nexus9000v]: FAILED! => changed=false
#    msg: VRF site-1 has address-family configurations.
#         Please use the nxos_bgp_af module to remove those first.
"""

RETURN = """
before:
  description: The configuration prior to the model invocation.
  returned: always
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
after:
  description: The resulting configuration model invocation.
  returned: when changed
  type: dict
  sample: >
    The configuration returned will always be in the same format
     of the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample:
    - router bgp 65563
    - maxas-limit 20
    - router-id 192.168.1.1
    - confederation peers 65020 65030 65040
    - neighbor 192.168.1.100
    - remote-as 65563
    - affinity-group 160
    - bmp-activate-server 1
    - description NBR-1
    - low-memory exempt
    - vrf site-1
    - log-neighbor-changes
    - neighbor 198.51.100.1
    - remote-as 65562
    - description site-1-nbr-1
    - password 3 13D4D3549493D2877B1DC116EE27A6BE
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
    - router bgp 65563
    - maxas-limit 20
    - router-id 192.168.1.1
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when I(state) is C(gathered)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
parsed:
  description: The device native config provided in I(running_config) option parsed into structured data as per module argspec.
  returned: when I(state) is C(parsed)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.argspec.bgp_global.bgp_global import (
    Bgp_globalArgs,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.config.bgp_global.bgp_global import (
    Bgp_global,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    module = AnsibleModule(
        argument_spec=Bgp_globalArgs.argument_spec,
        mutually_exclusive=[["config", "running_config"]],
        required_if=[
            ["state", "merged", ["config"]],
            ["state", "replaced", ["config"]],
            ["state", "rendered", ["config"]],
            ["state", "parsed", ["running_config"]],
        ],
        supports_check_mode=True,
    )

    result = Bgp_global(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
