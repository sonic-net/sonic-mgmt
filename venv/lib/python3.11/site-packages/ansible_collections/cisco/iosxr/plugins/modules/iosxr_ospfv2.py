#!/usr/bin/python
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

"""
The module file for iosxr_ospfv2
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
module: iosxr_ospfv2
short_description: Resource module to configure OSPFv2.
description: This module manages global OSPFv2 configuration on devices running Cisco
  IOS-XR
version_added: 1.0.0
author:
- Rohit Thakur (@rohitthakur2590)
notes:
- This module works with connection C(network_cli). See L(the IOS-XR Platform Options,../network/user_guide/platform_iosxr.html)
options:
  config:
    description: A list of OSPFv2 process configuration
    type: dict
    suboptions:
      processes:
        description: A list of OSPFv2 instances configuration
        type: list
        elements: dict
        suboptions:
          address_family_unicast:
            description: Enable unicast topology for ipv4 address family
            type: bool
          adjacency_stagger:
            description: Stagger OSPFv2 adjacency bring up
            type: dict
            suboptions:
              min_adjacency:
                description: Initial number of neighbors to bring up per area (default
                  2)
                type: int
              max_adjacency:
                description: Maximum simultaneous neighbors to bring up
                type: int
              disable:
                description: Disable stagger OSPFv2 adjacency
                type: bool
          authentication:
            description: Enable authentication
            type: dict
            suboptions:
              keychain:
                description: Specify keychain name
                type: str
              message_digest:
                description: Use message-digest authentication
                type: dict
                suboptions:
                  set:
                    description: Specify message-digest selection
                    type: bool
                  keychain:
                    description: Specify keychain name
                    type: str
              no_auth:
                description: Use no authentication
                type: bool
          apply_weight:
            description: Enable weights configured under interfaces for load sharing
            type: dict
            suboptions:
              bandwidth:
                description: Reference bandwidth to use for calculation (Mbits/sec)
                type: int
              default_weight:
                description: Specify default weight value to use when it is not configured
                  under interface
                type: int
          areas:
            description: Configure OSPFv2 areas' properties
            type: list
            elements: dict
            suboptions:
              area_id:
                description: Area ID as IP address or integer
                type: str
                required: true
              authentication:
                description: Enable authentication
                type: dict
                suboptions:
                  keychain:
                    description: Specify keychain name
                    type: str
                  message_digest:
                    description: Use message-digest authentication
                    type: dict
                    suboptions:
                      keychain:
                        description: Specify keychain name
                        type: str
                  no_auth:
                    description: Use no authentication
                    type: bool
              authentication_key:
                description: Used to mention authentication password (key)
                type: dict
                suboptions:
                  password:
                    description: The OSPFv2 password (key)
                    type: str
                  clear:
                    description: Specifies an UNENCRYPTED password (key) will follow
                    type: str
                  encrypted:
                    description: Specifies an ENCRYPTED password (key) will follow
                    type: str
              default_cost:
                description: Set the summary default-cost of a NSSA/stub area. Stub's
                  advertised external route metric
                type: int
              cost:
                description: Interface cost
                type: int
              dead_interval:
                description: Interval after which a neighbor is declared dead
                type: int
              hello_interval:
                description: Time between HELLO packets
                type: int
              transmit_delay:
                description: Estimated time needed to send link-state update packet
                type: int
              mpls:
                description: Configure MPLS routing protocol parameters
                type: dict
                suboptions:
                  traffic_eng:
                    description: Configure an ospf area to run MPLS Traffic Engineering
                    type: bool
                  ldp:
                    description: Configure LDP parameters
                    type: dict
                    suboptions:
                      auto_config:
                        description: Enable LDP IGP interface auto-configuration
                        type: bool
                      sync:
                        description: Enable LDP IGP synchronization
                        type: bool
                      sync_igp_shortcuts:
                        description: LDP sync for igp-shortcut tunnels
                        type: bool
              mtu_ignore:
                description: Enable/Disable ignoring of MTU in DBD packets
                type: str
                choices:
                - enable
                - disable
              bfd:
                description: Configure BFD parameters
                type: dict
                suboptions:
                  fast_detect:
                    description: Configure fast detection
                    type: dict
                    suboptions:
                      set:
                        description: Enable fast detection only
                        type: bool
                      strict_mode:
                        description: Hold down neighbor session until BFD session is up
                        type: bool
                  minimum_interval:
                    description: Hello interval in milli-seconds
                    type: int
                  multiplier:
                    description: Detect multiplier
                    type: int
              nssa:
                description:
                - NSSA settings for the area
                type: dict
                suboptions:
                  set:
                    description: Configure area as NSSA
                    type: bool
                  default_information_originate:
                    description: Originate default Type 7 LSA
                    type: dict
                    suboptions:
                      metric:
                        description: OSPFv2 default metric
                        type: int
                      metric_type:
                        description: Metric type for default routes
                        type: int
                  no_redistribution:
                    description: Do not send redistributed LSAs into NSSA area
                    type: bool
                  no_summary:
                    description: Do not send summary LSAs into NSSA area
                    type: bool
                  translate:
                    description: Translate LSA
                    type: dict
                    suboptions:
                      type7:
                        description:
                        - Translate from Type 7 to Type 5
                        type: dict
                        suboptions:
                          always:
                            description:
                            - Always translate LSAs
                            type: bool
              ranges:
                description: Summarize routes matching address/mask (border routers
                  only)
                type: list
                elements: dict
                suboptions:
                  address:
                    description: IP in Prefix format (x.x.x.x/len)
                    type: str
                    required: true
                  advertise:
                    description: Advertise this range (default)
                    type: bool
                  not_advertise:
                    description: DoNotAdvertise this range
                    type: bool
              route_policy:
                description: Specify the route-policy to filter type 3 LSAs (list
                  can have one inbound and/or one outbound policy only)
                type: list
                elements: dict
                suboptions:
                  parameters:
                    description: Specify parameter values for the policy
                    type: list
                    elements: str
                  direction:
                    description: Specify inbound or outbound
                    type: str
                    choices:
                    - in
                    - out
              stub:
                description:
                - Settings for configuring the area as a stub
                type: dict
                suboptions:
                  set:
                    description:
                    - Configure the area as a stub
                    type: bool
                  no_summary:
                    description:
                    - Do not send summary LSA into stub area
                    type: bool
              virtual_link:
                description: Define a virtual link
                type: list
                elements: dict
                suboptions:
                  id:
                    description: Router-ID of virtual link neighbor (A.B.C.D)
                    type: str
                    required: true
                  authentication:
                    description: Enable authentication
                    type: dict
                    suboptions:
                      keychain:
                        description: Specify keychain name
                        type: str
                      message_digest:
                        description: Use message-digest authentication
                        type: dict
                        suboptions:
                          keychain:
                            description: Specify keychain name
                            type: str
                      no_auth:
                        description: Use no authentication
                        type: bool
                  authentication_key:
                    description: Used to mention authentication password (key)
                    type: dict
                    suboptions:
                      password:
                        description: The OSPFv2 password (key)
                        type: str
                      clear:
                        description: Specifies an UNENCRYPTED password (key) will
                          follow
                        type: str
                      encrypted:
                        description: Specifies an ENCRYPTED password (key) will follow
                        type: str
                  dead_interval:
                    description: Interval after which a neighbor is declared dead
                    type: int
                  hello_interval:
                    description: Time between HELLO packets
                    type: int
                  retransmit_interval:
                    description: Delay between LSA retransmissions
                    type: int
                  transmit_delay:
                    description: Link state transmit delay
                    type: int
                  message_digest_key:
                    description: Message digest authentication password (key)
                    type: dict
                    suboptions:
                      id:
                        description: Key ID (1-255)
                        type: int
                        required: true
                      md5:
                        description: Use MD5 Algorithm
                        type: dict
                        suboptions:
                          password:
                            description: The OSPFv2 password (key)
                            type: str
                          clear:
                            description: Specifies an UNENCRYPTED password (key) will
                              follow
                            type: bool
                          encrypted:
                            description: Specifies an ENCRYPTED password (key) will
                              follow
                            type: bool

          authentication_key:
            description: Used to mention authentication password (key)
            type: dict
            suboptions:
              password:
                description: The OSPFv2 password (key)
                type: str
              clear:
                description: Specifies an UNENCRYPTED password (key) will follow
                type: bool
              encrypted:
                description: Specifies an ENCRYPTED password (key) will follow
                type: bool
          auto_cost:
            description: Calculate OSPFv2 interface cost according to bandwidth
            type: dict
            suboptions:
              reference_bandwidth:
                description: Specify reference bandwidth in megabits per sec
                type: int
              disable:
                description: Assign OSPFv2 cost based on interface type
                type: bool
          bfd:
            description: Configure BFD parameters
            type: dict
            suboptions:
              fast_detect:
                description: Configure fast detection
                type: dict
                suboptions:
                  set:
                    description: Enable fast detection only
                    type: bool
                  strict_mode:
                    description: Hold down neighbor session until BFD session is up
                    type: bool
              minimum_interval:
                description: Hello interval in milli-seconds
                type: int
              multiplier:
                description: Detect multiplier
                type: int
          capability:
            description: Enable specific OSPFv2 feature
            type: dict
            suboptions:
              type7:
                description: NSSA capability
                type: str
              opaque:
                description: Configure opaque LSA
                type: dict
                suboptions:
                  disable:
                    description: Disable Opaque LSA capability
                    type: bool
                  set:
                    description: Enable opaque LSA
                    type: bool
          cost:
            description: Interface cost (1-65535)
            type: int
          database_filter:
            description: Filter OSPFv2 LSA during synchronization and flooding (all
              outgoing LSA). Enable/Disable filtering
            type: str
            choices: [enable, disable]
          dead_interval:
            description: Interval after which a neighbor is declared dead
            type: int
          default_information_originate:
            description: Distribute default route
            type: dict
            suboptions:
              always:
                description: Always advertise default route
                type: bool
              metric:
                description: OSPFv2 default metric
                type: int
              metric_type:
                description: OSPFv2 metric type for default routes
                type: int
              route_policy:
                description: Apply route-policy to default-information origination
                type: str
              set:
                description: Enable distribution of default route
                type: bool
          default_metric:
            description: Set metric of redistributed routes
            type: int
          demand_circuit:
            description: Enable/Disable OSPFv2 demand circuit
            type: str
            choices: [enable, disable]
          distance:
            description: Define an administrative distance
            type: dict
            suboptions:
              admin_distance:
                description: Administrative distance
                type: list
                elements: dict
                suboptions:
                  value:
                    description: Distance value
                    type: int
                  source:
                    description: Source IP address
                    type: str
                  wildcard:
                    description: IP wild card bits (A.B.C.D)
                    type: str
                  access_list:
                    description: Access list name
                    type: str
              ospf_distance:
                description: OSPFv2 administrative distance
                type: dict
                suboptions:
                  external:
                    description: Distance for external routes
                    type: int
                  inter_area:
                    description: Distance for inter-area routes
                    type: int
                  intra_area:
                    description: Distance for intra-area routes
                    type: int
          distribute_link_state:
            description: Enable Distribution of LSAs to external services
            type: dict
            suboptions:
              instance_id:
                description: Set distribution process instance identifier
                type: int
              throttle:
                description: Throttle time between successive LSA updates
                type: int
          distribute_bgp_ls:
            description: Enable Distribution of LSAs to external services
            type: dict
            suboptions:
              instance_id:
                description: Set distribution process instance identifier
                type: int
              throttle:
                description: Throttle time between successive LSA updates
                type: int
          distribute_list:
            description: Filter networks in routing updates (list can have one inbound
              and/or one outbound policy only)
            type: list
            elements: dict
            suboptions:
              access_list:
                description: Inbound/outbound access-list
                type: str
              direction:
                description: Filter incoming/outgoing routing updates
                type: str
                choices:
                - in
                - out
              outgoing_params:
                description: Specify additional parameters for outgoing updates only
                type: dict
                suboptions:
                  route_type:
                    description: Type of routes
                    type: str
                    choices:
                    - bgp
                    - connected
                    - dagr
                    - ospf
                    - static
                  id:
                    description:
                    - For BGP, specify AS number. 2-byte AS number (or) 4-byte AS
                      number in asdot (X.Y) format (or) 4-byte AS number in asplain
                      format
                    - For OSPF, specify OSPFv2 instance name
                    type: str
              route_policy:
                description: Route Policy to filter OSPFv2 prefixes (for incoming
                  updates only)
                type: str
          external_out:
            description: Enable/Disable advertisement of intra-area prefixes as external
            type: str
            choices:
            - enable
            - disable
          flood_reduction:
            description: Enable/Disable OSPFv2 Flood Reduction
            type: str
            choices:
            - enable
            - disable
          hello_interval:
            description: Time between HELLO packets (<1-65535> seconds)
            type: int
          ignore_lsa_mospf:
            description: Do not complain upon receiving MOSPFv2 Type 6 LSA
            type: bool
          link_down_fast_detect:
            description: Enable fast or early detection of link-down events
            type: bool
          log_adjacency_changes:
            description: Log adjacency state changes
            type: dict
            suboptions:
              set:
                description: Set log adjacency
                type: bool
              disable:
                description: Disable log adjacency changes
                type: bool
              detail:
                description: Log all state changes
                type: bool
          loopback_stub_network:
            description: Advertise loopback as a stub network
            type: str
            choices:
            - enable
            - disable
          max_lsa:
            description:
            - Feature to limit the number of non-self-originated LSAs
            type: dict
            suboptions:
              threshold:
                description:
                - Threshold value (%) at which to generate a warning message
                type: int
              ignore_count:
                description:
                - Set count on how many times adjacencies can be suppressed
                type: int
              ignore_time:
                description:
                - Set number of minutes during which all adjacencies are suppressed
                type: int
              reset_time:
                description:
                - Set number of minutes after which ignore-count is reset to zero
                type: int
              warning_only:
                description:
                - Log a warning message when limit is exceeded
                type: bool
          max_metric:
            description: Set maximum metric
            type: dict
            suboptions:
              router_lsa:
                description: Maximum metric in self-originated router-LSAs
                type: dict
                suboptions:
                  set:
                    description: Set router-lsa attribute
                    type: bool
                  external_lsa:
                    description: External LSA configuration
                    type: dict
                    suboptions:
                      set:
                        description: Set external-lsa attribute
                        type: bool
                      max_metric_value:
                        description: Set max metric value for external LSAs
                        type: int
                  include_stub:
                    description:
                    - Advertise Max metric for Stub links as well
                    type: bool
                  on_startup:
                    description:
                    - Effective only at startup
                    type: dict
                    suboptions:
                      set:
                        description:
                        - Set on-startup attribute
                        type: bool
                      wait_period:
                        description:
                        - Wait period in seconds after startup
                        type: int
                      wait_for_bgp_asn:
                        description:
                        - ASN of BGP to wait for
                        type: int
                  summary_lsa:
                    description:
                    - Summary LSAs configuration
                    type: dict
                    suboptions:
                      set:
                        description:
                        - Set summary-lsa attribute
                        type: bool
                      max_metric_value:
                        description:
                        - Max metric value for summary LSAs
                        type: int
          message_digest_key:
            description: Message digest authentication password (key)
            type: dict
            suboptions:
              id:
                description: Key ID
                type: int
                required: true
              md5:
                description: Use MD5 Algorithm
                type: dict
                required: true
                suboptions:
                  password:
                    description: The OSPFv2 password (key)
                    type: str
                  clear:
                    description: Specifies an UNENCRYPTED password (key) will follow
                    type: bool
                  encrypted:
                    description: Specifies an ENCRYPTED password (key) will follow
                    type: bool
          microloop_avoidance:
            description: Avoid microloops
            type: dict
            suboptions:
              protected:
                description: Avoid microloops for protected prefixes only)
                type: bool
              rib_update_delay:
                description: Delay to introduce between SPF and RIB updates
                type: int
              segment_routing:
                description: Enable segment routing microloop avoidance
                type: bool
          monitor_convergence:
            description: Enables OSPFv2 route convergence monitoring
            type: dict
            suboptions:
              prefix_list:
                description: Enables Individual Prefix Monitoring
                type: str
              track_external_routes:
                description: Enables Tracking External(Type-5/7) Prefix monitoring
                type: bool
              track_ip_frr:
                description: Enables Tracking IP-Frr Convergence
                type: bool
              track_summary_routes:
                description: Enables Tracking Summary(Inter-Area) Prefix monitoring
                type: bool
          mpls:
            description: Configure MPLS routing protocol parameters
            type: dict
            suboptions:
              traffic_eng:
                description: Routing protocol commands for MPLS Traffic Engineering
                type: dict
                suboptions:
                  autoroute_exclude:
                    description: Exclude IP address destinations from using TE tunnels
                    type: dict
                    suboptions:
                      route_policy:
                        description: Policy name
                        type: str
                      parameters:
                        description: Specify parameter values for the policy
                        type: list
                        elements: str
                  igp_intact:
                    description: Retain one or more IPv4 nexthops with tunnel nexthops
                    type: bool
                  ldp_sync_update:
                    description: Enable LDP sync induced metric propagation
                    type: bool
                  multicast_intact:
                    description: Publish multicast-intact paths to RIB
                    type: bool
                  router_id:
                    description: Traffic Engineering stable IP address for system
                    type: str
              ldp:
                description: Configure LDP parameters
                type: dict
                suboptions:
                  auto_config:
                    description: Enable LDP IGP interface auto-configuration
                    type: bool
                  sync:
                    description: Enable LDP IGP synchronization
                    type: bool
                  sync_igp_shortcuts:
                    description: LDP sync for igp-shortcut tunnels
                    type: bool
          mtu_ignore:
            description: Enable/Disable ignoring of MTU in DBD packets
            type: str
            choices:
            - enable
            - disable
          network:
            description: Network type
            type: dict
            suboptions:
              broadcast:
                description: Specify OSPFv2 broadcast multi-access network
                type: bool
              non_broadcast:
                description: Specify OSPFv2 NBMA network
                type: bool
              point_to_multipoint:
                description: Specify OSPFv2 point-to-multipoint network
                type: bool
              point_to_point:
                description: Specify OSPFv2 point-to-point network
                type: bool
          nsf:
            description: Non-stop forwarding
            type: dict
            suboptions:
              cisco:
                description: Cisco Non-stop forwarding
                type: dict
                suboptions:
                  enforce_global:
                    description: Cancel NSF restart when non-NSF-aware neighbors detected
                      for the whole OSPFv2 process
                    type: bool
                  set:
                    description: Enable Cisco NSF
                    type: bool
              flush_delay_time:
                description: Maximum time allowed for external route learning
                type: int
              ietf:
                description: IETF graceful restart
                type: dict
                suboptions:
                  helper_disable:
                    description: Disable router's helper support level
                    type: bool
                  set:
                    description: Only enable ietf option
                    type: bool
              interval:
                description: Minimum interval between NSF restarts (<90-3600> seconds)
                type: int
              lifetime:
                description: Maximum route lifetime following restart (<90-1800> seconds)
                type: int
          nsr:
            description: Enable NSR for all VRFs in this process. 'False' option to
              disable NSR for all VRFs in this process
            type: bool
          packet_size:
            description: Size of OSPFv2 packets to use. min=576 max=MTU bytes
            type: int
          passive:
            description: Enable/Disable passive
            type: str
            choices:
            - enable
            - disable
          prefix_suppression:
            description: Suppress advertisement of the prefixes
            type: dict
            suboptions:
              set:
                description: Set the suppression option
                type: bool
              secondary_address:
                description: Enable/Disable secondary address suppression
                type: bool
          priority:
            description: Router priority
            type: int
          process_id:
            description: The OSPFv2 Process ID
            type: str
            required: true
          protocol_shutdown:
            description: Protocol specific configuration
            type: dict
            suboptions:
              host_mode:
                description: Only traffic destined for this box allowed(cisco-support)
                type: bool
              on_reload:
                description: Shutdown post reload only
                type: bool
              set:
                description: Shutdown the OSPFv2 Protocol
                type: bool
              limit:
                description: High watermark for incoming priority events
                type: dict
                suboptions:
                  high:
                    description: Hello events are dropped when incoming event queue
                      exceeds this value
                    type: int
                  low:
                    description: DBD/LS Update/Req packets are dropped when incoming
                      event queue exceeds this value
                    type: int
                  medium:
                    description: LSA ACKs are dropped when incoming event queue exceeds
                      this value
                    type: int
          redistribute:
            description: Redistribute information from another routing Protocol
            type: dict
            suboptions:
              route_type:
                description: Route type to redistribute
                type: str
                choices: [application, bgp, connected, dagr, eigrp, isis, mobile,
                  ospf, rip, static, subscriber]
              id:
                description: OnePK application name for application routes (or) AS
                  number for bgp and eigrp (or) instance name for isis and ospf
                type: str
              level:
                description: ISIS levels
                choices: [1, 2, 12]
                type: int
              lsa_type_summary:
                description: LSA type 3 for redistributed routes
                type: bool
              match:
                description: Redistribution of routes. For OSPFv2 - external/internal/nssa-external
                  1/2. For EIGRP - external/internal
                type: str
              metric:
                description: Metric for redistributed routes
                type: int
              metric_type:
                description: OSPFv2 exterior metric type for redistributed routes
                type: int
                choices: [1, 2]
              route_policy:
                description: Apply route-policy to redistribution
                type: dict
                suboptions:
                  name:
                    description: Name of the policy
                    type: str
                  parameters:
                    description: Specify parameter values for the policy
                    type: list
                    elements: str
              nssa_only:
                description: Redistribute to NSSA areas only
                type: bool
              preserve_med:
                description: Preserve med of BGP routes
                type: bool
              tag:
                description: Set tag for routes redistributed into OSPFv2
                type: int
          retransmit_interval:
            description: Delay between LSA retransmissions
            type: int
          router_id:
            description: OSPFv2 router-id in IPv4 address format (A.B.C.D)
            type: str
          security_ttl:
            description: Enable security
            type: dict
            suboptions:
              set:
                description: Enable ttl security
                type: bool
              hops:
                description: Maximum number of IP hops allowed <1-254>
                type: int
          summary_in:
            description: Enable/Disable advertisement of external prefixes as inter-area
            type: str
            choices: [enable, disable]
          summary_prefix:
            description: Configure IP address summaries
            type: list
            elements: dict
            suboptions:
              prefix:
                description: IP summary address/mask (A.B.C.D/prefix)
                type: str
                required: true
              not_advertise:
                description: Suppress routes that match the specified prefix/mask
                  pair
                type: bool
              tag:
                description: Set tag
                type: int
          timers:
            description: Configure timer related constants
            type: dict
            suboptions:
              graceful_shutdown:
                description: Timers for graceful shutdown(cisco-support)
                type: dict
                suboptions:
                  initial_delay:
                    description: Delay before starting graceful shutdown
                    type: int
                  retain_routes:
                    description: Time to keep routes active after graceful shutdown
                    type: int
              lsa:
                description: OSPFv2 global LSA timers
                type: dict
                suboptions:
                  group_pacing:
                    description: OSPFv2 LSA group pacing timer. Interval between group
                      of LSA being refreshed or maxaged
                    type: int
                  min_arrival:
                    description: OSPFv2 MinLSArrival timer. The minimum interval in
                      millisec between accepting the same LSA
                    type: int
                  refresh:
                    description: OSPFv2 LSA refresh interval. How often self-originated
                      LSAs should be refreshed, in seconds
                    type: int
              throttle:
                description: OSPFv2 throttle timers
                type: dict
                suboptions:
                  lsa_all:
                    description: LSA throttle timers for all types of OSPFv2 LSAs
                    type: dict
                    suboptions:
                      initial_delay:
                        description: Delay to generate first occurance of LSA in milliseconds
                        type: int
                      min_delay:
                        description: Minimum delay between originating the same LSA
                          in milliseconds
                        type: int
                      max_delay:
                        description: Maximum delay between originating the same LSA
                          in milliseconds
                        type: int
                  spf:
                    description: OSPFv2 SPF throttle timers
                    type: dict
                    suboptions:
                      change_delay:
                        description: Delay between receiving a change to SPF calculation
                          in milliseconds
                        type: int
                      second_delay:
                        description: Delay between first and second SPF calculation
                          in milliseconds
                        type: int
                      max_wait:
                        description: Maximum wait time in milliseconds for SPF calculations
                        type: int
                  fast_reroute:
                    description: Fast-reroute throttle timer. Delay between end of
                      SPF and start of the fast-reroute computation in milliseconds
                    type: int
              pacing_flood:
                description: OSPFv2 flood pacing timer. Interval in msec to pace flooding
                  on all interfaces
                type: int
          transmit_delay:
            description: Estimated time needed to send link-state update packet
            type: int
          weight:
            description: Interface weight
            type: int
  running_config:
    description:
    - This option is used only with state I(parsed).
    - The value of this option should be the output received from the IOS-XR device
      by executing the command B(show running-config router ospf).
    - The state I(parsed) reads the configuration from C(running_config) option and
      transforms it into Ansible structured data as per the resource module's argspec
      and the value is then returned in the I(parsed) key within the result.
    type: str
  state:
    description:
    - The state the configuration should be left in.
    type: str
    choices:
    - merged
    - replaced
    - deleted
    - parsed
    - gathered
    - rendered
    - overridden
    default: merged

"""

EXAMPLES = """
# Using merged

# Before state:
# -------------
#
# RP/0/RP0/CPU0:anton#show running-config router ospf
# Thu Jun 11 15:54:44.569 UTC
# % No such configuration item(s)
#

- name: Merge provided OSPFv2 configuration with the existing configuration
  cisco.iosxr.iosxr_ospfv2:
    config:
      processes:
        - process_id: '27'
          areas:
            - area_id: '10'
              hello_interval: 2
              authentication:
                keychain: ansi11393
        - process_id: '26'
          adjacency_stagger:
            max_adjacency: 20
            min_adjacency: 10
        - process_id: '10'
          authentication:
            keychain: ansible_test1102
          areas:
            - area_id: '11'
              default_cost: 5
              cost: 11
            - area_id: 22
              default_cost: 6
        - process_id: '30'
          areas:
            - area_id: 11
              default_cost: 5
            - area_id: 22
              default_cost: 6
          cost: 2
          default_metric: 10
          transmit_delay: 2
          hello_interval: 1
          dead_interval: 2
          retransmit_interval: 2
          weight: 2
          packet_size: 577
          priority: 1
          router_id: 2.2.2.2
          demand_circuit: enable
          passive: disable
          summary_in: enable
          flood_reduction: disable
          mtu_ignore: enable
          external_out: disable
    state: merged

# Task Output:
# ------------
#
# before: {}
#
# commands:
#   - router ospf 30
#   - cost 2
#   - weight 2
#   - passive disable
#   - priority 1
#   - flood-reduction disable
#   - default-metric 10
#   - router-id 2.2.2.2
#   - demand-circuit enable
#   - packet-size 577
#   - transmit-delay 2
#   - summary-in enable
#   - external-out disable
#   - dead-interval 2
#   - hello-interval 1
#   - retransmit-interval 2
#   - mtu-ignore enable
#   - area 11 default-cost 5
#   - area 22 default-cost 6
#   - router ospf 26
#   - adjacency stagger 10 20
#   - router ospf 10
#   - authentication keychain ansible_test1102
#   - area 11 default-cost 5
#   - area 11 cost 11
#   - area 22 default-cost 6
#   - router ospf 27
#   - area 10 authentication keychain ansi11393
#   - area 10 hello-interval 2
#
# after:
#     processes:
#     - areas:
#       - area_id: '11'
#         cost: 11
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       authentication:
#         keychain: ansible_test1102
#       process_id: '10'
#     - adjacency_stagger:
#         max_adjacency: 20
#         min_adjacency: 10
#       process_id: '26'
#     - areas:
#       - area_id: '10'
#         authentication:
#           keychain: ansi11393
#         hello_interval: 2
#       process_id: '27'
#     - areas:
#       - area_id: '11'
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       cost: 2
#       dead_interval: 2
#       default_metric: 10
#       demand_circuit: enable
#       external_out: disable
#       flood_reduction: disable
#       hello_interval: 1
#       mtu_ignore: enable
#       packet_size: 577
#       passive: disable
#       priority: 1
#       process_id: '30'
#       retransmit_interval: 2
#       router_id: 2.2.2.2
#       summary_in: enable
#       transmit_delay: 2
#       weight: 2
#
# After state:
# ------------
#
# router ospf 10
#  authentication keychain ansible_test1102
#  area 11
#   cost 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
# router ospf 26
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#   authentication keychain ansi11393
#   hello-interval 2
#  !
# !
# router ospf 30
#  router-id 2.2.2.2
#  summary-in enable
#  external-out disable
#  cost 2
#  packet-size 577
#  weight 2
#  passive disable
#  priority 1
#  mtu-ignore enable
#  flood-reduction disable
#  dead-interval 2
#  retransmit-interval 2
#  demand-circuit enable
#  hello-interval 1
#  transmit-delay 2
#  default-metric 10
#  area 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !

# Using replaced
#
# Before state:
# -------------
#
#
# RP/0/RP0/CPU0:anton#show running-config router ospf
# Thu Jun 11 16:06:44.406 UTC
# router ospf 10
#  authentication keychain ansible_test1102
#  area 11
#   cost 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
# router ospf 26
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#   authentication keychain ansi11393
#   hello-interval 2
#  !
# !
# router ospf 30
#  router-id 2.2.2.2
#  summary-in enable
#  external-out disable
#  cost 2
#  packet-size 577
#  weight 2
#  passive disable
#  priority 1
#  mtu-ignore enable
#  flood-reduction disable
#  dead-interval 2
#  retransmit-interval 2
#  demand-circuit enable
#  hello-interval 1
#  transmit-delay 2
#  default-metric 10
#  area 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
#
- name: Replace running OSPFv2 routes configurations with provided config.
  cisco.iosxr.iosxr_ospfv2:
    config:
      processes:
        - process_id: 27
          areas:
            - area_id: 10
              hello_interval: 2
            - area_id: 20
              cost: 2
              default_cost: 2
              authentication:
                keychain: ansi11393
        - process_id: 26
          adjacency_stagger:
            min_adjacency: 10
            max_adjacency: 20
    state: replaced

# Task Output:
# ------------
#
# before:
#     processes:
#     - areas:
#       - area_id: '11'
#         cost: 11
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       authentication:
#         keychain: ansible_test1102
#       process_id: '10'
#     - adjacency_stagger:
#         max_adjacency: 20
#         min_adjacency: 10
#       process_id: '26'
#     - areas:
#       - area_id: '10'
#         authentication:
#           keychain: ansi11393
#         hello_interval: 2
#       process_id: '27'
#     - areas:
#       - area_id: '11'
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       cost: 2
#       dead_interval: 2
#       default_metric: 10
#       demand_circuit: enable
#       external_out: disable
#       flood_reduction: disable
#       hello_interval: 1
#       mtu_ignore: enable
#       packet_size: 577
#       passive: disable
#       priority: 1
#       process_id: '30'
#       retransmit_interval: 2
#       router_id: 2.2.2.2
#       summary_in: enable
#       transmit_delay: 2
#       weight: 2
#
# commands:
#   - router ospf 27
#   - no area 10 authentication keychain ansi11393
#   - area 20 authentication keychain ansi11393
#   - area 20 default-cost 2
#   - area 20 cost 2
#
# after:
#     processes:
#     - areas:
#       - area_id: '11'
#         cost: 11
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       authentication:
#         keychain: ansible_test1102
#       process_id: '10'
#     - adjacency_stagger:
#         max_adjacency: 20
#         min_adjacency: 10
#       process_id: '26'
#     - areas:
#       - area_id: '10'
#         hello_interval: 2
#       - area_id: '20'
#         authentication:
#           keychain: ansi11393
#         cost: 2
#         default_cost: 2
#       process_id: '27'
#     - areas:
#       - area_id: '11'
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       cost: 2
#       dead_interval: 2
#       default_metric: 10
#       demand_circuit: enable
#       external_out: disable
#       flood_reduction: disable
#       hello_interval: 1
#       mtu_ignore: enable
#       packet_size: 577
#       passive: disable
#       priority: 1
#       process_id: '30'
#       retransmit_interval: 2
#       router_id: 2.2.2.2
#       summary_in: enable
#       transmit_delay: 2
#       weight: 2
#
# After state:
# ------------
#
# RP/0/RP0/CPU0:anton(config)#do show running-config router ospf
# Thu Jun 11 16:40:31.038 UTC
# router ospf 10
#  authentication keychain ansible_test1102
#  area 11
#   cost 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
# router ospf 26
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#   hello-interval 2
#  !
#  area 20
#   cost 2
#   authentication keychain ansi11393
#   default-cost 2
#  !
# !
# router ospf 30
#  router-id 2.2.2.2
#  summary-in enable
#  external-out disable
#  cost 2
#  packet-size 577
#  weight 2
#  passive disable
#  priority 1
#  mtu-ignore enable
#  flood-reduction disable
#  dead-interval 2
#  retransmit-interval 2
#  demand-circuit enable
#  hello-interval 1
#  transmit-delay 2
#  default-metric 10
#  area 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !

# Using overridden
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:anton#show running-config router ospf
# Thu Jun 11 16:06:44.406 UTC
# router ospf 10
#  authentication keychain ansible_test1102
#  area 11
#   cost 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
# router ospf 26
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#   hello-interval 2
#  !
#  area 20
#   cost 2
#   authentication keychain ansi11393
#   default-cost 2
#  !
# !
# router ospf 30
#  router-id 2.2.2.2
#  summary-in enable
#  external-out disable
#  cost 2
#  packet-size 577
#  weight 2
#  passive disable
#  priority 1
#  mtu-ignore enable
#  flood-reduction disable
#  dead-interval 2
#  retransmit-interval 2
#  demand-circuit enable
#  hello-interval 1
#  transmit-delay 2
#  default-metric 10
#  area 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !

- name: Override existing OSPFv2 configurations with provided config.
  cisco.iosxr.iosxr_ospfv2:
    config:
      processes:
        - process_id: 27
          areas:
            - area_id: 10
              hello_interval: 2
              authentication:
                keychain: ansi11393
            - area_id: 20
              cost: 2
              default_cost: 2
              authentication:
                keychain: ansi11393
        - process_id: 26
          adjacency_stagger:
            min_adjacency: 10
            max_adjacency: 20
    state: overridden


#
# Task Output:
# ------------
#
# before:
#     processes:
#     - areas:
#       - area_id: '11'
#         cost: 11
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       authentication:
#         keychain: ansible_test1102
#       process_id: '10'
#     - adjacency_stagger:
#         max_adjacency: 20
#         min_adjacency: 10
#       process_id: '26'
#     - areas:
#       - area_id: '10'
#         hello_interval: 2
#       - area_id: '20'
#         authentication:
#           keychain: ansi11393
#         cost: 2
#         default_cost: 2
#       process_id: '27'
#     - areas:
#       - area_id: '11'
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       cost: 2
#       dead_interval: 2
#       default_metric: 10
#       demand_circuit: enable
#       external_out: disable
#       flood_reduction: disable
#       hello_interval: 1
#       mtu_ignore: enable
#       packet_size: 577
#       passive: disable
#       priority: 1
#       process_id: '30'
#       retransmit_interval: 2
#       router_id: 2.2.2.2
#       summary_in: enable
#       transmit_delay: 2
#       weight: 2

#
# commands:
#   - router ospf 10
#   - no authentication keychain ansible_test1102
#   - no area 11 default-cost 5
#   - no area 11 cost 11
#   - no area 22 default-cost 6
#   - router ospf 30
#   - no cost 2
#   - no weight 2
#   - no passive disable
#   - no priority 1
#   - no flood-reduction disable
#   - no default-metric 10
#   - no router-id 2.2.2.2
#   - no demand-circuit enable
#   - no packet-size 577
#   - no transmit-delay 2
#   - no summary-in enable
#   - no external-out disable
#   - no dead-interval 2
#   - no hello-interval 1
#   - no retransmit-interval 2
#   - no mtu-ignore enable
#   - no area 11 default-cost 5
#   - no area 22 default-cost 6
#   - router ospf 27
#   - area 10 authentication keychain ansi11393
#
# after:
#     processes:
#     - process_id: '10'
#     - adjacency_stagger:
#         max_adjacency: 20
#         min_adjacency: 10
#       process_id: '26'
#     - areas:
#       - area_id: '10'
#         authentication:
#           keychain: ansi11393
#         hello_interval: 2
#       - area_id: '20'
#         authentication:
#           keychain: ansi11393
#         cost: 2
#         default_cost: 2
#       process_id: '27'
#     - process_id: '30'
#
# After state:
# ------------
#
# RP/0/RP0/CPU0:anton#show running-config router ospf
# Thu Jun 11 16:50:36.332 UTC
# router ospf 10
#  area 11
#  !
#  area 22
#  !
# !
# router ospf 26
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#   authentication keychain ansi11393
#   hello-interval 2
#  !
#  area 20
#   cost 2
#   authentication keychain ansi11393
#   default-cost 2
#  !
# !
# router ospf 30
#  area 11
#  !
#  area 22
#  !
# !
#

# Using deleted
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:anton#show running-config router ospf
# Thu Jun 11 16:06:44.406 UTC
# router ospf 10
#  authentication keychain ansible_test1102
#  area 11
#   cost 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
# router ospf 26
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#   authentication keychain ansi11393
#   hello-interval 2
#  !
#  area 20
#   cost 2
#   authentication keychain ansi11393
#   default-cost 2
#  !
# !
# router ospf 30
#  router-id 2.2.2.2
#  summary-in enable
#  external-out disable
#  cost 2
#  packet-size 577
#  weight 2
#  passive disable
#  priority 1
#  mtu-ignore enable
#  flood-reduction disable
#  dead-interval 2
#  retransmit-interval 2
#  demand-circuit enable
#  hello-interval 1
#  transmit-delay 2
#  default-metric 10
#  area 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !

- name: Deleted provided ospfv2 processes.
  cisco.iosxr.iosxr_ospfv2:
    config:
      processes:
        - process_id: '10'
        - process_id: '26'
        - process_id: '27'
        - process_id: '30'
    state: deleted


#
# Task Output:
# ------------
#
# before:
#     processes:
#     - areas:
#       - area_id: '11'
#         cost: 11
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       authentication:
#         keychain: ansible_test1102
#       process_id: '10'
#     - adjacency_stagger:
#         max_adjacency: 20
#         min_adjacency: 10
#       process_id: '26'
#     - areas:
#       - area_id: '10'
#         authentication:
#           keychain: ansi11393
#         hello_interval: 2
#       - area_id: '20'
#         authentication:
#           keychain: ansi11393
#         cost: 2
#         default_cost: 2
#       process_id: '27'
#     - areas:
#       - area_id: '11'
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       cost: 2
#       dead_interval: 2
#       default_metric: 10
#       demand_circuit: enable
#       external_out: disable
#       flood_reduction: disable
#       hello_interval: 1
#       mtu_ignore: enable
#       packet_size: 577
#       passive: disable
#       priority: 1
#       process_id: '30'
#       retransmit_interval: 2
#       router_id: 2.2.2.2
#       summary_in: enable
#       transmit_delay: 2
#       weight: 2
#
# commands:
#   - router ospf 10
#   - no authentication keychain ansible_test1102
#   - no area 11 default-cost 5
#   - no area 11 cost 11
#   - no area 22 default-cost 6
#   - router ospf 26
#   - no adjacency stagger 10 20
#   - router ospf 27
#   - no area 10 authentication keychain ansi11393
#   - no area 10 hello-interval 2
#   - no area 20 authentication keychain ansi11393
#   - no area 20 default-cost 2
#   - no area 20 cost 2
#   - router ospf 30
#   - no cost 2
#   - no weight 2
#   - no passive disable
#   - no priority 1
#   - no flood-reduction disable
#   - no default-metric 10
#   - no router-id 2.2.2.2
#   - no demand-circuit enable
#   - no packet-size 577
#   - no transmit-delay 2
#   - no summary-in enable
#   - no external-out disable
#   - no dead-interval 2
#   - no hello-interval 1
#   - no retransmit-interval 2
#   - no mtu-ignore enable
#   - no area 11 default-cost 5
#   - no area 22 default-cost 6
#
# after:
#     processes:
#     - process_id: '10'
#     - process_id: '26'
#     - process_id: '27'
#     - process_id: '30'

# After state:
# ------------
#
# RP/0/RP0/CPU0:anton(config)#show running-config router ospf
# Thu Jun 11 17:07:34.218 UTC
# router ospf 10
#  area 11
#  !
#  area 22
#  !
# !
# router ospf 26
# !
# router ospf 27
#  area 10
#  !
#  area 20
#  !
# !
# router ospf 30
#  area 11
#  !
#  area 22
#  !
# !


# Using parsed
# parsed.cfg
# ------------
# Thu Jun 11 17:28:51.918 UTC
# router ospf 10
#  authentication keychain ansible_test1102
#  area 11
#   cost 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
# router ospf 26
#  authentication message-digest keychain ansible1101pass
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#   authentication keychain ansi11393
#   hello-interval 2
#  !
# !
# router ospf 30
#  router-id 2.2.2.2
#  summary-in enable
#  external-out disable
#  cost 2
#  packet-size 577
#  weight 2
#  passive disable
#  priority 1
#  mtu-ignore enable
#  flood-reduction disable
#  dead-interval 2
#  retransmit-interval 2
#  demand-circuit enable
#  hello-interval 1
#  transmit-delay 2
#  default-metric 10
#  area 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
#
- name: Parsed the device configuration to get output commands
  cisco.iosxr.iosxr_ospfv2:
    running_config: "{{ lookup('file', './parsed.cfg') }}"
    state: parsed
#
# Task Output:
# ------------
#
# parsed:
#     processes:
#     - areas:
#       - area_id: '11'
#         cost: 11
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       authentication:
#         keychain: ansible_test1102
#       process_id: '10'
#     - adjacency_stagger:
#         max_adjacency: 20
#         min_adjacency: 10
#       authentication:
#         message_digest:
#           keychain: ansible1101pass
#       process_id: '26'
#     - areas:
#       - area_id: '10'
#         authentication:
#           keychain: ansi11393
#         hello_interval: 2
#       process_id: '27'
#     - areas:
#       - area_id: '11'
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       cost: 2
#       dead_interval: 2
#       default_metric: 10
#       demand_circuit: enable
#       external_out: disable
#       flood_reduction: disable
#       hello_interval: 1
#       mtu_ignore: enable
#       packet_size: 577
#       passive: disable
#       priority: 1
#       process_id: '30'
#       retransmit_interval: 2
#       router_id: 2.2.2.2
#       summary_in: enable
#       transmit_delay: 2
#       weight: 2

# Using rendered
#
- name: Render the commands for provided  configuration
  cisco.iosxr.iosxr_ospfv2:
    config:
      processes:
        - process_id: 27
          areas:
            - area_id: 10
              hello_interval: 2
              authentication:
                keychain: ansi11393
        - process_id: 26
          adjacency_stagger:
            min_adjacency: 10
            max_adjacency: 20
        - process_id: 10
          authentication:
            keychain: ansible_test1102
          areas:
            - area_id: 11
              default_cost: 5
              cost: 11
            - area_id: 22
              default_cost: 6
        - process_id: 30
          areas:
            - area_id: 11
              default_cost: 5
            - area_id: 22
              default_cost: 6
          cost: 2
          default_metric: 10
          transmit_delay: 2
          hello_interval: 1
          dead_interval: 2
          retransmit_interval: 2
          weight: 2
          packet_size: 577
          priority: 1
          router_id: 2.2.2.2
          demand_circuit: enable
          passive: disable
          summary_in: enable
          flood_reduction: disable
          mtu_ignore: enable
          external_out: disable
    state: rendered


#
# Task Output:
# ------------
#
# rendered:
#   - router ospf 27
#   - area 10 authentication keychain ansi11393
#   - area 10 hello-interval 2
#   - router ospf 26
#   - adjacency stagger 10 20
#   - router ospf 10
#   - authentication keychain ansible_test1102
#   - area 11 default-cost 5
#   - area 11 cost 11
#   - area 22 default-cost 6
#   - router ospf 30
#   - cost 2
#   - weight 2
#   - passive disable
#   - priority 1
#   - flood-reduction disable
#   - default-metric 10
#   - router-id 2.2.2.2
#   - demand-circuit enable
#   - packet-size 577
#   - transmit-delay 2
#   - summary-in enable
#   - external-out disable
#   - dead-interval 2
#   - hello-interval 1
#   - retransmit-interval 2
#   - mtu-ignore enable
#   - area 11 default-cost 5
#   - area 22 default-cost 6


# Using gathered
#
# Before state:
# -------------
#
# RP/0/RP0/CPU0:anton#show running-config router ospf
# Thu Jun 11 16:06:44.406 UTC
# router ospf 10
#  authentication keychain ansible_test1102
#  area 11
#   cost 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
# router ospf 26
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#   authentication keychain ansi11393
#   hello-interval 2
#  !
#  area 20
#  !
# !
# router ospf 30
#  router-id 2.2.2.2
#  summary-in enable
#  external-out disable
#  cost 2
#  packet-size 577
#  weight 2
#  passive disable
#  priority 1
#  mtu-ignore enable
#  flood-reduction disable
#  dead-interval 2
#  retransmit-interval 2
#  demand-circuit enable
#  hello-interval 1
#  transmit-delay 2
#  default-metric 10
#  area 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
#
- name: Gather ospfv2 routes configuration
  cisco.iosxr.iosxr_ospfv2:
    state: gathered
#
#
# Task Output:
# ------------
#
# gathered:
#     processes:
#     - areas:
#       - area_id: '11'
#         cost: 11
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       authentication:
#         keychain: ansible_test1102
#       process_id: '10'
#     - adjacency_stagger:
#         max_adjacency: 20
#         min_adjacency: 10
#       process_id: '26'
#     - areas:
#       - area_id: '10'
#         authentication:
#           keychain: ansi11393
#         hello_interval: 2
#       process_id: '27'
#     - areas:
#       - area_id: '11'
#         default_cost: 5
#       - area_id: '22'
#         default_cost: 6
#       cost: 2
#       dead_interval: 2
#       default_metric: 10
#       demand_circuit: enable
#       external_out: disable
#       flood_reduction: disable
#       hello_interval: 1
#       mtu_ignore: enable
#       packet_size: 577
#       passive: disable
#       priority: 1
#       process_id: '30'
#       retransmit_interval: 2
#       router_id: 2.2.2.2
#       summary_in: enable
#       transmit_delay: 2
#       weight: 2
#
# After state:
# -------------
#
# RP/0/RP0/CPU0:anton#show running-config router ospf
# Thu Jun 11 16:06:44.406 UTC
# router ospf 10
#  authentication keychain ansible_test1102
#  area 11
#   cost 11
#   default-cost 5
#  !
#  area 22
#   default-cost 6
#  !
# !
# router ospf 26
#  authentication message-digest keychain ansible1101pass
#  adjacency stagger 10 20
# !
# router ospf 27
#  area 10
#  authentication keychain ansi11393
#   hello-interval 2
# !
# !
# router ospf 30
# router-id 2.2.2.2
# summary-in enable
# external-out disable
# cost 2
# packet-size 577
# weight 2
# passive disable
# priority 1
# mtu-ignore enable
# flood-reduction disable
# dead-interval 2
# retransmit-interval 2
# demand-circuit enable
# hello-interval 1
# transmit-delay 2
# default-metric 10
# area 11
#  default-cost 5
# !
# area 22
#  default-cost 6
# !
# !
#
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
    - "router ospf 30"
    - "authentication message-digest keychain 'ansible1101pass'"
rendered:
  description: The provided configuration in the task rendered in device-native format (offline).
  returned: when I(state) is C(rendered)
  type: list
  sample:
  - router ospf 27
  - area 10 authentication keychain ansi11393
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

from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.argspec.ospfv2.ospfv2 import (
    Ospfv2Args,
)
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.config.ospfv2.ospfv2 import (
    Ospfv2,
)


def main():
    """
    Main entry point for module execution

    :returns: the result form module invocation
    """
    required_if = [
        ("state", "merged", ("config",)),
        ("state", "replaced", ("config",)),
        ("state", "overridden", ("config",)),
        ("state", "rendered", ("config",)),
        ("state", "parsed", ("running_config",)),
    ]
    mutually_exclusive = [("config", "running_config")]
    module = AnsibleModule(
        argument_spec=Ospfv2Args.argument_spec,
        required_if=required_if,
        supports_check_mode=True,
        mutually_exclusive=mutually_exclusive,
    )
    result = Ospfv2(module).execute_module()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
