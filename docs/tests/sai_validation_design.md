# ASIC DB / SAI validation for test cases

## Background

ASIC_DB stores data plane configuration in an ASIC-friendly format. SONiC control plane test cases make configuration changes in CONFIG_DB or APP_DB could indirectly affect ASIC_DB object types or data plane tests configure the ASIC directly. In either of the cases these tests do not explicitly verify that the ASIC_DB has been setup correctly before the tests are executed.

## Purpose

The purpose of ASIC_DB or SAI validation is to design a intuitive, simple, easy-to-use set of libraries / methods which allow tests to verify ASIC_DB object types are valid and have been setup correctly.

## High Level Design Document

### Revision: Draft

## Revision

| Rev      | Date        | Author                   | Change Description            |
|----------|-------------|--------------------------|-------------------------------|
| Draft    | 14-08-2024  | Sai Kiran Gummaraj       | Initial version               |


## About this document

The aim of this document is to:

1. Evaluate all the SONiC test cases
2. Identify the tests that qualify for ASIC_DB validation
3. Record any findings of the existing test setup phase and identify the ASIC_DB SAI object types that are affected by the test case
4. Identify and document design principles from [SWSS VS Test](https://github.com/sonic-net/sonic-swss/blob/master/tests/README.md)
5. Document different design techniques for performing ASIC_DB / SAI validation
6. Identify the suitable, simple and easy-to-use design technique to perform ASIC_DB validation.

## Introduction

A reliable way to map data-plane tests is to look for features that operate at the ASIC/SAI layer. All the ASIC configuration is stored in the ASIC DB and a list of all the ASIC SAI objects are available here [https://github.com/opencomputeproject/SAI/blob/master/inc/saitypes.h](https://github.com/opencomputeproject/SAI/blob/master/inc/saitypes.h). The table below examines each test to identify if any dataplane interactions are part of the test.

|     Test Case Information                            | ASIC/SAI Validation |     Notes                                                                  |
|------------------------------------------------------|---------------------|----------------------------------------------------------------------------|
| tests/acl                                            | Yes                 | tests delete `CONFIG_DB` `ACL_TABLE_TYPE  CUSTOM_TYPE` and set `ACL_RULE STRESS_ACL RULE_{}`; Changes to SAI objects `SAI_OBJECT_TYPE_ACL_TABLE, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER` |
| tests/arp                                            | Yes                 | tests set and delete `CONFIG_DB` types `VLAN_INTERFACE`. ARP impact neighbor entries. Checked in `ASIC_DB` neighbor tables `SAI_OBJECT_TYPE_NEIGHBOR_ENTRY` |
| tests/autorestart                                    | No                  | Tests if critical processes (like orchagent etc.) are restarted after killing them. |
| tests/bfd                                            | Yes                 | Tests modifies `CONFIG_DB STATIC_ROUTE` and `STATE_DB BFD_SESSION_TABLE` check `SAI_OBJECT_TYPE_BFD_SESSIONS`|
| tests/bgp                                            | Yes                 | Tests modifies `CONFIG_DB BGP_ALLOWED_PREFIXES`, `BGP_NEIGHBOR`, `BGP_MONITORS` and in `STATE_DB` the `NEIGH_STATE_TABLE` |
| tests/cacl                                           | No                  | Control plane ACL functionality set up iptables to control mgmt traffic (check acl-loader) |
| tests/clock                                          | No                  | Tests 'show clock' command, 'config clock timezone', 'config clock date' |
| tests/configlet                                      | No                  | configlet a generic command to apply configuration patches to `CONFIG_DB`. The tests require exporting database content. |
| tests/console                                        | No                  | Test if console features are working in SONiC; Skipped unless console feature is enabled on device |
| tests/container_checker                              | No                  | Uses [monit](https://salsa.debian.org/sk-guest/monit), patched [here](https://github.com/sonic-net/sonic-buildimage/tree/master/src/monit) to run [container_checker](https://github.com/sonic-net/sonic-buildimage/blob/master/files/image_config/monit/container_checker) |
| tests/container_hardening                            | No                  | Test non-privileged containers must NOT have access to /dev/vda* or /dev/sda* |
| tests/copp                                           | Yes                 | **Co**ntrol *P*lane *P*olicing - feature to enable rate limiting to access control plane. The [design document](https://github.com/sonic-net/SONiC/blob/master/doc/copp/CoPP%20Config%20and%20Management.md) refers to updates to SAI_HOSTIF_TRAP_TYPE_IP2ME and reads from SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET. Should these be checked?|
| tests/crm                                            | Yes                 | Critical Resource Monitoring lets users monitor critical ASIC functionality by polling SAI attributes; The table [CRM Sai Attributes](https://github.com/sonic-net/SONiC/blob/master/doc/crm/Critical-Resource-Monitoring-High-Level-Design.md#26-sai) shows all the SAI attributes which should be used to get required CRM counters. Tests modify `CONFIG_DB CRM|Config`, query `COUNTERS_DB CRM:STATS` and `ASIC_DB` ACL entries|
| tests/dash                                           | Yes                 | Disaggregated APIs for SONiC Hosts ([DASH](https://github.com/sonic-net/DASH/blob/main/documentation/general/dash-high-level-design.md)). Tests export `ASIC_DB` and checks for object types `SAI_OBJECT_TYPE_VNET`, `SAI_OBJECT_TYPE_ENI`. `test_dash_disable_enable_eni` checks for `SAI_ENI_ATTR_ADMIN_STATE` and `*ENI` keys|
| tests/database                                       | No                  | Tests Redis database configurations |
| tests/decap                                          | Yes                 | [DB Schema in decap](https://github.com/sonic-net/SONiC/blob/master/doc/decap/subnet_decap_HLD.md#62-db-schema) In `CONFIG_DB` it stores subnet based decap config in `SUBNET_DECAP` config_name. In `APPL_DB` it stores list of decap tunnels in `TUNNEL_DECAP_TABLE` and stores decap terms in `TUNNEL_DECAP_TERM_TABLE`. Same like `APP_DB` these values are stored in `STATE_DB`. `ASIC_DB` has `SAI_OBJECT_TYPE_TUNNEL_*` holds tunnel information |
| tests/dhcp_relay                                     | No                  | Queries `DHCP_COUNTER_TABLE` and `DHCPV6_COUNTER_TABLE` from `STATE_DB` |
| tests/dhcp_server                                    | No                  | `CONFIG_DB` has keys `DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS`,`DHCP_SERVER_IPV4_RANGE`, `DHCP_SERVER_IPV4_PORT`, `DHCP_SERVER_IPV4`.|
| tests/disk                                           | No                  | Test simulates disk full and test connectivity |
| tests/dns                                            | No                  | Checks nameserver configuration in the containers |
| tests/drop_packets                                   | Yes                 | `test_drop_counters.py` fetches from `CONFIG_DB FLEX_COUNTER_TABLE`. [Flex Counters](https://github.com/sonic-net/SONiC/blob/master/doc/flex_counter/flex_counter_refactor.md) provides a way to query different types of statistic/attributes which uses SAI API to query counter values. Based on my understanding there are no ASIC_DB counters for this. While in `test_configurable_drop_counters.py` installs drop counters and those has reasons added to SAI_OBJECT_TYPE_DEBUG_COUNTER. |
| tests/dualtor                                        | Yes(?)              | Applicable for specific cases; `crm` (see tests/decap for ipinip, tests/crm above).|
| tests/dualtor_io                                     | No                  | Tests to verify connectivity and different failover scenarios (links, bgp etc.) |
| tests/dualtor_mgmt                                   | No(?)               | Tests mux cable states for various scenarios like server down and checks for if mux toggle is working. For test_ingress_drop & test_egress_drop_nvidia the orchagent installs ingress drop ACL. Can this be verified in ASIC_DB?|
| tests/dut_console                                    | No                  | Tests switch console settings work as expected. |
| tests/ecmp                                           | Yes                 | `test_fgnhg` (Fine Grain Next Hop Group) tests `generate_fgnhg_config` uses the generated fgnhg config and writes it to the database. `CONFIG_DB` has `FG_NHG, FG_NHG_PREFIX, FG_NHG_MEMBER` tables. `STATE_DB` has `FG_ROUTE_TABLE`. The routeorch pushes routes down to the ASIC. It creates ECMP groups in the ASIC where there are multiple nexthops. It also adds / removes next-hop members. The fgnhgorch receives the `FG_NHG` entries and identifies the exact way in which the hash buckets need to be created. It creates ECMP groups with [new SAI components](https://github.com/sonic-net/SONiC/blob/master/doc/ecmp/fine_grained_next_hop_hld.md#25-sai). `APP_DB SWITCH_TABLE` flag `order_ecmp_group` for enabling/disabling ECMP. SAI attribute `SAI_NEXT_HOP_GROUP_TYPE_DYNAMIC_ORDERED_ECMP` is set. Verify entries in the next hop tables in ASIC_DB. For `inner_hashing` tests check how `config pbh` commands impact ASIC DB config.|
