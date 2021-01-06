# NAT Test Plan

## Rev 0.2

- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#Setup-configuration)
- [Test Cases](#Test-cases)
  - [Static NAT/NAPT](#Static-NAT/NAPT)
    - [test_nat_static_basic](#Test-case-test_nat_static_basic)
    - [test_nat_static_basic_icmp](#Test-case-test_nat_static_basic_icmp)
    - [test_nat_static_napt](#Test-case-test_nat_static_napt)
    - [test_nat_clear_statistics_static_basic](#Test-case-test_nat_clear_statistics_static_basic)
    - [test_nat_clear_statistics_static_napt](#Test-case-test_nat_clear_statistics_static_napt)
    - [test_nat_clear_translations_static_basic](#Test-case-test_nat_clear_translations_static_basic)
    - [test_nat_clear_translations_static_napt](#Test-case-test_nat_clear_translations_static_napt)
    - [test_nat_crud_static_nat](#Test-case-test_nat_crud_static_nat)
    - [test_nat_crud_static_napt](#Test-case-test_nat_crud_static_napt)
    - [test_nat_reboot_static_basic](#Test-case-test_nat_reboot_static_basic)
    - [test_nat_reboot_static_napt](#Test-case-test_nat_reboot_static_napt)
    - [test_nat_static_zones_basic_snat](#Test-case-test_nat_static_zones_basic_snat)
    - [test_nat_static_zones_basic_icmp_snat](#Test-case-test_nat_static_zones_basic_icmp_snat)
    - [test_nat_static_zones_napt_dnat_and_snat](#Test-case-test_nat_static_zones_napt_dnat_and_snat)
  - [Dynamic NAT](#Dynamic-NAT)
    - [test_nat_dynamic_basic](#Test-case-test_nat_dynamic_basic)
    - [test_nat_dynamic_basic_icmp](#Test-case-test_nat_dynamic_basic_icmp)
    - [test_nat_dynamic_entry_persist](#Test-case-test_nat_dynamic_entry_persist)
    - [test_nat_dynamic_entry_persist_icmp](#Test-case-test_nat_dynamic_entry_persist_icmp)
    - [test_nat_dynamic_disable_nat](#Test-case-test_nat_dynamic_disable_nat)
    - [test_nat_dynamic_disable_nat_icmp](#Test-case-test_nat_dynamic_disable_nat_icmp)
    - [test_nat_dynamic_bindings](#Test-case-test_nat_dynamic_bindings)
    - [test_nat_dynamic_bindings_icmp](#Test-case-test_nat_dynamic_bindings_icmp)
    - [test_nat_dynamic_other_protocols](#Test-case-test_nat_dynamic_other_protocols)
    - [test_nat_dynamic_acl_rule_actions](#Test-case-test_nat_dynamic_acl_rule_actions)
    - [test_nat_dynamic_acl_rule_actions_icmp](#Test-case-test_nat_dynamic_acl_rule_actions_icmp)
    - [test_nat_dynamic_acl_modify_rule](#Test-case-test_nat_dynamic_acl_modify_rule)
    - [test_nat_dynamic_acl_modify_rule_icmp](#Test-case-test_nat_dynamic_acl_modify_rule_icmp)
    - [test_nat_dynamic_pool_threshold](#Test-case-test_nat_dynamic_pool_threshold)
    - [test_nat_dynamic_crud](#Test-case-test_nat_dynamic_crud)
    - [test_nat_dynamic_crud_icmp](#Test-case-test_nat_dynamic_crud_icmp)
    - [test_nat_dynamic_full_cone](#Test-case-test_nat_dynamic_full_cone)
    - [test_nat_dynamic_enable_disable_nat_docker](#Test-case-test_nat_dynamic_enable_disable_nat_docker)
    - [test_nat_dynamic_enable_disable_nat_docker_icmp](#Test-case-test_nat_dynamic_enable_disable_nat_docker_icmp)
    - [test_nat_clear_statistics_dynamic](#Test-case-test_nat_clear_statistics_dynamic)
    - [test_nat_clear_translations_dynamic](#Test-case-test_nat_clear_translations_dynamic)
    - [test_nat_interfaces_flap_dynamic](#Test-case-test_nat_interfaces_flap_dynamic)
    - [test_nat_dynamic_zones](#Test-case-test_nat_dynamic_zones)
    - [test_nat_dynamic_zones_icmp](#Test-case-test_nat_dynamic_zones_icmp)




## Revision

| Rev |     Date    |       Author       | Change Description                 |
|:---:|:-----------:|:-------------------|:-----------------------------------|
| 0.3 |  03/11/2020 | Mykhailo Onipko, <br> Roman Savchuk|          Initial version           |


## Overview

The purpose is to test the functionality of NAT feature on the SONIC switch DUT. The tests expecting that
all necessary configuration for NAT are pre-configured on SONiC switch before test runs.

## Scope

The test is targeting a running SONiC system with fully functioning configuration.
Purpose of the test is to verify a SONiC switch system correctly performs NAT translations based on configured rules.

## Testbed

Supported topologies t0, t0-64-32, t0-64

## Setup configuration

Each NAT test case needs client/server traffic transmission.
NAT starts address/port translation only if connection tracking is taking place(i.e. for TCP handshake).

PTF performs traffic transmission as a client and as a server at the same time.
That approach needs testbed be customized to:

- avoid limitaion of PTFs injected interfaces(i.e. traffic on DUT's ingress from VMs cannot be captured)
- keep PTF's client/server traffic isolated (using VRFs)

The customized testbed with applied T0 topo for each NAT test case looks as follows:

```
       ________________________________
      |              |                 |                  VM    VM    VM
      |              |   Server's VRF  |_____________      |     |     |
      |              |_________________|       ______|_____|_____|_____|______
      |                                |      |                               |
      |    PTF                         |      |              DUT              |
      |               _________________|      |                               |
      |              |                 |      |_______________________________|
      |              |   Client's VRF  |_____________|
      |______________|_________________|

```

After end of the test session teardown procedure turns testbed to the initial state.

## Python scripts to setup and run test

NAT test suite is located in tests/nat folder. The are two separate files test_dynamic_nat.py and test_static_nat.py

### Setup of DUT switch

During setup procedure python mgmt scripts perform DUT configuration with CLI commands via corresponding wrappers.
Setup  procedure configures/removes  PTF's vrf interfaces with fixture setup_test_env

For specific features like ACL mgmt scripts are using jinja template to convert it in to the JSON file containing configuration to be pushed to the SONiC config DB via sonic-cfggen.

create_acl_rule.j2
```
   {

    "ACL_TABLE": {
        "{{ acl_table_name }}": {
            "stage": "{{ stage }}",
            "type": "L3",
            "policy_desc": "test_policy",
            "ports": ["{{ ports_assigned }}"]
        }
    },

  {% for rule in acl_rules %}
      "ACL_RULE": {
          "{{ acl_table_name }}|{{ loop.index }}": {
              "PRIORITY": "{{ rule.priority }}",
              "SRC_IP": "{{ rule.src_ip }}",
              "PACKET_ACTION": "{{ rule.action }}"
          }
      }
  {% if not loop.last %}
  {% endif %}{% endfor %}

  }
```

## Test cases

All test cases will be parametrize by protocol type (TCP, UDP, ICMP), interface type ("loopback", "port_in_lag") and direction ("host-tor", "leaf-tor")

## Static NAT/NAPT

## Test case test_nat_static_basic

### Test objective

Verify that NAT will happen when NAT basic static configuration applied on DUT

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Static NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic with configured inner SRC IP
- Verify that packet was SNAT and DNAT in both directions for configured inner SRC IP
- Send bidirectional traffic with not configured inner SRC IP
- Verify that packets are not translating for not configured inner SRC IP

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_static_basic_icmp

### Test objective

Verify that NAT for ICMP will happen when NAT basic static configuration applied on DUT

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Static NAT config on DUT via CLI
- Send ICMP traffic with configured inner SRC IP
- Verify that packet was SNAT and DNAT in both directions for configured inner SRC IP
- Send ICMP traffic with not configured inner SRC IP
- Verify that ICMP packets are not translating for not configured inner SRC IP

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_static_napt

### Test objective

Verify that NAT will happen when static NAPT configuration applied on DUT

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data and L4 ports
- Apply Static NAPT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic with DST IP/PORT according the configured NAPT rule
- Verify that traffic was SNAPT and DNAPT in both direction
- Send traffic traffic with DST IP according the configured NAPT rule and different DST PORT
- Verify that traffic was not DNAPTed

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_clear_statistics_static_basic

### Test objective

Verify that for NAT static basic configuraion NAT statistics is incremeting and can be cleared

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Static NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAT and DNAT in both direction
- Verify that NAT statistics is incremeting
- Perform clearance procedure for NAT statistics
- Make sure NAT statistics has been cleared

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_clear_statistics_static_napt

### Test objective

Verify that for NAPT static configuraion NAT statistics is incremeting and can be cleared

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Static NAPT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT in both direction
- Verify that NAT statistics is incremeting
- Perform clearance procedure for NAT statistics
- Make sure NAT statistics has been cleared

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_clear_translations_static_basic

### Test objective

Verify that for NAT static basic configuraion NAT translations cannot be cleared

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Define expected NAT translations
- Apply Static NAT config on DUT via CLI
- Perform handshake
- Make sure NAT translations has been set
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT in both direction
- Perform clearance procedure for static NAT translations
- Make sure NAT translations are not cleared
- Make sure NAT statistics is not cleared
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT in both direction

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_clear_translations_static_napt

### Test objective

Verify that for static NAPT configuraion NAT translations cannot be cleared

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Define expected NAT translations
- Apply Static NAPT config on DUT via CLI
- Perform handshake
- Make sure NAPT translations has been set
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT in both direction
- Perform clearance procedure for static NAPT translations
- Make sure NAPT translations are not cleared
- Make sure NAPT statistics is not cleared
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT in both direction

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_crud_static_nat

### Test objective

Verify Create/Read/Update/Delete actions for NAT static basic rule

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Static NAT config on DUT via CLI
- Perform handshake
- Make sure static basic NAT rule has been set
- Send bidirectional traffic
- Verify that traffic was SNAT and DNAT in both direction
- Remove NAT rule
- Make sure static basic NAT rule has been deleted
- Send bidirectional traffic
- Verify that traffic was forwarded and not SNAT/DNAT in both direction
- Add updated static basic NAT rule
- Make sure updated static basic NAT rule has been set
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAT and DNAT in both direction
- Remove NAT rule
- Make sure static basic NAT rule has been deleted
- Send bidirectional traffic
- Verify that traffic was forwarded and not SNAT/DNAT in both direction

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_crud_static_napt

### Test objective

Verify Create/Read/Update/Delete actions for NAPT static rule

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Static NAPT config on DUT via CLI
- Perform handshake
- Make sure static NAPT rule has been set
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT
- Remove NAPT rule
- Make sure static NAPT rule has been deleted
- Send bidirectional traffic
- Verify that traffic was forwarded and not SNAPT/DNAPT
- Add updated static NAPT rule
- Make sure updated static NAPT rule has been set
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT
- Remove NAT rule
- Make sure static NAPT rule has been deleted
- Send bidirectional traffic
- Verify that traffic was forwarded and not SNAPT/DNAPT

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_reboot_static_basic

### Test objective

Verify for static basic NAT that with saved configuration after COLD/FAST reboot translation takes place in accordance saved and restored static basic NAT rules

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Static NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAT and DNAT in both direction
- Save running configuration
- Perform COLD/FAST(parametrized) reboot
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAT and DNAT in both direction

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_reboot_static_napt

### Test objective

Verify for static NAPT that with saved configuration after COLD/FAST reboot translation takes place in accordance saved and restored static basic NAT rules

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Static NAPT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT in both direction
- Save running configuration
- Perform COLD/FAST(parametrized) reboot
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT in both direction

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_static_zones_basic_snat

### Test objective

Verify for static basic NAT that there is no NAT when all interfaces zones configuration is set to 1

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Set all interfaces zone config to 1
- Apply Static NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was forwarded and not SNAT
- Set inner interface (Vlan1000) zone config to 0
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAT and DNAT in both direction


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_static_zones_basic_icmp_snat

### Test objective

Verify for static basic NAT that there is no NAT for ICMP when all interfaces zones configuration is set to 1

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Set all interfaces zone config to 1
- Apply Static NAT config on DUT via CLI
- Send ICMP traffic
- Verify that traffic was forwarded and not SNAT
- Set inner interface (Vlan1000) zone config to 0
- Send ICMP traffic
- Verify that traffic was SNAT and DNAT in both direction


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_static_zones_napt_dnat_and_snat

### Test objective

Verify for static NAPT that there is no NAT when all interfaces zones configuration is set to 1

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Set all interfaces zone config to 1
- Apply Static NAPT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was refused/dropped and not DNAPT
- Verify that traffic was forwarded and not SNAPT
- Set inner interface (Vlan1000) zone config to 0
- Perform handshake
- Send bidirectional traffic
- Verify that traffic was SNAPT and DNAPT in both direction


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Dynamic NAT

## Test case test_nat_dynamic_basic

### Test objective

Verify that NAT will happen when NAT basic dynamic configuration applied on DUT

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that packet was SNAT and DNAT in both directions

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_basic_icmp

### Test objective

Verify that NAT will happen when NAT basic dynamic configuration applied on DUT for ICMP

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Send bidirectional traffic
- Verify that packet was SNAT and DNAT in both directions

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_dynamic_entry_persist

### Test objective

Verify that dynamic NAT entries are stay in the translation table according NAT protocol timeout settings

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that NAT entries are persist in the translation table according NAT protocol timeout settings, packet was SNAT and DNAT in both directions
- Wait random time in range [1 second: half global protocol timout value]
- Repeat previous 3 steps 4 times


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_entry_persist_icmp

### Test objective

Verify that with no dynamic NAT entries in the translation table ICMP id value is persist and id value is in dynamic pool range

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Send ICMP traffic
- Verify that no dynamic NAT entries in the translation table, packet was SNAT and DNAT in both directions, ICMP id value is persist and id value is in dynamic pool range
- Wait 15 seconds
- Repeat previous 2 steps 4 times

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_disable_nat

### Test objective

Verify there is no any NAT translation for dynamic NAT configuration with disabled NAT feature globally

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Disable NAT feature
- Send bidirectional traffic
- Verify that packet was not SNAT and DNAT in both directions
- Enable NAT feature
- Perform handshake
- Send bidirectional traffic
- Verify that packet was SNAT and DNAT in both directions

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_dynamic_disable_nat_icmp

### Test objective

Verify there is no any NAT translation for dynamic NAT configuration with disabled NAT feature globally for ICMP

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Disable NAT feature
- Send bidirectional traffic
- Verify that packet was not SNAT and DNAT in both directions
- Enable NAT feature
- Perform handshake
- Send bidirectional traffic
- Verify that packet was SNAT and DNAT in both directions

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_bindings

### Test objective

Verify there is no any NAT translation for dynamic NAT configuration with removed bindigs

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Remove NAT POOL bindings to ACL
- Perform handshake
- Send bidirectional traffic
- Verify that packet was not SNAT and DNAT in both directions


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_dynamic_bindings_icmp

### Test objective

Verify there is no any NAT translation for ICMP and dynamic NAT configuration with removed bindigs

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Remove NAT POOL bindings to ACL
- Perform handshake
- Send ICMP traffic
- Verify that packet was not SNAT and DNAT in both directions


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_dynamic_other_protocols

### Test objective

Verify there is no any NAT translation for non-IPv4 traffic

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Send bidirectional GRE traffic
- Verify that packet was not SNAT and DNAT in both directions


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_acl_rule_actions

### Test objective

Verify that NAT happens with ACL action "forward" and does not with action "do_not_nat"

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Set ACL with priority 10, src_ip 192.168.0.0/24 and "do_not_nat" action
- Perform handshake
- Send bidirectional traffic with src_ip 192.168.0.101
- Verify that packet was not SNAT and DNAT in both directions
- Set ACL with priority 10, src_ip 192.168.0.0/24 and "forward" action
- Perform handshake
- Send bidirectional traffic with src_ip 192.168.0.101
- Verify that packet was SNAT and DNAT in both directions
- Set ACL with priority 10, src_ip 192.168.0.0/24 and "do_not_nat" action
- Perform handshake
- Send bidirectional traffic with src_ip 192.168.0.101
- Verify that packet was not SNAT and DNAT in both directions

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_acl_rule_actions_icmp

### Test objective

Verify that NAT happens with ACL action "forward" and does not with action "do_not_nat" for ICMP

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Set ACL with priority 10, src_ip 192.168.0.0/24 and "do_not_nat" action
- Send ICMP traffic with src_ip 192.168.0.101
- Verify that packet was not SNAT and DNAT in both directions
- Set ACL with priority 10, src_ip 192.168.0.0/24 and "forward" action
- Send ICMP traffic with src_ip 192.168.0.101
- Verify that packet was SNAT and DNAT in both directions
- Set ACL with priority 10, src_ip 192.168.0.0/24 and "do_not_nat" action
- Send ICMP traffic with src_ip 192.168.0.101
- Verify that packet was not SNAT and DNAT in both directions

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_acl_modify_rule

### Test objective

Verify that NAT happens with ACL action "forward" and does not with action "do_not_nat" and changed ACL subnet value

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic with src_ip 192.168.0.101
- Verify that packet was SNAT and DNAT in both directions
- Set ACL with priority 10, src_ip 172.20.0.0/24 and "do_not_nat" action
- Send ICMP traffic with src_ip 172.20.0.2
- Perform handshake
- Send bidirectional traffic
- Verify that packet was not SNAT and DNAT in both directions

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_acl_modify_rule_icmp

### Test objective

Verify that NAT happens with ACL action "forward" and does not with action "do_not_nat" and changed ACL subnet value for ICMP

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Send bidirectional traffic
- Verify that packet was SNAT and DNAT in both directions
- Set ACL with "do_not_nat" action and change ACL subnet value
- Change traffic SRC IP according to the ACL subnet value
- Send bidirectional traffic
- Verify that packet was not SNAT and DNAT in both directions

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_pool_threshold

### Test objective

Verify that all NAT requests will be dropped in case all L4 port values from the dynamic pool range are in use

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Set dynamic pool range limited to 2 free values
- Perform handshake
- Send bidirectional 1st traffic set
- Perform handshake
- Send bidirectional 2nd traffic set
- Verify that first 2 dynamic NAT entries are created and traffic is SNAT and DNAT in both directions
- Perform handshake
- Send bidirectional 3rd traffic set
- Verify that 3-rd dynamic NAT entry is not created and packets are dropped
- Wait till first 2 dynamic NAT entries will be expired
- Perform handshake
- Send bidirectional 1st traffic set
- Perform handshake
- Send bidirectional 2nd traffic set
- Verify that 2 new dynamic NAT entries are created and traffic is SNAT and DNAT in both directions


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_crud

### Test objective

Verify that the same dynamic NAT entry's (re-added) SRC PORT is changed if dynamic pool range has been updated

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that dynamic NAT entriy is created and traffic is SNAT and DNAT
- Set new dynamic pool range values
- Wait till first dynamic NAT entry will be expired
- Perform handshake
- Send same bidirectional traffic set
- Verify that new dynamic NAT entriy is created and traffic is SNAT and DNAT
- Make sure new dynamic NAT entries has only translated SRC PORT updated

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_crud_icmp

### Test objective

Verify that translated ICMP id is changed for same traffic item if dynamic pool range has been updated

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Send ICMP traffic from the inner network
- Verify that packets ICMP id value is in configured dynamic pool range
- Set new dynamic pool range values
- Send same ICMP traffic set from the inner network
- Verify that packets ICMP id value is in updated dynamic pool range

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_dynamic_full_cone

### Test objective

Verify full cone(one to one) NAT funcionality for dynamic NAT

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Send traffic from the inner network with SRC PORT value in the configured dynamic pool range
- Verify that dynamic NAT entriy is created and traffic is SNAT and DNAT
- Make sure new dynamic NAT entry has translated SRC PORT equal to the SRC PORT of originated packet

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_dynamic_enable_disable_nat_docker

### Test objective

Verify that when NAT docker is disabled - iptable rules in the nat table and dynamic NAT translation entries are cleared.

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Make sure iptables rules are in the nat table
- Send traffic from the inner network
- Verify that dynamic NAT entriy is created and traffic is SNAT and DNAT
- Stop NAT docker
- Make sure corresponding iptables rules are cleared
- Start NAT docker
- Make sure corresponding iptables rules are restored


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_enable_disable_nat_docker_icmp

### Test objective

Verify that when NAT docker is disabled - iptable rules in the nat table and dynamic NAT translation entries are cleared.

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Make sure iptables rules are in the nat table
- Send ICMP traffic from the inner network
- Stop NAT docker
- Make sure corresponding iptables rules are cleared
- Start NAT docker
- Make sure corresponding iptables rules are restored


### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_clear_statistics_dynamic

### Test objective

Verify that NAT statistics counters for dynamic NAT entries are incremeting and can be cleared

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Send traffic from the inner network
- Verify that dynamic NAT entriy is created and traffic is SNAT and DNAT
- Make sure corresponding statistics counters for dynamic NAT entries incremented
- Perform statistics clearence procedure
- Make sure corresponding statistics counters for dynamic NAT entries has been cleared

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_clear_translations_dynamic

### Test objective

Verify that translation entries for dynamic NAT can be cleared

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Make sure there is no any translation entries for dynamic NAT
- Send traffic from the inner network
- Verify that corresponding dynamic NAT entriy is created and traffic is SNAT and DNAT
- Perform dynamic NAT translation entries clearence procedure
- Make sure there is no any translation entries for dynamic NAT
- Make sure there is no any statistics counters for dynamic NAT entries

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration

## Test case test_nat_interfaces_flap_dynamic

### Test objective

Verify that dynamic NAT translation entries and iptables rules are not cleared in case of interface flap

### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Send traffic from the inner network
- Verify that corresponding dynamic NAT entriy is created and traffic is SNAT and DNAT
- Disable the outer interface
- Make sure corresponding iptables rules are not cleared
- Make sure translation entries for dynamic NAT are not cleared
- Enable the outer interface
- Send traffic from the inner network
- Verify that traffic is SNAT and DNAT

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_zones

### Test objective

Verify for dynamic NAT that there is no NAT when all interfaces zones configuration is set to 1


### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Perform handshake
- Send bidirectional traffic
- Verify that corresponding dynamic NAT entriy is created and traffic is SNAT and DNAT
- Set all interfaces zones configuration to 1
- Send bidirectional traffic
- Verify that traffic is not SNAT and DNAT
- Set inner interface (Vlan1000) zone configuration to 0
- Perform handshake
- Send bidirectional traffic
- Verify that corresponding dynamic NAT entriy is created and traffic is SNAT

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration


## Test case test_nat_dynamic_zones_icmp

### Test objective

Verify for dynamic NAT that there is no NAT when all interfaces zones configuration is set to 1 for ICMP


### Test set up

- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data
- Apply Dynamic NAT config on DUT via CLI
- Send traffic from the inner network
- Verify that ICMP packets have correct translated SRC IP and ICMP id value in the configured dynamic pool range
- Set all interfaces zones configuration to 1
- Send same traffic set from the inner network
- Verify that ICMP packets have not trasnlated and forwarded
- Set inner interface (Vlan1000) zone configuration to 0
- Send same traffic set from the inner network
- Verify that ICMP packets have correct translated SRC IP and ICMP id value in the configured dynamic pool range

### Test teardown

- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration
