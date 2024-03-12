# IPv4 Port Based DHCP Server Test Plan
<!-- TOC -->

- [IPv4 Port Based DHCP Server Test Plan](#ipv4-port-based-dhcp-server-test-plan)
    - [Related Documents](#related-documents)
    - [Overview](#overview)
    - [Scope](#scope)
        - [Test Scenario](#test-scenario)
        - [Supported Topology](#supported-topology)
    - [Test Case](#test-case)
        - [Common Function](#common-function)
            - [send_and_verify:](#send_and_verify)
        - [Test Module #1 test_dhcp_server.py](#test-module-1-test_dhcp_serverpy)
            - [Port Based Common setup](#port-based-common-setup)
            - [Port Based Common teardown](#port-based-common-teardown)
            - [test_dhcp_server_port_based_assignment_single_ip](#test_dhcp_server_port_based_assignment_single_ip)
            - [test_dhcp_server_port_based_assigenment_single_ip_mac_move](#test_dhcp_server_port_based_assigenment_single_ip_mac_move)
            - [test_dhcp_server_port_based_assigenment_single_ip_mac_swap](#test_dhcp_server_port_based_assigenment_single_ip_mac_swap)
            - [test_dhcp_server_port_based_assignment_range](#test_dhcp_server_port_based_assignment_range)
            - [test_dhcp_server_port_based_customize_options](#test_dhcp_server_port_based_customize_options)
            - [test_dhcp_server_config_change](#test_dhcp_server_config_change)
            - [test_dhcp_server_config_vlan_intf_change](#test_dhcp_server_config_vlan_intf_change)
            - [test_dhcp_server_config_vlan_member_change](#test_dhcp_server_config_vlan_member_change)
            - [test_dhcp_server_critical_process](#test_dhcp_server_critical_process)
        - [Test Module #2 test_dhcp_server_multi_vlan.py](#test-module-2-test_dhcp_server_multi_vlanpy)
            - [Common setup](#common-setup)
            - [Common teardown](#common-teardown)
            - [test_dhcp_server_multi_vlan](#test_dhcp_server_multi_vlan)
        - [Test Module #3 test_dhcp_server_stress.py](#test-module-3-test_dhcp_server_stresspy)
            - [Common setup](#common-setup)
            - [Common teardown](#common-teardown)
            - [test_dhcp_server_stress](#test_dhcp_server_stress)
        - [Test Module #4 test_dhcp_server_smart_switch.py](#test-module-4-test_dhcp_server_smart_switchpy)
            - [Common setup](#common-setup)
            - [Common teardown](#common-teardown)
            - [test_dhcp_server_smart_switch](#test_dhcp_server_smart_switch)

<!-- /TOC -->
## Related Documents

| **Document Name** | **Link** |
|-------------------|----------|
| IPv4 Port Based DHCP_SERVER in SONiC | [port_based_dhcp_server_high_level_design.md](https://github.com/sonic-net/SONiC/blob/master/doc/dhcp_server/port_based_dhcp_server_high_level_design.md)|
|Smart Switch IP address assignment| [smart-switch-ip-address-assignment.md](https://github.com/sonic-net/SONiC/blob/master/doc/smart-switch/ip-address-assigment/smart-switch-ip-address-assignment.md)|

## Overview

A DHCP Server is a server on network that can automatically provide and assign IP addresses, default gateways and other network parameters to client devices. Port based DHCP server is to assign IPs based on interface index.

## Scope

### Test Scenario

The tests will include:

1. Configuration test
   1. Add related configuration into CONFIG_DB and then verify configuration and process running status.
   2. Update related tables in CONFIG_DB to see whether configuration for DHCP Server change too.
2. Functionality test
   1. Check whether dhcrelay in dhcp_relay can foward DHCP packets between client and dhcp_server container.
   2. Check whether dhcp_server container can reply DHCP reply packets as expected.
   3. Verify in multi-vlan scenario.
   4. Verify in mac change scenario.

### Supported Topology

Base dhcp_server functionality tests (test module [#1](#test-module-1-test_dhcp_serverpy) [#2](#test-module-2-test_dhcp_server_multi_vlanpy) [#3](#test-module-3-test_dhcp_server_stresspy)) are supported on mx topology, smart switch related test (test module [#4](#test-module-4-test_dhcp_server_smart_switchpy)) is supported on t1-smartswitch topology (A new topology on real smart switch testbed).

## Test Case

### Common Function

#### send_and_verify
 * Send DHCP discover packets from PTF, check whether configured port receive DHCP offer packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr.
 * Send DHCP request packets from PTF, check whether configured port receive DHCP ack packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr. Besides, check lease via show CLI to make sure lease is correct.
 * For renew scenario, send DHCP request packets from PTF, check whether configured port receive DHCP ack packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr. Besides, check lease via show CLI to make sure lease is correct.
 * Send DHCP release packets from PTF, check whether lease release via lease file inside dhcp_server container.

### Test Module #1 test_dhcp_server.py

#### Port Based Common setup

* Check whether dhcrelay process running as expected (Original dhcp_relay functionality).
* Enable dhcp_server feature, and then use CLI to add DHCP Server configuration.

#### Port Based Common teardown

* Disable dhcp_server feature, and then check whether dhcrelay process running as expected (Original dhcp_relay functionality).
* Config reload, remove dhcp_server container.

#### test_dhcp_server_port_based_assignment_single_ip

* **Test objective**

  To test port based single ip assign.

  Assume that ports in DUT and PTF are connected like below:

  * DUT Ethernet0 - PTF eth0
  * DUT Ethernet1 - PTF eth1
  * DUT Ethernet2 - PTF eth2
  * DUT Ethernet3 - PTF eth3
  * DUT EThernet4 - PTF eth4 (Not configured interface)

  3 tested scenarios:

  1. Verify configured interface with client mac not in FDB table can successfully get IP.
  2. Verify configured interface with client mac in FDB table can successfully get IP.
  3. Verify configured interface with client mac in FDB table but ip it's learnt from another interface can successfully get IP.
  4. Verify no-configured interface cannot get IP.

* **Setup**

  * Clear FDB table in DUT.
  * Ping DUT vlan ip from eth1 and eth3 in PTF.

* **Test detail**

  * Add a fixture to verify above scenarios:
    * mac_not_in_fdb: Use `send_and_verify` to send and verify from eth0 with mac address of eth0, success to get IP.
    * mac_in_fdb:Use `send_and_verify` to send and verify from eth0 with mac address of eth1, success to get IP.
    * mac_learnt_from_other_interface: Use `send_and_verify` to send and verify from eth2 with mac address of eth3, success to get IP.
    * no_configured_interface: Use `send_and_verify` to send and verify from eth4 with mac address of eth4, expected result: fail to get IP.

#### test_dhcp_server_port_based_assigenment_single_ip_mac_move

* **Test objective**

  To test port based single ip assign with client move to an interface has free IP to assign.

* **Setup**

  Save originaly mac address in PTF.

* **Teardown**

  Restore mac address configuration in PTF.

* **Test detail**

  * `send_and_verify` with mac A in interface A, expected result: IP assign successfully.
  * `send_and_verify` with mac A in interface B, expected result: IP assign successfully.

#### test_dhcp_server_port_based_assigenment_single_ip_mac_swap

* **Test objective**

  To test port based single ip assign with client swap.

* **Setup**

  Save originaly mac address in PTF.

* **Teardown**

  Restore mac address configuration in PTF.

* **Test detail**

  * `send_and_verify` with mac A in interface A, expected result: client A can get correct IP.
  * `send_and_verify` with mac B in interface B, expected result: client A can get correct IP.
  * `send_and_verify` with mac A in interface B, expected result: client A can get correct IP.
  * `send_and_verify` with mac B in interface A, expected result: client A can get correct IP.

#### test_dhcp_server_port_based_assignment_range

* **Test objective**

   To test port based range ip assign.

* **Setup**

  Add range and bind range via CLI.

* **Teardown**

  Unbind range and del range via CLI.

* **Test detail**

  * Always send packets from 1 PTF port with different client mac, process of sending and verifying can reuse function `send_and_verify`.
  * Verify that new client can get / renew / release IP from range binded. When IPs in range are all used, new client cannot get IP.

#### test_dhcp_server_port_based_customize_options

* **Test objective**

   To test customize options (In current design, customized options will be always sent to client).

* **Setup**

  Add option and bind option via CLI.

* **Teardown**

  Unbind option and del option via CLI.

* **Test detail**

  * Send DHCP discover packets from PTF, check whether configured port receive DHCP offer packet and no-configured ports don't receive. Need to check customized options.
  * Send DHCP request packets from PTF, check whether configured port receive DHCP ack packet and no-configured ports don't receive. Need to check customized options.
  * Send DHCP release packets from PTF.

#### test_dhcp_server_config_change

* **Test objective**

   To test dhcp_server configuration change scenario.

* **Test detail**

  * Use CLI to modify lease_time / netmask / gateway / customized_options in `DHCP_SEVER_IPV4` table and send discover / requset packets from PTF and check whether receive expected offer / ack packets.
  * Use CLI to disable / enable DHCP interface and send discover / requset packets from PTF and check whether receive expected offer / ack packets.
  * Use CLI to modify `DHCP_SERVER_IPV4_PORT` / `DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS` and send discover / requset packets from PTF and check whether receive expected offer / ack packets.

#### test_dhcp_server_config_vlan_intf_change

* **Test objective**

   To test vlan interface configuration change scenario.

* **Setup**

  Modify vlan ip in `VLAN_INTERFACE` table, change to another subnet.

* **Teardown**

  Restore vlan ip.

* **Test detail**

  * Send discover / requset packets from PTF, expect not receive offer / ack packets because ip address configure in `DHCP_SERVER_IPV4_PORT` doesn't match vlan ip.

#### test_dhcp_server_config_vlan_member_change

* **Test objective**

   To test vlan member configuration change scenario.

* **Setup**

  Delete vlan member.

* **Teardown**

  Restore vlan member.

* **Test detail**

  * Send discover / requset packets from PTF, expect not receive offer / ack packets because member not in vlan.

#### test_dhcp_server_critical_process

* **Test objective**

   To test critical processes crush scenario.

* **Test detail**

   * Kill processes in `dhcp_relay:/etc/supervisor/critical_processes` and `dhcp_server:/etc/supervisor/critical_processes` to see whether dhcp_server and dhcp_relay container restart.
   * Can refer to `tests/process_monitoring/test_critical_process_monitoring.py`

### Test Module #2 test_dhcp_server_multi_vlan.py

#### Common setup

* Enable dhcp_server feature.
* Apply DHCP Server related configuration for multiple vlans (Suggest use GCU).
* Use GCU to apply different VLAN configuration (VLAN / VLAN_MEMBER / VLAN_INTERFACE). The reason use GCU is that changing VLAN configuration via CLI is complicate.

#### Common teardown

* Config reload, remove dhcp_server container.

#### test_dhcp_server_multi_vlan

* **Test objective**

   To test ip assign in multiple vlan scenario.

* **Test detail**

  * Send DHCP discover packets from PTF, check whether configured port receive DHCP offer packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr.
  * Send DHCP request packets from PTF, check whether configured port receive DHCP ack packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr. Besides, check lease via show CLI to make sure lease is correct.
  * For renew scenario, send DHCP request packets from PTF, check whether configured port receive DHCP ack packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr. Besides, check lease via show CLI to make sure lease is correct.
  * Send DHCP release packets from PTF, check whether lease release via lease file inside dhcp_server container.

### Test Module #3 test_dhcp_server_stress.py

#### Common setup

* Enable dhcp_server feature, and then add DHCP Server configuration.

#### Common teardown

* Config reload, remove dhcp_server container.

#### test_dhcp_server_stress

* **Test objective**

   To test ip assign with flooding packets.

* **Test detail**

   * Send flooding (100/s) DHCP discover packets in PTF and verify offer packets receive (whether receive and receive time) in PTF side.
   * Send flooding (100/s) DHCP request packets in PTF and verify ack packets receive (whether receive and receive time) in PTF side.

### Test Module #4 test_dhcp_server_smart_switch.py

#### Common setup

* Enable dhcp_server feature.
* Add DHCP Server configuration.
* Add smart switch related configuration (`DPUS` table and `MID_PLANE` table).

#### Common teardown

* Config reload, remove dhcp_server container.

#### test_dhcp_server_smart_switch

* **Test objective**

   To test ip assign with in smart switch.

* **Test detail**

  * Send DHCP discover packets from PTF, check whether configured port receive DHCP offer packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr.
  * Send DHCP request packets from PTF, check whether configured port receive DHCP ack packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr. Besides, check lease via show CLI to make sure lease is correct.
  * For renew scenario, send DHCP request packets from PTF, check whether configured port receive DHCP ack packet and no-configured ports don't receive. Need to check netmask / gateway / lease_time / yiaddr. Besides, check lease via show CLI to make sure lease is correct.
  * Send DHCP release packets from PTF, check whether lease release via lease file inside dhcp_server container.
