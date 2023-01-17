# ACL Outer Vlan_ID Test Plan

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test Cases](#test-cases)
  - [test_tagged_forwarded](#test-case-group-1)
  - [test_tagged_dropped](#test-case-group-2)
  - [test_untagged_forwarded](#test-case-group-1)
  - [test_untagged_dropped](#test-case-group-2)
  - [test_combined_tagged_forwarded](#test-case-group-1)
  - [test_combined_tagged_dropped](#test-case-group-2)
  - [test_combined_untagged_forwarded](#test-case-group-1)
  - [test_combined_untagged_dropped](#test-case-group-2)
- [TODO](#todo)

## Overview

The purpose is to test the functionality of ACL feature on the SONiC switch DUT.

## Scope

The test is targeting a running SONiC system with fully functioning configuration.
Purpose of the test is to verify a SONiC switch system correctly performs ACL actions based on match with Outer Vlan Id.

## Testbed

Supported topologies: t0

## Setup configuration

No setup pre-configuration is required, test will configure and return testbed to the initial state.

### Setup of DUT switch

On setup, tests will create 2 Vlans and add members to it on DUT.
Before test run ports that will become Vlan members should be removed from Vlan1000.
Example of created vlan

    +-----------+-----------------+-------------+----------------+-----------------------+-------------+
    |   VLAN ID | IP Address      | Ports       | Port Tagging   | DHCP Helper Address   | Proxy ARP   |
    +===========+=================+=============+================+=======================+=============+
    |       100 | 192.100.0.1/24  | Ethernet24  | tagged         |                       | disabled    |
    |           | fc02:100::1/96  | Ethernet32  | untagged       |                       |             |
    +-----------+-----------------+-------------+----------------+-----------------------+-------------+
    |       200 | fc02:200::1/96  | Ethernet28  | untagged       |                       | disabled    |
    |           | 192.200.0.1/24  | Ethernet32  | tagged         |                       |             |
    +-----------+-----------------+-------------+----------------+-----------------------+-------------+
- Ethernet24 belongs to Vlan100, tagged mode
- Ethernet28 belongs to Vlan200, untagged mode
- Ethernet32 belongs to both Vlan100 (untagged) and Vlan200 (tagged)

During test run 2 ACL tables of different types 'L3' and 'L3V6' will be created and binded to all the above 3 interfaces.

Example of Acl rules that will be created:

acltb_test_rules_outer_vlan.j2
```
{
    "ACL_RULE": {
        "{{ table_name }}|rule_1": {
            "priority": "1003",
            "VLAN_ID": "{{ vlan_id }}",
            "PACKET_ACTION": "{{ action }}"
        }
    }
}
```
The Acl rule will be created before test running, and removed after test running.
## Test cases

## Test case group 1
- test_tagged_forwarded
- test_untagged_forwarded
- test_combined_tagged_forwarded
- test_combined_untagged_forwarded

### Test objective

Validate that packet is switched if ACL rule with action ```FORWARD``` is matched with Outer Vlan ID. The test cases will cover tagged, untagged and combined(tagged in one vlan and untagged in another vlan) mode.

### Test steps
#### Ingress
- Create QinQ TCP packet with target vlan ID.
- Send packet from PTF to one of the interface in vlan.
- Verify that packet is switched to the other interface in vlan.
- Verify that ACL counter for particular rule was incremented.
#### Egress
- Create TCP packet with dst_ip in vlan.
- Send packet from PTF to one of the PortChannels on DUT.
- Verify that packet is switched to the target interface in vlan.
- Verify that ACL counter for particular rule was incremented.
## Test case group 2
- test_tagged_dropped
- test_untagged_dropped
- test_combined_tagged_dropped
- test_combined_untagged_dropped

### Test objective

Validate that packet is dropped if ACL rule with action ```DROP``` is matched with Outer Vlan ID. The test cases will cover tagged, untagged and combined(tagged in one vlan and untagged in another vlan) mode.

### Test steps

#### Ingress
- Create QinQ TCP packet with target vlan ID.
- Send packet from PTF to one of the interface in vlan.
- Verify that packet is not switched to the other interface in vlan.
- Verify that ACL counter for particular rule was incremented.
#### Egress
- Create TCP packet with dst_ip in vlan.
- Send packet from PTF to one of the PortChannels on DUT.
- Verify that packet is not switched to the target interface in vlan.
- Verify that ACL counter for particular rule was incremented.
