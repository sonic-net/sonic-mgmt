# ACL Outer Vlan_ID Test Plan

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#Setup-configuration)
- [Test Cases](#Test-cases)
  - [test_egress_vlan_outer_forward](#Test-case-test_egress_vlan_outer_forward)
  - [test_ingress_vlan_outer_forward](#Test-case-test_ingress_vlan_outer_forward)
  - [test_ingress_vlan_outer_drop](#Test-case-test_ingress_vlan_outer_drop)
  - [test_egress_vlan_outer_drop](#Test-case-test_egress_vlan_outer_drop)

## Overview

The purpose is to test the functionality of ACL feature on the SONiC switch DUT. The tests expecting that all necessary configuration for ACL are pre-configured on SONiC switch before test runs.

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
During test run 2 ACL tables of different types 'L3' and 'L3V6' will be created, with bindind to a single Port/PortChannel.

Example of Acl rules that will be created:

acltb_test_rules_outer_vlan.j2
```
{
    "ACL_RULE": {
        "{{ table_egress }}|rule_1": {
            "priority": "1003",
            "VLAN_ID": "100",
            "PACKET_ACTION": "FORWARD"
        },
        "{{ table_egress }}|rule_2": {
            "priority": "1002",
            "VLAN_ID": "100",
            "PACKET_ACTION": "DROP"
        },
        "{{ table_ingress }}|rule_1": {
            "priority": "1001",
            "VLAN_ID": "200",
            "PACKET_ACTION": "FORWARD"
        },
        "{{ table_ingress }}|rule_2": {
            "priority": "1000",
            "VLAN_ID": "200",
            "PACKET_ACTION": "DROP"
        }
    }
}
```

## Test cases

## Test case test_egress_vlan_outer_forward

### Test objective

Validate that packet is swithed if egress ACL rule with action forward is matched with Outer Vlan ID.

### Test steps

- Create UDP packet with single Vlan ID.
- Send UDP packet from PTF to DUT.
- Verify that PTF received UDP packet.
- Verify that ACL counter for particular rule was incremented.

## Test case test_ingress_vlan_outer_forward

### Test objective

Validate that packet is swithed if ingress ACL rule with action forward is matched with Outer Vlan ID.

### Test steps

- Create QinQ packet or TCP packet with single Vlan ID in case of ipv6 traffic.
- Send QinQ packet from PTF to DUT.
- Verify that PTF received QinQ packet.
- Verify that ACL counter for particular rule was incremented.

## Test case test_ingress_vlan_outer_drop

### Test objective

Validate that packet aren't switched if ingress ACL rule with action drop is matched with Outer_Vlan ID.

### Test steps

- Remove ingress ACL rule with action forward for vlan 200.
- Create QinQ packet or TCP packet with single Vlan ID in case of ipv6 traffic.
- Send QinQ packet from PTF to DUT.
- Verify that QinQ packet wasn't switched to PTF.
- Verify that ACL counter for particular rule was incremented.

## Test case test_egress_vlan_outer_drop

### Test objective

Validate that packet aren't switched if egress ACL rule with action drop is matched with Outer Vlan ID.

### Test set up
- Delete previosly created Acl forward rule.

### Test steps

- Remove egress ACL rule with action forward for vlan 100.
- Create UDP packet with single Vlan ID.
- Send UDP packet from PTF to DUT.
- Verify that UDP packet wasn't switched to PTF.
- Verify that ACL counter for particular rule was incremented.
