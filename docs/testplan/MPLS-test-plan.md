- [Overview](#overview)
  * [Scope](#scope)
  * [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
    + [Setup of DUT switch](#setup-of-dut-switch)
- [Test cases](#test-cases)
  * [Test case \#1 - POP Label](#test-case-1---pop-label)
    + [Test objective](#test-objective)
    + [Test steps](#test-steps)
  * [Test case \#2 - SWAP Label for single label](#test-case-2---swap-label-for-single-label)
    + [Test objective](#test-objective-1)
    + [Test steps](#test-steps-1)
  * [Test case \#3 - PUSH Label](#test-case-3---push-label)
    + [Test objective](#test-objective-2)
    + [Test steps](#test-steps-2)
  * [Test case \#4 - SWAP Label for multiple label stack](#test-case-4---swap-label-for-multiple-label-stack)
    + [Test objective](#test-objective-3)
    + [Test steps](#test-steps-3)

## Overview
This is Test Plan to test MPLS feature on SONiC. The test enables MPLS on interfaces, configures static LSPs and assumes all basic configurations including BGP routes are already preconfigured.

### Scope
The test is targeting a running SONiC system with basic functioning configuration.
Purpose of the test is to verify MPLS on a SONiC system bringing up the ingress, transit or egress static LSP and forwarding the traffic correctly.

### Testbed 
T1

## Setup configuration
MPLS configuration will be set on DUT dynamically.

#### Setup of DUT switch
During testrun, Ansible will copy JSON file containing configuration for MPLS to DUT and push to SONiC APPL DB via swssconfig.

JSON Sample:

label_pop_routes.json

```
[
    {
        "LABEL_ROUTE_TABLE:1000001": {
            "nexthop": "10.0.0.51",
            "ifname": "Ethernet25",
            "weight": "1"
        },
        "OP": "SET"
    },
    {
        "INTF_TABLE:Ethernet10": {
            "mpls": "enable"
        },
        "OP": "SET"
    },
    {
        "LABEL_ROUTE_TABLE:1000003": {
            "nexthop": "10.0.0.21",
            "ifname": "Ethernet10",
            "weight": "1"
        },
        "OP": "SET"
    },
    {
        "INTF_TABLE:Ethernet25": {
            "mpls": "enable"
        },
        "OP": "SET"
    }
]
 ```
 
 label_push_routes.json
 
 ```
 [
    {
        "ROUTE_TABLE:192.168.0.1": {
            "nexthop": "1000001+10.0.0.51",
            "ifname": "Ethernet25",
            "weight": "1"
        },
        "OP": "SET"
    },
    {
        "INTF_TABLE:Ethernet25": {
            "mpls": "enable"
        },
        "OP": "SET"
    }
]
```
label_swap_routes.json

```
[
    {
        "LABEL_ROUTE_TABLE:1000001": {
            "nexthop": "1000002+10.0.0.51",
            "ifname": "Ethernet25",
            "weight": "1"
        },
        "OP": "SET"
    },
    {
        "INTF_TABLE:Ethernet10": {
            "mpls": "enable"
        },
        "OP": "SET"
    },
    {
        "LABEL_ROUTE_TABLE:1000003": {
            "nexthop": "1000004+10.0.0.21",
            "ifname": "Ethernet10",
            "weight": "1"
        },
        "OP": "SET"
    },
    {
        "INTF_TABLE:Ethernet25": {
            "mpls": "enable"
        },
        "OP": "SET"
    }
]
```
label_del_routes.json

```
[
    {
        "LABEL_ROUTE_TABLE:1000001": {
        },
        "OP": "DEL"
    },
    {
        "INTF_TABLE:Ethernet10": {
        },
        "OP": "DEL"
    },
    {
        "LABEL_ROUTE_TABLE:1000003": {
        },
        "OP": "DEL"
    },
    {
        "INTF_TABLE:Ethernet25": {
        },
        "OP": "DEL"
    },
    {
        "ROUTE_TABLE:192.168.0.1": {
        },
        "OP": "DEL"
    }
]
```
## Test cases

Each testcase configures static LSP, sends traffic, captures on receving port and verifies appropriate LABEL action is applied on packet.

### Test case \#1 - POP Label

#### Test objective

Verify that the MPLS label is removed on the received packet.

#### Test steps
- Enable MPLS on interfaces and configure pop label.
- Send MPLS packet.
- Capture the packet and verify that it is IP packet with MPLS removed.

### Test case \#2 - SWAP Label for single label

#### Test objective

Verify that the MPLS label is swapped on the received packet.

#### Test steps
- Enable MPLS on interfaces and configure swap label for MPLS packet.
- Send MPLS packet.
- Capture the packet and verify that it is MPLS packet with label swapped as per configuration.

### Test case \#3 - PUSH Label

#### Test objective

Verify that the MPLS label is pushed on the received packet.

#### Test steps
- Enable MPLS on interfaces and configure push label for MPLS packet.
- Send IP packet.
- Capture the packet and verify that it is MPLS packet with label added as per configuration. 


### Test case \#4 - SWAP Label for multiple label stack

#### Test objective

Verify that the MPLS top label is swapped on the received packet.

#### Test steps
- Enable MPLS on interfaces and configure swap label for MPLS packet.
- Send MPLS packet.
- Capture the packet and verify that it is MPLS packet with label swapped as per configuration for the top label.
 
