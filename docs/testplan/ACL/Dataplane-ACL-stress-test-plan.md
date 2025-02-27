# Dataplane ACL Stress Test Plan

- [Overview](#overview)
  - [Scope](#scope)
  - [Topology](#topology)
- [Setup configuration](#setup-configuration)
- [Test scenarios](#test-scenarios)
  - [Scale test](#Scale-test)
  - [Dynamically ACL update test](#dynamically-acl-update-test)
  - [Dynamically ACL update test on custom ACL table type](#dynamically-acl-update-test-on-custom-acl-table-type)
- [Open questions](#open-questions)

## Overview

The purpose for this doc is to propose a stress test plan for dataplane ACL.

## Scope

The test is targeting a running SONiC system with fully functioning configuration.
Purpose of the test is to verify dataplane ACL is functioning properly in large scale and after dynamically updating.
The stress test will only cover Ingress ACL.

## Topology

The test suite will be implemented in 4 steps
- Step 1: support both T0 and T1 topologies
- Step 2: support dualtor (active-standby and active-active mode)
- Step 3: support M0 and Mx topology
- Step 4: support T2 topology

## Setup configuration

No setup pre-configuration is required, test will configure and return testbed to the initial state.


The Acl rule will be created before test running, and removed after test running.
## Test scenarios

### Scale test

#### Test objective

This test is to verify dataplane ACL is functioning properly when a large scale of ACL rules are configured to ASIC.

#### Test steps

1. Define different scale for each covered platform. A table like below is recommended.

    | Platform | Scale |
    |----------|-------|
    | Arista-7050cx3       | 500 |
    | Mellanox-SN2700       | 800 |
    | ... | ...|
    | Default       | 200  |

    An initial scale test is requried to get the scale for each platform. If the scale is not specified, default scale will be used.
2. Create dataplane ACL tables `DATAACL` with type `L3` and `DATAACL_V6` with type `L3V6` if not exist.
3. Create ACL rules by loading `acl.json` in OpenConfig format or loading config patch with `config apply-patch` command (recommended). A sample patch (IPv4) is as below
    ```
    [
      {
        "op": "add",
        "path": "/ACL_RULE",
        "value": {
          "DATAACL|RULE_1": {
            "DST_IP": "10.10.10.1/32",
            "PRIORITY": "9999",
            "PACKET_ACTION": "FORWARD"
          },
          "DATAACL|RULE_2": {
            "DST_IP": "10.10.10.2/32",
            "PRIORITY": "9998",
            "PACKET_ACTION": "FORWARD"
          },
          ......
          "DATAACL|RULE_255": {
            "DST_IP": "10.10.10.255/32",
            "PRIORITY": "9744",
            "PACKET_ACTION": "FORWARD"
          },
          "DATAACL|DEFAULT": {
            "ETHERNET_TYPE": "0x0800",
            "PRIORITY": "9000",
            "PACKET_ACTION": "DROP"
          }
        }
      }
    ]
    ```
4. Cleanup the testbed, including removing all ACL rules and tables.

**Notes:**
  - The json patch should be generated according to the scale.
  - There is a default rule which is used to drop all other packets. The priority should be lower than all other rules.


4. Check the status of the rules by running `show acl rule` command. The status should be `ACTIVE`.
5. Send packets from PTF to DUT and verify the packets are forwarded properly.

#### Test expectation
  - No service crash. No error logs from SAI and SDK.
  - All traffic test passed

### Dynamically ACL upadte test

#### Test objective

This test is to verify dataplane ACL is still functioning properly after changing dynamically.

#### Test steps

1. Create dataplane ACL tables `DATAACL` with type `L3` and `DATAACL_V6` with type `L3V6` if not exist.
2. Programme a set of ACL rules as described in the scale test.
3. Perform dynamically updates on the ACL rules with `config apply-patch` command. The updates include
    - Add new rules
    - Remove existing rules
    - Modify existing rules

  A sample json patch for adding new rules

  ```
  [
      {
        "op": "add",
        "path": "/ACL_RULE",
        "value": {
          "DATAACL|RULE_300": {
            "DST_IP": "10.10.20.1/32",
            "PRIORITY": "9999",
            "PACKET_ACTION": "FORWARD"
          },
          "DATAACL|RULE_301": {
            "DST_IP": "10.10.20.2/32",
            "PRIORITY": "9998",
            "PACKET_ACTION": "FORWARD"
          },
          ......
          "DATAACL|RULE_310": {
            "DST_IP": "10.10.20.10/32",
            "PRIORITY": "9790",
            "PACKET_ACTION": "FORWARD"
          }
        }
      }
    ]
  ```
  A sample json patch for removing existing rules
  ```
  [
      {
        "op": "remove",
        "path": "/ACL_RULE/DATAACL|RULE_1"
      },
      {
        "op": "remove",
        "path": "/ACL_RULE/DATAACL|RULE_2"
      },
      ......
      {
        "op": "remove",
        "path": "/ACL_RULE/DATAACL|RULE_255"
      }
    ]
  ```
  A sample json patch for modifying existing rules
  ```
  [
      {
        "op": "replace",
        "path": "/ACL_RULE/DATAACL|RULE_1/DST_IP",
        "value": "10.10.30.1/32"
      },
      {
        "op": "replace",
        "path": "/ACL_RULE/DATAACL|RULE_2/DST_IP",
        "value": "10.10.30.2/32"
      },
      ......
      {
        "op": "replace",
        "path": "/ACL_RULE/DATAACL|RULE_255/DST_IP",
        "value": "10.10.30.255/32"
      }
    ]
  ```
4. Run step 3 repeatly for a few times. The number can be specified by argument.
5. Send packets from PTF to DUT and verify the packets are forwarded properly.
6. Cleanup the testbed, including removing all ACL rules and tables.

#### Test expectation
  - No service crash. No error logs from SAI and SDK
  - All traffic test passed

### Dynamically ACL upadte test on custom ACL table type

#### Test objective

This test scenario is to verify dataplane ACL is still functioning properly after changing dynamically on custom ACL table type.

#### Test steps

1. Define a custom ACL table type by loading configuration in json format with `config apply-patch` command. A sample json is as below
  ```
  [
    {
      "op": "add",
      "path": "/ACL_TABLE_TYPE",
      "value": {
        "CUSTOM_TABLE_TYPE": {
          "MATCHES": [
            "DST_IP",
            "DST_IPV6",
            "L4_DST_PORT",
            "IP_PROTOCOL",
            "ETHER_TYPE",
            "IN_PORTS"
          ],
          "ACTIONS": [
            "PACKET_ACTION",
            "COUNTER"
          ],
          "BIND_POINTS": [
            "PORT"
          ]
        }
      }
    }
  ]
  ```
2. Create an ACL table with the custom type by loading a json patch with `config apply-patch` command. A sample json is as below
  ```
  [
	{
		"op": "add",
		"path": "/ACL_TABLE/CUSTOM_TABLE",
		"value": {
			"policy_desc": "CUSTOM_TABLE",
			"type": "CUSTOM_TABLE_TYPE",
			"stage": "INGRESS",
			"ports": [
				"Ethernet4",
				"Ethernet8",
				"Ethernet12",
				"Ethernet16",
				"Ethernet20",
				"Ethernet24",
				"Ethernet28",
				"Ethernet32",
				"Ethernet36",
				"Ethernet40",
				"Ethernet44",
				"Ethernet48",
				"Ethernet52",
				"Ethernet56",
				"Ethernet60",
				"Ethernet64",
				"Ethernet68",
				"Ethernet72",
				"Ethernet76",
				"Ethernet80",
				"Ethernet84",
				"Ethernet88",
				"Ethernet92",
				"Ethernet96"
			]
		}
	}
]
  ```
3. Programme a set of ACL rules as described in the scale test. The ACL rules should cover both IPv4 and IPv6.
4. Perform dynamically updates on the ACL rules with `config apply-patch` command. The updates include
    - Add new rules
    - Remove existing rules
    - Modify existing rules
5. Run step 4 repeatly for a few times. The number can be specified by argument.
6. Send packets from PTF to DUT and verify the packets are forwarded properly.
7. Cleanup the testbed, including removing all ACL rules, tables and table type definition.

#### Test expectation
  - No service crash. No error logs from SAI and SDK
  - All traffic test passed

## Open questions
  - When to run the test?

    The stress test is expected to take a few hours. It is recommended to run the test in a single pipeline rather than in nightly test.

  - How to determine the scale for each platform?

    The scale can be determined by running the test with a few different scales and check the result. The scale used in test should be slightly lower than the scale which can pass the test.

  - How to determine the number of repeatly updates?

    The number of repeatly updates can be determined by the time taken for each update.
