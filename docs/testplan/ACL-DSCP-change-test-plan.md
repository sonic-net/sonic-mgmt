## [DRAFT, UNDER DEVELOPMENT]
## Table of Contents

1. [Overview](#overview)
    1. [Scope](#scope)
    2. [Related DUT CLI commands](#related-dut-cli-commands)
2. [Test structure](#test-structure)
    1. [Setup configuration](#setup-configuration)
    2. [Teardown](#teardown)
    3. [Scripts for generating ACL configuration on SONIC](#scripts-for-generating-acl-configuration-on-sonic)
    4. [General Test Flow](#General-Test-Flow)
    5. [Packet Structure](#packet-structure)
5. [Test Cases](#test-cases)
    1. [Test case #1 - Basic verification test](#test-case-1---basic-verification-test)
    2. [Test case #2 - ACL rules with different DSCP values](#test-case-2---acl-rules-with-different-dscp-values)
    3. [Test case #3 - ACL rules with different match criteria](#test-case-3---acl-rules-with-different-match-criteria)
    4. [Test case \#4 - ACL rules with different match criteria but same DSCP rewrite value](#test-case-4---acl-rules-with-different-match-criteria-but-same-dscp-rewrite-value)

## Overview
The purpose is to test the functionality of DSCP change ACL rules on the SONIC switch DUT with and without LAGs configured, closely resembling the production environment.
The test assumes all necessary configurations, including ACL and LAG configuration, and BGP routes, are already pre-configured on the SONIC switch before the test runs.

### Scope
The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is not to test specific SAI API, but functional testing of DSCP change ACL on SONIC system ensuring that
the outer DSCP value of the Vxlan encapsulated packet is changed based on the original packet match criteria.
In order to perform these tests, the DUT needs to be configured with VXLAN ECMP routes so these tests can only be performed on platforms supporting this feature.
In addition, the ACL DSCP change feature depends on the SAI_ACL_METADATA support to work. This also limits this test run to only
T1 platforms supporting this capability.

The setup configuration for ACL and VXLAN tunnel routes is beyond the scope of this document.

### Related **DUT** CLI commands
Manual ACL configuration can be done using swssconfig utility in swss container.

    swssconfig <json-file to apply>

## Test structure

### Setup configuration
These tests require Vxlan tunnel configuration along with ACL configuration. It uses the existing infrastructure of ACL and 
Vxlan ECMP tests to perform the required configuration on the device. 
The setup performs the following tasks
1) Select Vxlan encapsulation: The test runs all the cases with the following Vxlan encapsulation scenarios

    a) 'v4_in_v4'

    b) 'v6_in_v4'

    c) 'v4_in_v6'

    d) 'v6_in_v6'

2) Selection of ports: The test selects the ports from the upstream devices connected to the DUT in the testbed. These ports are used for sending to and receiving the packets from the DUT.
3) Vxlan ECMP routes setup: Using the Vxlan ECMP REST libraries, this test sets up the following configuration.

   a) Vxlan Tunnel with src IP set to the DUT loopback address and Vxlan source port=4789.

   b) VNET setup with VNI=10000

   c) Setup VNET routes with ECMP nexthops. This setup part allocates a route prefix and 4 nexthop addresses based on the Vxlan encapsulation type parameters.
    It then creates a vxlan tunnel route with 4 nexthops

### Teardown
During teardown, the test cleans up the VNET and Vxlan configuration along with any outstanding ACL rules which remain due to a failing previous test combination run.
This ensures that the lingering configuration does not impact the next test run.

### Scripts for generating ACL configuration on SONIC

There will be two j2 template files for the ACL test configuration: dscp_acl_tablev4_v6.j2 and dscp_acl_rulev4_v6.j2. They will be used by an Ansible playbook to generate JSON files and apply them on the switch.
An example of the generated JSON files is shown below.

table.json

        {
            "ACL_TABLE": {
                "OVERLAY_MARK_META_TEST": {
                    "policy_desc": "OVERLAY_MARK_META_TESTV4",
                    "ports": [
                        "Ethernet0"
                    ],
                    "stage": "ingress",
                    "type": "UNDERLAY_SET_DSCP"
                },
                "OVERLAY_MARK_META_TESTV6": {
                    "policy_desc": "OVERLAY_MARK_META_TEST_v6",
                    "ports": [
                        "Ethernet0"
                    ],
                    "stage": "ingress",
                    "type": "UNDERLAY_SET_DSCPV6"
                }
            }
        }

rule.json

        [
            {
                "OVERLAY_MARK_META_TEST:RULE10": {
                    "priority" : "55",
                    "DSCP_ACTION" : "7",
                    "SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:1/128"
                },
                "OP": "SET"
            }
        ]



### General Test Flow
Each test case executes the following sets of actions in the given order:
1) Apply ACL configuration based on the test case.
2) Generate a single packet to match each of the configured rules.
3) Verify that the packet indeed hit the ACL rule and it resulted in outer header DSCP change after VxLAN encapsulation.

### Packet Structure

#### Sent packet
The packet sent to the DUT has the following format.
<pre>
###[ Ethernet ]###
  dst = [auto]
  src = [auto]
  type = 0x800
###[ IP/IPv6 ]###
    version = 4/6
    ttl/hlim = 121
    proto = udp
    tos/tc= configured by the test
    chksum = None
    src = 170.170.170.170 / 9999:AAAA:BBBB:CCCC:DDDD:EEEE:EEEE:7777
    dst = VNET route prefix
###[ UDP ]###
    sport = any
    dport = any
</pre>

#### Recieved packet
The packet recieved from the  has the following format.
<pre>
###[ Ethernet ]###
  dst = [auto]
  src = [auto]
  type = 0x800
###[ IP/IPv6 ]###
    version = 4/6
    ttl/hlim = 128
    proto = udp
    tos/tc= Set by ACL rule based on the configuration by the test.
    chksum = None
    src = DUT Loopback IPv4/IPv6
    dst = one ofthe 4 next hops configured by the test in the VNET route.
###[ UDP ]###
    sport = any
    dport = 4789
###[ Vxlan ]###
    vni = 10000
###[ payload ]###
    Original packet sent to the DUT.
    ###[ Ethernet  ]###
    ###[ IP/IPv6 ]###
    ###[ UDP ]###
</pre>

## Test Cases

### Test case \#1 - Basic verification test.

#### Test objective

Verify ACL table and rule creation/deletion logic. This test performs basic sanity check to see if ACL group and rule are created successfully.

#### Test steps

- Create ACL Table
- Create a Single ACL rule.
- Verify the ACL rule.
- Delete the ACL rule.
- Delete the ACL table.

### Test case \#2 - ACL rules with different DSCP values.

#### Test objective

This test creates multiple ACL rules with different DSCP values. The intention is to verify the ability of the ACL group to handle multiple DSCP value rewrites. This test would verify the basic functionality of the metadata manager along with the creation of multiple EGR_SET_DSCP rules. After traffic verification, these rules are deleted to verify proper cleanup. The test uses the following parameters to create different rules.

##### IPv4:
<pre>
           {'rule_id': '1', 'priority': '100', 'dscp_action': '10', 'match': '"SRC_IP":"170.170.170.1/32"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '20', 'match': '"SRC_IP":"170.170.170.2/32"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '30', 'match': '"SRC_IP":"170.170.170.3/32"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '40', 'match': '"SRC_IP":"170.170.170.4/32"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '50', 'match': '"SRC_IP":"170.170.170.5/32"'}
</pre>
##### IPv6:
<pre>
            {'rule_id': '1', 'priority': '100', 'dscp_action': '10', 'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:1/128"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '20', 'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:2/128"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '30', 'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:3/128"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '40', 'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:4/128"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '50', 'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:5/128"'}
</pre>

#### Test steps

- Create ACL Table
- Create ACL rule based on the above-mentioned parameters.
- Verify the ACL rule status exists by sending one packet for each of the rules created and the received packets have their outer DSCP value changed as expected.
- Delete the ACL rules.
- Delete the ACL table.


### Test case \#3 - ACL rules with different match criteria.

#### Test objective

This test creates multiple ACL rules with different DSCP values and different match attributes.
The intention is to verify the ability of the ACL group to handle multiple DSCP value rewrites while matching on different attributes.
After traffic verification, these rules are deleted to verify proper cleanup.
The test uses the following parameters to create different rules.

##### IPv4:
<pre>
            {'rule_id': '1', 'priority': '100', 'dscp_action': '10', 'match': '"SRC_IP":"170.170.170.9/32"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '20', 'match': '"L4_SRC_PORT":"1234"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '30', 'match': '"L4_DST_PORT":"80"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '40', 'match': '"DSCP":"10"'}
</pre>

##### IPv6:
<pre>
            {'rule_id': '1', 'priority': '100', 'dscp_action': '10', 'match': '"SRC_IPV6":"9999:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:0006/128"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '20', 'match': '"L4_SRC_PORT":"1234"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '30', 'match': '"L4_DST_PORT":"80"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '40', 'match': '"DSCP":"10"'}
</pre>

#### Test steps

- Create ACL Table
- Create ACL rules based on the above-mentioned parameters.
- Verify the ACL rule status exists by sending one packet for each of the rules created and ensuring the received packets have their outer DSCP value changed as expected.
- Delete the ACL rules.
- Delete the ACL table.

### Test case \#4 - ACL rules with different match criteria but same DSCP rewrite value

#### Test objective

This test creates multiple ACL rules with same DSCP rewrite values but with different match criteria
The intention is to verify the functionality of the shared EGR_SET_DSCP rule.
After traffic verification, these rules are deleted to verify proper cleanup.
The test uses the following parameters to create different rules.

##### IPv4:
<pre>
            {'rule_id': '1', 'priority': '100', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.1"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.2"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.3"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.4"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '24', 'match': '"SRC_IP":"10.0.0.5"'}
</pre>
##### IPv6:
<pre>
            {'rule_id': '1', 'priority': '100', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::1"'},
            {'rule_id': '2', 'priority': '200', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::2"'},
            {'rule_id': '3', 'priority': '300', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::3"'},
            {'rule_id': '4', 'priority': '400', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::4"'},
            {'rule_id': '5', 'priority': '500', 'dscp_action': '24', 'match': '"SRC_IPV6":"2001:db8::5"'}
</pre>

#### Test steps

- Create ACL Table
- Create ACL rules based on the above-mentioned parameters.
- Verify the ACL rule status exists by sending one packet for each of the rules created and ensuring the received packets have their outer DSCP value changed as expected.
- Delete the ACL rules.
- Delete the ACL table.

## TODO
### Other possible tests
- Metadata exhaustion with traffic test : Verfiy metadata exhaustion results in graceful ACL failure. Only applicable on Mlnx platofrm.
- UNDERLAY_SET_DSCP/V6 table creation failure test : Create multiple ACL tables with single rule until TCAM is exhaused, ensure graceful failure.
- Rule update test: Create a rule, modify it and test with traffic.

## Open Questions