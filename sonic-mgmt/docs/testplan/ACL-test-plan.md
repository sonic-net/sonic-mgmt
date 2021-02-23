## [DRAFT, UNDER DEVELOPMENT]


- [Overview](#overview)
    - [Scope](#scope)
    - [Related **DUT** CLI commands](#related-dut-cli-commands)
- [Setup configuration](#setup-configuration)
    - [Scripts for generating ACL configuration on SONIC](#Scripts-for-generating-ACL-configuration-on-SONIC)
    - [Ansible scripts to setup and run ACL test](#Ansible scripts to setup and run ACL test)
        - [acl_testbed.yml](#acl-testbed-yml)
    - [Setup of DUT switch](#Setup-of-DUT-switch)
        - [J2 templates](#j2-templates)
- [PTF Test](#ptf-test)
    - [Input files for PTF test](#input-files-for-ptf-test)
    - [Traffic validation in PTF](#traffic-validation-in-ptf)
- [Test cases](#test-cases)
- [TODO](#todo)
- [Open Questions](#open-questions)

## Overview
The purpose is to test functionality of ACL rules on the SONIC switch DUT with and without LAGs configured, closely resembling production environment.
The test assumes all necessary configuration, including ACL and LAG configuration, BGP routes, are already pre-configured on the SONIC switch before test runs.

### Scope
The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is not to test specific SAI API, but functional testing of ACL on SONIC system, making sure that traffic flows correctly, according to BGP routes advertised by BGP peers of SONIC switch, and the LAG configuration.

NOTE: ACL+LAG test will be able to run **only** in the testbed specifically created for LAG.

### Related **DUT** CLI commands
Manual ACL configuration can be done using swssconfig utility in swss container.

    swssconfig <json-file to apply>

## Test structure 
### Setup configuration
ACL configuration should be created on the DUT before running the test. Configuration could be deployed using ansible sonic test playbook with the tag acltb_configure.

#### Scripts for generating ACL configuration on SONIC

There will be two j2 template files for the ACL test configuration: acltb_test_table.j2 and acltb_test_rules.j2. They will be used by Ansible playbook to generate json files and apply them on the switch.

#### Ansible scripts to setup and run ACL test

##### acl_testbed.yml

acl_testbed.yml when run with ***different tags*** will
 
Tag ***acltb_configure*** will generate acl json files for the ACL test out of the corresponding j2 files and apply them on the switch.  
Tag ***acltb_test*** will run ACL test (or ACL+LAG) test.  
Tag ***acltb_cleanup*** will clear the test ACL configuration from the switch.  

ACL test consists of a number of subtests, and each of them will include the following steps:

1. Run lognanalyzer 'init' phase
2. Run ACL Sub Test
3. Run loganalyzer 'analyze' phase

ACL subtests will be implemented in the PTF (acl_testbed_test.py). Every subtest wibb be implemented in a separate class.

#### Setup of DUT switch
Setup of SONIC DUT will be done by Ansible script. During setup Ansible will copy json file containing configuration for ACL to the swss container on the DUT. swssconfig utility will be used to push configuration to the SONiC DB. Data will be consumed by orchagent.

JSON Sample:

table.json

        [
            {
                "ACL_TABLE:Drop_IP": {
                    "policy_desc" : "Drop_IP_Traffic",
                    "type" : "L3",
                    "ports" : "Ethernet0"
                },
            "OP": "SET"
            }
        ]

rule.json

        [
            {
                "ACL_RULE_TABLE:Drop_IP:TheDrop": {
                    "priority" : "55",
                    "ETHER_TYPE" : "0x0800",
                    "PACKET_ACTION" : "DROP"
                },
                "OP": "SET"
            }
        ]

**NOTE**
Tables and rules configuration will reside in two different jsons and table configuration will be applied before rules to ensure correct objects creation order in SAI.

##### J2 templates
acltb_test_table.j2 will configure single table bound to all switch ports.

        [
            {
                "ACL_TABLE:ACL_Testbed_Test_Table": {
                    "policy_desc" : "Thistable_contains_rules_needed_for_the_testbed_regression_tests",
                    "type" : "L3",
                    "ports" : "{% list_of_ingress_ports %}",
                },
                "OP": "SET"
            }
        ]

acltb_test_rules.j2 will contain ACL rules needed for the test

ACL Rules:

**RulesN..N+1000-<existing>:** Any rules, action: forward (placeholder)  
**Rule#1:** match src ip 10.0.0.2, action: drop  
**Rule#2:** match dst ip TBD, action: drop  
**Rule#3:** match l4_src_port 0x1235, action: drop  
**Rule#4:** match l4_dst_port 0x1235, action: drop  
**Rule#5:** match ether type 0x1234, action: forward  
**Rule#6:** match ip protocol 0x7E, action: drop  
**Rule#7:** match tcp flags 0xFF/RST, action: drop  
**Rule#8:** match ip type TBD, action: drop  
**Rules#9.1-9.8:** match source ports range [[0x1240..0x1249], [0x1250..0x1259]...], action: drop (8 rules with different port ranges)  
**Rule#10.1-10.8:** match destination ports range [[0x1240..0x1249], [0x1250..0x1259]...], action: drop (8 rules with different port ranges)  
**Rules#11-12:** check priority: match some src ip 10.0.0.3, action: drop + match src ip 10.0.0.3 (higher prio), action: forward  

/if needed additionally match src ip/

## PTF Test

### Input files for PTF test

PTF test will generate traffic between ports and make sure it passes according to the configured ACL rules. Depending on the testbed topology and the existing configuration (e.g. ECMP, LAGS, etc) packets may arrive to different ports. Therefore ports connection information will be generated from the minigraph and supplied to the PTF script.

### Traffic validation in PTF
Depending on the test PTF test will verify the packet arrived or dropped.

## Test cases

Each test case will be additionally validated by the loganalizer and counters reading utility.

### Generic packet
Packet with the values below should not trigger any "drop" rule.
<pre>
###[ Ethernet ]###
  dst = [auto]
  src = [auto]
  type = 0x800
###[ IP ]###
    version = 4  
    ttl = <auto>  
    proto = tcp  
    chksum = None  
    src = 10.0.0.1  
    dst = [get_from_route_info]
###[ TCP ]###  
    sport = 4660 (0x1234)  
    dport = http (80)  
    flags = S  
</pre>

### Test case \#0 - Resources consuming test

#### Test objective

Verify whether ACL engine resources are being freed on rule/range/counter/table delete.

#### Test steps

- Clear ACL configuration.
- Reapply ACL configuration.
- Verify there are no errors in the log

### Test case \#1 - Verify source IP match

#### Test objective

Verify match source IP address works.

#### Packet to trigger the rule #1
<pre>
...
###[ IP ]###
    version = 4  
    ttl = <auto>  
    proto = tcp  
    chksum = None  
    <b>src = 10.0.0.2</b>
    dst = [get_from_route_info]
...
</pre>

#### Test steps

- PTF host will send packet specifying particular source IP address in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #1. PTF docker should not receive this packet.
- Counter for the rule #1 should increment


### Test case \#2 - Verify destination IP match

#### Test objective

Verify match destination IP address works.

#### Packet to trigger the rule #2
<pre>
...
###[ IP ]###
    version = 4  
    ttl = <auto>  
    proto = tcp  
    chksum = None  
    src = 10.0.0.1
    <b>dst = [get_from_route_info]</b>
...
</pre>

#### Test steps

- PTF host will send packet specifying particular destination IP address in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #2. PTF docker should not receive this packet.
- Counter for the rule #2 should increment


### Test case \#3 - Verify L4 source port match

#### Test objective

Verify match L4 source port works.

#### Packet to trigger the rule #3
<pre>
...
###[ TCP ]###  
    <b>sport = 4661 (0x1235)</b>
    dport = 80
    flags = S
...
</pre>

#### Test steps

- PTF host will send packet with the specific L4 source port in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #3. PTF docker should not receive this packet.
- Counter for the rule #3 should increment

### Test case \#4 - Verify L4 destination port match

#### Test objective

Verify match L4 source port works.

#### Packet to trigger the rule #4
<pre>
...
###[ TCP ]###  
    sport = 4660 (0x1234)
    <b>dport = 4661 (0x1235)</b>
    flags = S
...
</pre>

#### Test steps

- PTF host will send packet with the specific L4 destination port in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #4. PTF docker should not receive this packet.
- Counter for the rule #4 should increment

### Test case \#5 - Verify ether type match

#### Test objective

Verify match packet ether type works.

#### Packet to trigger the rule #5
<pre>
###[ Ethernet ]###
  dst = [auto]
  src = [auto]
  <b>type = 0x1234</b>
...
</pre>

#### Test steps

- PTF host will send packet with the specific ether type in the packet.
- When packet reaches SONIC DUT, it should be dropped because non-IP ethertype. But will be forwarded by the rule #5. PTF docker should receive this packet.
- Counter for the rule #5 should increment

***NOTE*** Ether type used in this test should be "exotic" enough to exclude possible interference with the other tests traffic.

### Test case \#6 - Verify ip protocol match

#### Test objective

Verify match ip protocol works.

#### Packet to trigger the rule #6
<pre>
...
###[ IP ]###
    version = 4  
    ttl = <auto>  
    <b>proto = 0x7E</b>
    chksum = None  
    src = 10.0.0.1  
    dst = [get_from_route_info]
</pre>
...
#### Test steps

- PTF host will send packet with the specific ip protocol field in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #6. PTF docker should not receive this packet.
- Counter for the rule #6 should increment

***NOTE*** IP protocol used in this test should be "exotic" enough to exclude possible interference with the other tests traffic. For example  0x7E (Combat Radio Transport Protocol)

### Test case \#7 - Verify TCP flags match

#### Test objective

Verify match TCP flags works.

#### Packet to trigger the rule #7
<pre>
...
###[ TCP ]###  
    sport = 4660 (0x1234)
    dport = 80
    <b>flags = RS</b>
...
</pre>
#### Test steps

- PTF host will send TCP packet with the specific flags in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #7. PTF docker should not receive this packet.
- Counter for the rule #7 should increment.

### Test case \#8 - Verify ip type match

#### Test objective

Verify match ip protocol works.

#### Test steps

- PTF host will send packet with the specific ip protocol field in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #8. PTF docker should not receive this packet.
- Counter for the rule #8 should increment

***TODO*** Think about IP protocol to use for the test. Maybe add another match criteria (source ip?)

### Test case \#9 - Verify source port range match

#### Test objective

Verify match source port range works.

#### Packet to trigger the rule #9
<pre>
...
###[ TCP ]###  
    <b>sport = 0x1236..0x1240</b>
    dport = 80
    flags = S
...
</pre>
#### Test steps

- PTF host will send TCP packet with the specific source port in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #9. PTF docker should not receive this packet.
- Counter for the rule #9 should increment

### Test case \#10 - Verify destination port range match

#### Test objective

Verify match destination port range works.

#### Packet to trigger the rule #9
<pre>
...
###[ TCP ]###  
    sport = 0x1234
    <b>dport = 0x1236..0x1240</b>
    flags = S
...
</pre>
#### Test steps

- PTF host will send TCP packet with the specific destination port in the packet.
- When packet reaches SONIC DUT, it should be dropped by the rule #10. PTF docker should not receive this packet.
- Counter for the rule #10 should increment

### Test case \#11 - Verify rules priority

#### Test objective

Verify rules priority works.

#### Test steps

- PTF host will send TCP packet with the specific source ip in the packet.
- When packet reaches SONIC DUT, it will not be dropped by the rule #11 because rule #12 with the same matching criteria allows packet to pass.
- PTF docker verefies packet arrived.
- Counter for the rule #12 should increment

### Test case \#12 - False rule triggering check

#### Test objective

Verify rules are not triggered by mistake.  
This test should be executed the last.

#### Test steps

- Send several "Generic packets"
- Verify all rules counters value is equal to number of packets used for each rule in all tests.

### Other possible tests
- match combinations

## TODO
- ACL+LAG test configuration and testcases (separate ansible tag)

## Open Questions
