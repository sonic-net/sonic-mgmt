- [Overview](#overview)
    - [Scope](#scope)
    - [Related **DUT** CLI commands](#related-dut-cli-commands)
- [Setup configuration](#setup-configuration)
    - [Scripts for generating configuration on SONIC](#scripts-for-generating-configuration-on-SONIC)
    - [Ansible scripts to setup and run test](#ansible-scripts-to-setup-and-run-test)
        - [everflow_testbed.yml](#everflow-testbed-yml)
    - [Setup of DUT switch](#Setup-of-DUT-switch)
        - [J2 templates](#j2-templates)
- [PTF Test](#ptf-test)
    - [Input files for PTF test](#input-files-for-ptf-test)
    - [Traffic validation in PTF](#traffic-validation-in-ptf)
- [Test cases](#test-cases)
- [TODO](#todo)
- [Open Questions](#open-questions)

##Overview
The purpose is to test functionality of Everflow on the SONIC switch DUT with and without LAGs configured, closely resembling production environment.
The test assumes all necessary configuration, including Everflow session and ACL rules, LAG configuration and BGP routes, are already pre-configured on the SONIC switch before test runs.

###Scope
The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is not to test specific SAI API, but functional testing of Everflow on SONIC system, making sure that traffic flows correctly, according to BGP routes advertised by BGP peers of SONIC switch, and the LAG configuration.

NOTE: Everflow+LAG test will be able to run **only** in the testbed specifically created for LAG.

###Related **DUT** CLI commands
Manual Everflow configuration can be done using swssconfig utility in swss container.

    swssconfig <json-file to apply>

##Test structure 
###Setup configuration
Everflow configuration should be created on the DUT before running the test. Configuration could be deployed using ansible sonic test playbook with the tag **everflow_tb**.

#### Scripts for generating configuration on SONIC

There will be three j2 template files for the Everflow test configuration: everflow_tb_test_session.j2, everflow_tb_test_acl_table.j2 and everflow_tb_test_acl_rue.j2. They will be used by Ansible playbook to generate json files and apply them on the switch.

#### Ansible scripts to setup and run test

##### everflow_testbed.yml

everflow_testbed.yml when run with tag "everflow_tb" will to the following:

1. Generate JSON files and apply them on the switch.
2. Run test.
3. Clean up dynamic configuration and temporary configuration on the DUT.

Everflow test consists of a number of subtests, and each of them will include the following steps:

1. Run lognanalyzer 'init' phase
2. Run Everflow Sub Test
3. Run loganalyzer 'analyze' phase

Everflow subtests will be implemented in the PTF (everflow_testbed_test.py). Every subtest will be implemented in a separate class.

#### Setup of DUT switch
Setup of SONIC DUT will be done by Ansible script. During setup Ansible will copy JSON file containing configuration for Everflow to the swss container on the DUT. swssconfig utility will be used to push configuration to the SONiC DB. Data will be consumed by orchagent.

JSON Sample:

everflow_session.json
```
[
    {
        "MIRROR_SESSION_TABLE:session_1": {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "gre_type": "0x6558",
            "dscp": "8",
            "ttl": "64",
            "queue": "0"
        },
        "OP": "SET"
    }
]
```

everfow_acl_table.json
```
[
    {
        "ACL_TABLE:acl_table_mirror": {
            "policy_desc" : "Everflow_ACL_table",
            "type" : "MIRROR",
            "ports" : "Ethernet0, Ethernet4, Ethernet8, Ethernet12, Ethernet16, Ethernet20, Ethernet24, Ethernet28, Ethernet32, Ethernet36, Ethernet40, Ethernet44, Ethernet48, Ethernet52, Ethernet56, Ethernet60, Ethernet64, Ethernet68, Ethernet72, Ethernet76, Ethernet80, Ethernet84, Ethernet88, Ethernet92, Ethernet96, Ethernet100, Ethernet104, Ethernet108, Ethernet112, Ethernet116, Ethernet120, Ethernet124, Ethernet128"
        },
        "OP": "SET"
    }
]
```
everflow_acl_rule_persistent.json
```
[
    {
        "ACL_RULE_TABLE:acl_table_mirror:Rule01": {
            "policy_desc" : "Mirror_packet_with_tcp_flag_fin",
            "priority" : "50",
            "tcp_flags" : "0x01/0xff",
            "mirror_action" : "session_1"
        },
        "OP": "SET"
    },
    {
        "ACL_RULE_TABLE:acl_table_mirror:Rule02": {
            "policy_desc" : "Mirror_packet_with_tcp_flag_syn_and_dscp",
            "priority" : "50",
            "tcp_flags" : "0x02/0xff",
			"dscp" : "1"
            "mirror_action" : "session_1"
        },
        "OP": "SET"
    },
    {
        "ACL_RULE_TABLE:acl_table_mirror:Rule03": {
            "policy_desc" : "Mirror_packet_with_tcp_flag_rst",
            "priority" : "50",
            "tcp_flags" : "0x04/0xff",
            "mirror_action" : "session_1"
        },
        "OP": "SET"
    },
    {
        "ACL_RULE_TABLE:acl_table_mirror:Rule04": {
            "policy_desc" : "Mirror_packet_with_specific_tcp_port",
            "priority" : "50",
			"ip_protocol" : "0x06",
            "l4_src_port" : "1101",
            "mirror_action" : "session_1"
        },
        "OP": "SET"
    },

]
```
everflow_acl_rule_dynamic.json
```
[
    {
        "ACL_RULE_TABLE:acl_table_mirror:RuleDynamic01": {
            "policy_desc" : "Mirror_packet_with_specific_src_ip",
            "priority" : "50",
            "src_ip" : "10.0.0.0/32",
            "mirror_action" : "session_1"
        },
        "OP": "SET"
    },
	{
        "ACL_RULE_TABLE:acl_table_mirror:RuleDynamic02": {
            "policy_desc" : "Mirror_packet_with_specific_dst_ip",
            "priority" : "50",
            "dst_ip" : "10.0.0.5/32",
            "mirror_action" : "session_1"
        },
        "OP": "SET"
    },
	{
        "ACL_RULE_TABLE:acl_table_mirror:RuleDynamic03": {
            "policy_desc" : "Mirror_packet_with_specific_src_and_dst_ip",
            "priority" : "50",
            "src_ip" : "10.0.0.0/32",
			"dst_ip" : "10.0.0.5/32",
            "mirror_action" : "session_1"
        },
        "OP": "SET"
    }
]
```
##PTF Test

### Input files for PTF test

PTF test will generate traffic between ports and make sure it mirrored according to the configured Everflow session and ACL rules. Depending on the testbed topology and the existing configuration (e.g. ECMP, LAGS, etc) packets may arrive to different ports. Therefore ports connection information will be generated from the minigraph and supplied to the PTF script.

### Traffic validation in PTF
Depending on the test PTF test will verify the packet arrived or dropped.

##Test cases

Each test case will be additionally validated by the loganalizer utility.

Each test case will add dynamic Everflow ACL rules at the beginning and remove them at the end.

Each test case will run traffic for persistent and dynamic Everflow ACL rules.

Each test case will analyze Everflow packet header and payload (if mirrored packet is equal to original).

### Test case \#1 - Resolved route

#### Test objective

Verify that session with resolved route has active state.

#### Test steps

- Create route that matches session destination IP with unresolved next hop.
- Resolve route next hop.
- Verify that session state in APP DB changed to active.
- Send packets that matches each Everflow ACL rule.
- Verify that packet mirrored to appropriate port.
- Analyze mirrored packet header.
- Verify that mirrored packet payload is equal to sent packet.
- Verify that counters value of each Everflow ACL rule is correct.

### Test case \#2 - Longer prefix route with resolved next hop

#### Test objective

Verify that session destination port and MAC address are changed after best match route insertion.

#### Test steps

- Create route that matches session destination IP with unresolved next hop.
- Resolve route next hop.
- Verify that session state in APP DB changed to active.
- Send packets that matches each Everflow ACL rule.
- Verify that packets mirrored to appropriate port.
- Analyze mirrored packet header.
- Verify that mirrored packet payload is equal to sent packet.
- Create best match route that matches session destination IP with unresolved next hop.
- Send packets that matches each Everflow ACL rule.
- Verify that packets are mirrored to the same port.
- Resolve best match route next hop (neighbor should be on different port).
- Verify that session state in APP DB is active.
- Send packets that matches each Everflow ACL rule.
- Verify that packets are mirrored and destination port changed accordingly.

### Test case \#3 - Remove longer prefix route.

#### Test objective

Verify that session destination port and MAC address are changed after best match route removal.

#### Test steps

- Create route that matches session destination IP with unresolved next hop.
- Resolve route next hop.
- Verify that session state in APP DB changed to active.
- Send packets that matches each Everflow ACL rule.
- Verify that packets mirrored to appropriate port.
- Analyze mirrored packet header.
- Verify that mirrored packet payload is equal to sent packet.
- Create best match route that matches session destination IP with unresolved next hop.
- Resolve best match route next hop (neighbor should be on different port).
- Send packets that matches each Everflow ACL rule.
- Verify that packets are mirrored and destination port changed accordingly.
- Remove best match route.
- Send packets that matches each Everflow ACL rule.
- Verify that packets are mirrored and destination port changed accordingly.

### Test case \#4 - Change neighbor MAC address.

#### Test objective

Verify that session destination MAC address is changed after neighbor MAC address update.

#### Test steps

- Create route that matches session destination IP with unresolved next hop.
- Resolve route next hop.
- Verify that session state in APP DB changed to active.
- Send packets that matches each Everflow ACL rule.
- Verify that packets mirrored to appropriate port.
- Analyze mirrored packet header.
- Verify that mirrored packet payload is equal to sent packet.
- Change neighbor MAC address.
- Send packets that matches each Everflow ACL rule.
- Verify that DST MAC address in mirrored packet header is changed accordingly.

### Test case \#5 - Resolved ECMP route.

#### Test objective

Verify that session with resolved ECMP route has active state.

#### Test steps

- Create ECMP route that matches session destination IP with two unresolved next hops.
- Resolve route next hops.
- Verify that session state in APP DB is changed to active.
- Send packets that matches each Everflow ACL rule.
- Verify that packets mirrored to appropriate port.
- Analyze mirrored packets header.
- Verify that mirrored packets payload is equal to sent packet.

### Test case \#6 - ECMP route change (add next hop).

#### Test objective

Verify that insertion of additional next hop to ECMP group doesn't affects session DST MAC and port.

#### Test steps

- Create ECMP route that matches session destination IP with two unresolved next hops.
- Resolve route next hops.
- Verify that session state in APP DB is changed to active.
- Send packets that matches each Everflow ACL rule.
- Verify that packets mirrored to appropriate port.
- Analyze mirrored packet header.
- Verify that mirrored packet payload is equal to sent packet.
- Add resolved next hop to ECMP route.
- Send packets that matches each Everflow rule.
- Verify that packets are mirrored to the same port.
- Verify that mirrored packets have the same DST MAC.

### Test case \#7 - ECMP route change (remove next hop used by session).

#### Test objective

Verify that removal of next hop that is not used by session doesn't cause DST port and MAC change.

#### Test steps

- Create ECMP route that matches session destination IP with two unresolved next hops.
- Resolve route next hops.
- Verify that session state in APP DB is changed to active.
- Send packets that matches each Everflow rule.
- Verify that packets mirrored to appropriate port.
- Analyze mirrored packet header.
- Verify that mirrored packets payload is equal to sent packets.
- Remove next hop that is not used by session.
- Send packets that matches each Everflow rule.
- Verify that packets are mirrored to the same port.
- Verify that mirrored packets have the same DST MAC.

### Test case \#8 - ECMP route change (remove next hop not used by session).

#### Test objective

Verify that after removal of next hop that was used by session from ECMP route session state is active.

#### Test steps

- Create ECMP route that matches session destination IP with two unresolved next hops.
- Resolve route next hops.
- Verify that session state in APP DB is changed to active.
- Send packets that matches each Everflow ACL rule.
- Verify that packets mirrored to appropriate port.
- Analyze mirrored packet header.
- Verify that mirrored packets payload is equal to sent packets.
- Remove next hop that is used by session.
- Send packets that matches each Everflow ACL rule.
- Verify that packets are mirrored and destination port changed accordingly.

### Other possible tests

## TODO
- Everflow+LAG test configuration and testcases (separate ansible tag)

## Open Questions