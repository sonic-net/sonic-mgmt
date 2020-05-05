# L3 RIF Counters Test Plan

## [DRAFT, UNDER DEVELOPMENT]
- [Overview](#overview)
    - [Scope](#scope)
    - [Related **DUT** CLI commands](#related-dut-cli-commands)
- [Setup configuration](#setup-configuration)
    - [Ansible scripts to setup and run test ](#Ansible-scripts-to-setup-and-run-test)
        - [l3_rif_counter.yml](#l3_rif_counter.yml)
    - [Setup of DUT switch](#Setup-of-DUT-switch)
- [PTF Test](#ptf-test)
- [Test cases](#test-cases)
- [TODO](#todo)
- [Open Questions](#open-questions)

## Overview
The purpose is to test functionality of L3 RIF counters on the SONIC switch based on router port and L3 vlan interface, including Ethernet port and LAG.

### Scope
The test is targeting a running SONIC system with L3 interface configuration.
The purpose of the test is to test L3 RIF counters on SONIC system, making sure that the counters are correct.

NOTE: L3 RIF counters + LAG test will be able to run **only** in the testbed specifically created for LAG.

### Related **DUT** CLI commands
show interface counters rif [OPTIONS] <interface_name>

show interface counters rif

sonic-clear rifcounters <interface_name>

## Test structure 
### Setup configuration
Tests will be based on t0 testbed type. The IP address of every Ethernet on the DUT will be flushed to make all Ethernet ports act as L2 ports. New test IP addresses will be configured on Ethernet, vlan interface and portchannel.

#### Ansible scripts to setup and run test

##### l3_rif_counter.yml

l3_rif_counter.yml when run with tag "l3_rif_counter" will do the following:

1. Run lognanalyzer 'init' phase
2. Run L3 RIF counter Sub Test
3. Run loganalyzer 'analyze' phase


#### Setup of DUT switch
Setup of SONIC DUT will be done by Ansible scripts. During setup Ansible will push json file containing configuration for L3 interface.

JSON Sample:

L3_router_interface.json

        [
            {
            "INTERFACE": {
                "Ethernet0|11.0.0.1/24": {},
                "Ethernet1|11.1.0.1/24": {},
                }
            }
        ]
        
L3_vlan_interface.json

        [
            {
             "VLAN": {
                 "Vlan1000": {
                    "dhcp_servers": [
                        "192.0.0.1",
                        "192.0.0.2",
                        "192.0.0.3",
                        "192.0.0.4"
                    ],
            "vlanid": "1000"
             }
            },
                "VLAN_INTERFACE": {
                  "Vlan1000|12.0.0.1/24": {}
                 },
               "VLAN_MEMBER": {
                  "Vlan1000|Ethernet2": {
                  "tagging_mode": "untagged"
                 },
               "Vlan1000|Ethernet3": {
                 "tagging_mode": "untagged"
                }
            }           
        ]
        
L3_portchannel.json

    [
      {
        "PORTCHANNEL": {
        "PortChannel0001": {
            "admin_status": "up",
            "members": [
                "Ethernet4",
                "Ethernet5"
            ],
            "min_links": "1",
            "mtu": "9100"
        }
        },
          "PORTCHANNEL_INTERFACE": {
             "PortChannel0001": {},
             "PortChannel0001|12.1.0.2/24": {},
              },
         "PORTCHANNEL_MEMBER": {
             "PortChannel0001|Ethernet4": {},
             "PortChannel0001|Ethernet5": {}
         }
     }
    ]
    
L3_vlan_portchannel.json

    [
      {
        "VLAN": {
        "Vlan1002": {
            "dhcp_servers": [
                "192.0.0.1",
                "192.0.0.2",
                "192.0.0.3",
                "192.0.0.4"
            ],
            "vlanid": "1002"
             }
         },
         "VLAN_INTERFACE": {
              "Vlan1002": {},
              "Vlan1002|12.2.0.1/21": {}
          },
         "VLAN_MEMBER": {
              "Vlan1002|PortChannel0002": {
              "tagging_mode": "untagged"
        },
        "PORTCHANNEL": {
        "PortChannel0002": {
            "admin_status": "up",
            "members": [
                "Ethernet6",
                "Ethernet7"
            ],
            "min_links": "1",
            "mtu": "9100"
          }
        },
         "PORTCHANNEL_MEMBER": {
             "PortChannel0001|Ethernet6": {},
             "PortChannel0001|Ethernet7": {}
         }
     }
    ]

## PTF Test
## Test cases

Each test case will be additionally validated by the loganalizer and counters reading utility.

### Test case \#1 - RX counter test
#### Test objective

Verify the correctness of RX packets counter and RX bytes counter in L3 RIF counters. Verify the validity of *sonic-clear rifcounters <interface_name>*.

#### Test steps

- Apply the L3 interface configuration.
- Clear the L3 RIF counter.
- PTF host sends a specific amount of packets to SONiC DUT.
 
    <pre>   
            ###[ Ethernet ]###
            dst = [auto]
            src = [auto]
            type = 0x800
            ###[ IP ]###
            version = 4  
            ttl =   
            proto = tcp  
            chksum = None  
            src = 11.0.0.2
            dst = [get_from_route_info]
            ，，，
    <pre>

- Verify that packet successfully received by SONiC DUT.
- Verify the log and the L3 RIF counters. The RX packets counter in *show interface counters rif <interface_name>* is the same with the RX_OK counters in *show interface counters rif*.
- Clear the counter, and verify the clear action take effect.
- Set default configuration.

### Test case \#2 - TX counter test

#### Test objective

Verify the correctness of TX packets counter and TX bytes counter in L3 RIF counters. Verify the validity of *sonic-clear rifcounters <interface_name>*.

#### Test steps

- Apply the L3 interface configuration.
- Clear the counter.
- SONiC DUT sends a specific amount of packets to PTF host.
    <pre>        
            ###[ Ethernet ]###
            dst = [auto]
            src = [auto]
            type = 0x800
            ###[ IP ]###
            version = 4  
            ttl =   
            proto = tcp  
            chksum = None  
            src = 11.0.0.2
            dst = [get_from_route_info]
            ，，，
   <pre>

- Verify that packet successfully sent by SONiC DUT.
- Verify the log and the L3 RIF counters.
- Clear the counter, and verify the clear action take effect. The TX packets counter in *show interface counters rif <interface_name>* is the same with the TX_OK counters in *show interface counters rif*.
- Set default configuration.

### Test case \#3 - Rx error packets counter test

#### Test objective

Verify the correctness of Rx error packets counter and Rx error bytes counter in L3 RIF counters. Verify the validity of *sonic-clear rifcounters <interface_name>*.

#### Test steps

- Apply the L3 interface configuration.
- Clear the counter.
- PTF host sends a specific amount of error packets to SONiC DUT.
      <pre>        
            ###[ Ethernet ]###
            dst = [auto]
            src = [auto]
            vlan tag = [not allowed vlan id]
            type = 0x800
            ###[ IP ]###
            version = 4  
            ttl =   
            proto = tcp  
            chksum = None  
            src = 11.0.0.2
            dst = [get_from_route_info]
            ，，，
   <pre> 
- Verify that packet successfully sent by SONiC DUT.
- Verify the log and the L3 RIF counters. The RX error packets counter in *show interface counters rif <interface_name>* is the same with the RX_ERR counters in *show interface counters rif*. 
- Clear the counter, and verify the clear action take effect.
- Set default configuration.

### Other possible tests
- Ipv6 packets counters
- *show interfaces counters rif -p [interface_name]* :
The period option gives the ability to see the counters and RX/TX BPS and PPS.

## TODO

## Open Questions