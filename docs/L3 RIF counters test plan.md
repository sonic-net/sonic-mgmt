# L3 RIF Counters Test Plan

## [DRAFT, UNDER DEVELOPMENT]
- [Overview](#overview)
    - [Scope](#scope)
    - [Related **DUT** CLI commands](#related-dut-cli-commands)
- [Setup configuration](#setup-configuration)
    - [Pytest scripts to setup and run test ](#Pytest-scripts-to-setup-and-run-test)
        - [test_l3_rif_counter.py](#test_l3_rif_counter.py)
    - [Setup of DUT switch](#Setup-of-DUT-switch)
        - [Json Sample](#json-sample)
- [PTF Test](#ptf-test)
- [Test cases](#test-cases)
- [TODO](#todo)
- [Open Questions](#open-questions)

## Overview
The purpose is to test functionality of L3 RIF counters on the SONIC switch based on router port and L3 vlan interface, including Ethernet port and LAG. The new instruction is issued in:

https://github.com/Azure/sonic-mgmt/blob/master/tests/README.md. 

Hence, the test is now considering to run under this new instruction.

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
Tests will be based on t1-lag testbed type. New test IP addresses will be configured on Ethernet, vlan interface and portchannel.

#### Pytest scripts to setup and run test

##### test_l3_rif_counter.py

test_l3_rif_counter.py with tag "l3rifcoun" will be done by the following:

./run_tests.sh -d <dut_name> -n <testbed_name> [-s ] -t t1-lag -u -c tests/test_l3rifcoun.py

#### Setup of DUT switch
Setup of SONIC DUT will be done inside the new pytest script:

https://github.com/Azure/sonic-mgmt/blob/master/tests/run_tests.sh

The setup will prepar DUT configuration for L3 RIF counters including the interface, portchannel. 

JSON Samples:

L3_router_interface

        [
            {
            "INTERFACE": {
                "Ethernet0|11.0.0.1/24": {},
                "Ethernet1|11.1.0.1/24": {}
                }
            }
        ]
        
L3_vlan_interface

        [
            {
             "VLAN": {
                 "Vlan1000": {
                  "vlanid": "1000"
             },
             "Vlan2000": {
                  "vlanid": "2000"
             }
            },
                "VLAN_INTERFACE": {
                  "Vlan1000|12.0.0.1/24": {},
                  "Vlan2000|12.1.0.1/24": {}
                 },
               "VLAN_MEMBER": {
                  "Vlan1000|Ethernet2": {
                  "tagging_mode": "untagged"
                 },
                 "Vlan2000|Ethernet3": {
                  "tagging_mode": "untagged"
                 }
            }           
        ]
        
L3_portchannel

    [
      {
        "PORTCHANNEL": {
        "PortChannel10": {
            "admin_status": "up",
            "members": [
                "Ethernet4",
                "Ethernet5"
            ],
            "min_links": "1",
            "mtu": "9100"
        },
        "PortChannel20": {
            "admin_status": "up",
            "members": [
                "Ethernet6",
                "Ethernet7"
            ],
            "min_links": "1",
            "mtu": "9100"
        }
        },
          "PORTCHANNEL_INTERFACE": {
             "PortChannel10|13.0.0.2/24": {},
             "PortChannel10|13.1.0.2/24": {}
              },
              
         "PORTCHANNEL_MEMBER": {
             "PortChannel10|Ethernet4": {},
             "PortChannel10|Ethernet5": {},
              "PortChannel20|Ethernet6": {},
             "PortChannel20|Ethernet7": {}
         }
     }
    ]
    
L3_vlan_portchannel

    [
      {
        "VLAN": {
        "Vlan3000": {
            "vlanid": "3000"
             },
        "Vlan4000": {
            "vlanid": "4000"
             }
         },
         "VLAN_INTERFACE": {
              "Vlan3000|14.0.0.2/24": {},
              "Vlan4000|14.1.0.2/24": {}
          },
         "VLAN_MEMBER": {
              "Vlan3000|PortChannel30": {
              "tagging_mode": "untagged"
              },
              "Vlan4000|PortChannel40": {
              "tagging_mode": "untagged"
              }
        },
        "PORTCHANNEL": {
        "PortChannel30": {
            "admin_status": "up",
            "members": [
                "Ethernet8",
                "Ethernet9"
            ],
            "min_links": "1",
            "mtu": "9100"
          },
          "PortChannel40": {
            "admin_status": "up",
            "members": [
                "Ethernet10",
                "Ethernet11"
            ],
            "min_links": "1",
            "mtu": "9100"
          }
        },
         "PORTCHANNEL_MEMBER": {
             "PortChannel30|Ethernet8": {},
             "PortChannel30|Ethernet9": {},
             "PortChannel40|Ethernet10": {},
             "PortChannel40|Ethernet11": {}
         }
     }
    ]

## PTF Test
## Test cases

Each test case will be additionally validated by the loganalizer. (the loganalizer is considering to add into the test_l3rifcoun.py)

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
            ···
    <pre>

- Verify that packet successfully received by SONiC DUT.
- Verify the L3 RIF counters. The RX packets counter in *show interface counters rif <interface_name>* is the same with the RX_OK counters in *show interface counters rif*.
- Clear the counter, and verify the clear action take effect.
- Verify the log.
- Check interface status.

### Test case \#2 - TX counter test

#### Test objective

Verify the correctness of TX packets counter and TX bytes counter in L3 RIF counters. Verify the validity of *sonic-clear rifcounters <interface_name>*.

#### Test steps

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
            ···
   <pre>

- Verify that packet successfully sent by SONiC DUT.
- Verify the L3 RIF counters.
- Clear the counter, and verify the clear action take effect. The TX packets counter in *show interface counters rif <interface_name>* is the same with the TX_OK counters in *show interface counters rif*.
- Verify the log.
- Check interface status.

### Test case \#3 - Rx error packets counter test

#### Test objective

Verify the correctness of Rx error packets counter and Rx error bytes counter in L3 RIF counters. Verify the validity of *sonic-clear rifcounters <interface_name>*.

#### Test steps

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
            ···
   <pre> 
- Verify that packet successfully sent by SONiC DUT.
- Verify the L3 RIF counters. The RX error packets counter in *show interface counters rif <interface_name>* is the same with the RX_ERR counters in *show interface counters rif*. 
- Clear the counter, and verify the clear action take effect.
- Set default configuration.
- Verify the log.
- Check interface status.

### Other possible tests
- Ipv6 packets counters
- *show interfaces counters rif -p [interface_name]* :
The period option gives the ability to see the counters and RX/TX BPS and PPS.

## TODO

## Open Questions
