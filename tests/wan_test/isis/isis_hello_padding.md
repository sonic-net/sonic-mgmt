# ISIS hello padding:
## Test sample topo:

- DUT(system ID: 0100.3015.1091)-----PO1----Device1(SONiC)
- the following action is on DUT, MTU config is 1500 on interface
```
"PORTCHANNEL":
{
    "PortChannel0001": {
        "admin_status": "up",
        "members": [
            "Ethernet0",
            "Ethernet1",
            "Ethernet4",
            "Ethernet5",
            "Ethernet6",
            "Ethernet7",
            "Ethernet8",
            "Ethernet9",
            "Ethernet12",
            "Ethernet13",
            "Ethernet14",
            "Ethernet15",
            "Ethernet16",
            "Ethernet17",
            "Ethernet18",
            "Ethernet19",
            "Ethernet20",
            "Ethernet21",
            "Ethernet22",
            "Ethernet23"
        ],
        "mtu": "1500"
    }
}
```




## Test steps :
* Step1: not config hello padding, by default hello padding is enabled.
```
    "ISIS_INTERFACE": {
        "PortChannel0001": {
            "interface_id": "PortChannel0001"
        }
}
```

* Step 2: Shutdown interface po1: 

> sudo config interface shutdown PortChannel0001

* Step3: start capture on Po1:
> sudo tcpdump -i PortChannel0001 -s 0 -c 500 -w sonic_isis_po1_bydefault.pcap

 * Step4: enable interface:
> sudo config interface startup PortChannel001

* Step5: Check isis adj is up via PO1
```
JUNYW@owr01:~$ show isis neighbors 

IS-IS isis
==========
IS-IS interface database:

  INTERFACE         STATE        THREE WAY     ADJACENCY      NEIGHBOR        NEIGHBOR       HOLD      RESTART  BFD
                                 STATE         TYPE           SYSTEM ID       HOSTNAME       TIMER     CAPABLE  STATUS
  ---------         -----        ---------     ---------      ---------       --------       -----     -------  ------
  PortChannel0001   up           up            level-2        0100.3015.1092  DUT    7         true     none
  PortChannel0120   up           up            level-2        1000.0315.1040  rwa01.str01    18        true     none

JUNYW@owr01:~$ 
```

* Step6: Check packets capture file sonic_isis_po1_bydefault.pcap
All ISIS hello packets from DUT with system id  0100.3015.1092 is 1514 and there are padding in the hello packets

  ![](./images/isis_1.png)  
  ![](./images/isis_2.png)  

* Step7: config ISIS hello padding disable
  
  
```
      "ISIS_INTERFACE": {
        "PortChannel0001": {
            "circuit_type": "POINT_TO_POINT",
            "hello_padding": "DISABLE",
            "interface_id": "PortChannel0001"
        },
        "PortChannel0120": {
            "circuit_type": "POINT_TO_POINT",
            "hello_padding": "DISABLE",
            "interface_id": "PortChannel0120"
        },
}
```

* Step 8: Shutdown interface with ISIS enable on Sonic:
  
    > sudo config interface shutdown PortChannel0001

* Step9: start packets capture
  
    > sudo tcpdump -i PortChannel0001 -s 0 -c 500 -w sonic_isis_po1_disable.pcap

* Step10: enable interface
   > sudo config interface startup PortChannel0001 

* Step11: Check isis adj is up via PO1
  
```
  IS-IS isis
==========
IS-IS interface database:

  INTERFACE         STATE        THREE WAY     ADJACENCY      NEIGHBOR        NEIGHBOR       HOLD      RESTART  BFD
                                 STATE         TYPE           SYSTEM ID       HOSTNAME       TIMER     CAPABLE  STATUS
  ---------         -----        ---------     ---------      ---------       --------       -----     -------  ------
  PortChannel0001   up           up            level-2        0100.3015.1092  DUT    7         true     none
  PortChannel0120   up           up            level-2        1000.0315.1040  rwa01.str01    18        true     none
```

* Step12: Check packets capture file sonic_isis_po1_disable.pcap, The first or the first and second ISIS hello packets from DUT with system id  0100.3015.1092 is 1514 length is 1514 and with padding in hello packets.
  After that, we can check all the hello packets from the third from  0100.3015.1092, the length is length than 1514 and no padding in the hello packets.

  ![](./images/isis_3.png)  
  ![](./images/isis_4.png)  

* Step 13, check ISIS session up. Start packets capture again, no hello padding in the hello packets
