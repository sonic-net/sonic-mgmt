# Routing protocols - ISIS authentication:

## Test sample topo:

- DUT: OWR01.STR10 
- Topo1: OWR01.STR10-----OWR01.STR01
- Topo2: OWR01.STR10-----RWA04.STR01(other vendor, this is arista)

## Test steps :
* Step1: Config key same on both devices, ISIS session can be up and ISIS route can be learned on owr01.str01 and rwa04.str01, e.g., loopback address of rwa04.str01: 10.3.159.63/32 2a01:111:e210:b::151:63/128 and loopback address of owr01.str01: 10.30.151.91/32, 2a01:111:e210:b::91/128
    ```
    {
        "ISIS_ROUTER": {
            "isis": {
                "primary_authentication_key": "m1cr0s0ft",
                "primary_authentication_type": "hmac-md5"
            }
        }
    }
    JUNYW@owr01:~$ show isis neighbors 

    IS-IS isis
    ==========
    IS-IS interface database:

    INTERFACE         STATE        THREE WAY     ADJACENCY      NEIGHBOR        NEIGHBOR       HOLD      RESTART  BFD
                                    STATE         TYPE           SYSTEM ID       HOSTNAME       TIMER     CAPABLE  STATUS
    ---------         -----        ---------     ---------      ---------       --------       -----     -------  ------
    PortChannel0001   up           up            level-2        0100.3015.1091  owr01.str01    8         true     none
    PortChannel0120   up           up            level-2        0100.0315.9063  rwa04.str01    25        true     none

    JUNYW@owr01:~$ 

    JUNYW@owr01:~$ show ip route 10.3.159.63/32

    Destination/Mask 10.3.159.63/32
    ===============================   
    Protocol                          isis
    Next Hop                          172.20.52.1
    Next hop label                    3
    Interface name                    PortChannel0120
    Metric                            510
    Admin tag                         1000
    Route type                        remote
    Age                               152878
    Connected                         false
    Admin distance                    116
    Path type                         isis-level2-internal
    Protection                        none
    Loose next hop                    false
    Active                            true
    LFA                               none

    JUNYW@owr01:~$ show ipv6 route 2a01:111:e210:b::151:63/128

    Destination/Mask 2a01:111:e210:b::151:63/128
    ============================================
    Protocol                          isis
    Next Hop                          fe80::febd:67ff:fe11:b128
    Next hop label                    3
    Interface name                    PortChannel0120
    Metric                            510
    Admin tag                         1000
    Route type                        remote
    Age                               152949
    Connected                         false
    Admin distance                    116
    Path type                         isis-level2-internal
    Protection                        none
    Loose next hop                    false
    Active                            true
    LFA                               none

    JUNYW@owr01:~$ 

    rwa04.str01#show ip route 10.30.151.91/32

    VRF: default
    Codes: C - connected, S - static, K - kernel, 
        O - OSPF, IA - OSPF inter area, E1 - OSPF external type 1,
        E2 - OSPF external type 2, N1 - OSPF NSSA external type 1,
        N2 - OSPF NSSA external type2, B - Other BGP Routes,
        B I - iBGP, B E - eBGP, R - RIP, I L1 - IS-IS level 1,
        I L2 - IS-IS level 2, O3 - OSPFv3, A B - BGP Aggregate,
        A O - OSPF Summary, NG - Nexthop Group Static Route,
        V - VXLAN Control Service, M - Martian,
        DH - DHCP client installed default route,
        DP - Dynamic Policy Route, L - VRF Leaked,
        G  - gRIBI, RC - Route Cache Route

    I L2     10.30.151.91/32 [115/1000] via 172.20.52.0, Port-Channel120

    rwa04.str01#show ipv6 rout 2a01:111:e210:b::91/128

    VRF: default
    Routing entry for 2a01:111:e210:b::91/128
    Codes: C - connected, S - static, K - kernel, O3 - OSPFv3,
        B - Other BGP Routes, A B - BGP Aggregate, R - RIP,
        I L1 - IS-IS level 1, I L2 - IS-IS level 2, DH - DHCP,
        NG - Nexthop Group Static Route, M - Martian,
        DP - Dynamic Policy Route, L - VRF Leaked,
        RC - Route Cache Route

    I L2     2a01:111:e210:b::91/128 [115/1000]
            via fe80::569f:c6ff:fec8:42d8, Port-Channel120

    rwa04.str01#


    ```
* Step 2: config different ISIS key, ISIS session are down with other ISIS neighbors

    ```
    {
        "ISIS_ROUTER": {
            "isis": {
                "primary_authentication_key": "test",
                "primary_authentication_type": "hmac-md5"
            }
        }
    }
    sudo sonic-cfggen -j add_isis_auth_md5.json -w

    JUNYW@owr01:~$ show isis neighbors 

    IS-IS isis
    ==========
    IS-IS interface database:

    INTERFACE         STATE        THREE WAY     ADJACENCY      NEIGHBOR        NEIGHBOR       HOLD      RESTART  BFD
                                    STATE         TYPE           SYSTEM ID       HOSTNAME       TIMER     CAPABLE  STATUS
    ---------         -----        ---------     ---------      ---------       --------       -----     -------  ------

    JUNYW@owr01:~$ 
    JUNYW@owr01:~$ 

    ```
Following logs are popped, log may change, create this feature: 
Feature 102689: [ISIS Auth] when ISIS auth failed, which ISIS neighor that auth failed need to display - Boards (azure.com)
Mar 11 06:22:55.920785 owr01 WARNING bgp#nbased[22]: EXCEPTION 0x3f02-14 (0000): DC-ISIS SDC discarded an inbound PDU which failed authentication.

* Step 3, config the same key as neighbor back and check if ISIS neighbor and routes can be learned again
  
```
  {
    "ISIS_ROUTER": {
         "isis": {
            "primary_authentication_key": "m1cr0s0ft",
            "primary_authentication_type": "hmac-md5"
         }
     }
}

JUNYW@owr01:~$ show isis neighbors 

IS-IS isis
==========
IS-IS interface database:

  INTERFACE         STATE        THREE WAY     ADJACENCY      NEIGHBOR        NEIGHBOR       HOLD      RESTART  BFD
                                 STATE         TYPE           SYSTEM ID       HOSTNAME       TIMER     CAPABLE  STATUS
  ---------         -----        ---------     ---------      ---------       --------       -----     -------  ------
  PortChannel0001   up           up            level-2        0100.3015.1091  owr01.str01    8         true     none
  PortChannel0120   up           up            level-2        0100.0315.9063  rwa04.str01    25        true     none

JUNYW@owr01:~$ 

JUNYW@owr01:~$ show ip route 10.3.159.63/32

Destination/Mask 10.3.159.63/32
===============================   
Protocol                          isis
Next Hop                          172.20.52.1
Next hop label                    3
Interface name                    PortChannel0120
Metric                            510
Admin tag                         1000
Route type                        remote
Age                               152878
Connected                         false
Admin distance                    116
Path type                         isis-level2-internal
Protection                        none
Loose next hop                    false
Active                            true
LFA                               none

JUNYW@owr01:~$ show ipv6 route 2a01:111:e210:b::151:63/128

Destination/Mask 2a01:111:e210:b::151:63/128
============================================
Protocol                          isis
Next Hop                          fe80::febd:67ff:fe11:b128
Next hop label                    3
Interface name                    PortChannel0120
Metric                            510
Admin tag                         1000
Route type                        remote
Age                               152949
Connected                         false
Admin distance                    116
Path type                         isis-level2-internal
Protection                        none
Loose next hop                    false
Active                            true
LFA                               none

JUNYW@owr01:~$ 

rwa04.str01#show ip route 10.30.151.91/32

VRF: default
Codes: C - connected, S - static, K - kernel, 
       O - OSPF, IA - OSPF inter area, E1 - OSPF external type 1,
       E2 - OSPF external type 2, N1 - OSPF NSSA external type 1,
       N2 - OSPF NSSA external type2, B - Other BGP Routes,
       B I - iBGP, B E - eBGP, R - RIP, I L1 - IS-IS level 1,
       I L2 - IS-IS level 2, O3 - OSPFv3, A B - BGP Aggregate,
       A O - OSPF Summary, NG - Nexthop Group Static Route,
       V - VXLAN Control Service, M - Martian,
       DH - DHCP client installed default route,
       DP - Dynamic Policy Route, L - VRF Leaked,
       G  - gRIBI, RC - Route Cache Route

 I L2     10.30.151.91/32 [115/1000] via 172.20.52.0, Port-Channel120

rwa04.str01#show ipv6 rout 2a01:111:e210:b::91/128

VRF: default
Routing entry for 2a01:111:e210:b::91/128
Codes: C - connected, S - static, K - kernel, O3 - OSPFv3,
       B - Other BGP Routes, A B - BGP Aggregate, R - RIP,
       I L1 - IS-IS level 1, I L2 - IS-IS level 2, DH - DHCP,
       NG - Nexthop Group Static Route, M - Martian,
       DP - Dynamic Policy Route, L - VRF Leaked,
       RC - Route Cache Route

 I L2     2a01:111:e210:b::91/128 [115/1000]
           via fe80::569f:c6ff:fec8:42d8, Port-Channel120

rwa04.str01#
```