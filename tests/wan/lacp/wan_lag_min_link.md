# Protocols - LACP min Links:

## Test sample topo:

- Topo1:
                PTF                                        PTF
                 |                                          |
                 |                                          |
                 |                                          |
cEOS---[PortChannel with 4 links]---DUT1(SONiC)---[PortChannel with 4 links]---cEOS

## Test steps :
* Step1: Config wan-4link topology with 2 portchannels in DUT, each PortChannel include 4 member links.
        PortChannel state is UP in DUT.

    ```
    admin@vlab-01:~$ show interfaces portchannel
    Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
        S - selected, D - deselected, * - not synced
    No.  Team Dev        Protocol     Ports
    -----  --------------  -----------  -------------------------------------------------------
    101  PortChannel101  LACP(A)(Up)  Ethernet8(S) Ethernet0(S) Ethernet4(S) Ethernet12(S)
    102  PortChannel102  LACP(A)(Up)  Ethernet44(S) Ethernet48(S) Ethernet52(S) Ethernet40(S)

    admin@vlab-01:~$ show ip interfaces
    Interface       Master    IPv4 address/mask    Admin/Oper    BGP Neighbor    Neighbor IP
    --------------  --------  -------------------  ------------  --------------  -------------
    Loopback0                 10.1.0.32/32         up/up         N/A             N/A
    PortChannel101            10.0.0.56/31         up/up         N/A             N/A
    PortChannel102            10.0.0.58/31         up/up         N/A             N/A
    docker0                   240.127.1.1/24       up/down       N/A             N/A
    eth0                      10.250.0.101/24      up/up         N/A             N/A
    lo                        127.0.0.1/16         up/up         N/A             N/A

    ```
* Step 2: (default min_link number is po_link_member * 75%), for wan-4link, default min_link is 3.
    Send backgroud traffic from one PortChannel to another.
    Find output PortChannel, shutdown/no shutdown every member link, check traffic loss rate.
    (Only 1 member link down at a time, the PortChannel state should be up.)
    Expected Result:
    1. Traffic would still be received in output PTF side.
    2. Alarm would be found in syslog or detected by other methods.

    ```
    admin@vlab-01:~$ sudo config interface shutdown Ethernet8
    admin@vlab-01:~$ show interfaces portchannel
    Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
        S - selected, D - deselected, * - not synced
    No.  Team Dev        Protocol     Ports
    -----  --------------  -----------  -------------------------------------------------------
    101  PortChannel101  LACP(A)(Up)  Ethernet8(D) Ethernet0(S) Ethernet4(S) Ethernet12(S)
    102  PortChannel102  LACP(A)(Up)  Ethernet44(S) Ethernet48(S) Ethernet52(S) Ethernet40(S)

    ```
* Step 3, Shutdown 2 member links in output PortChannel.
    Expect result:
    1. PortChannel state should be down.
    2. Traffic would not be received in output PTF side.

    ```
    admin@vlab-01:~$ sudo config interface shutdown Ethernet0
    admin@vlab-01:~$ show interfaces portchannel
    Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
        S - selected, D - deselected, * - not synced
    No.  Team Dev        Protocol     Ports
    -----  --------------  -----------  -------------------------------------------------------
    101  PortChannel101  LACP(A)(Dw)  Ethernet8(D) Ethernet0(D) Ethernet4(S) Ethernet12(S)
    102  PortChannel102  LACP(A)(Up)  Ethernet44(S) Ethernet48(S) Ethernet52(S) Ethernet40(S)
    admin@vlab-01:~$

    admin@vlab-01:~$ show ip interfaces
    Interface       Master    IPv4 address/mask    Admin/Oper    BGP Neighbor    Neighbor IP
    --------------  --------  -------------------  ------------  --------------  -------------
    Loopback0                 10.1.0.32/32         up/up         N/A             N/A
    PortChannel101            10.0.0.56/31         up/down       N/A             N/A
    PortChannel102            10.0.0.58/31         up/up         N/A             N/A
    docker0                   240.127.1.1/24       up/down       N/A             N/A
    eth0                      10.250.0.101/24      up/up         N/A             N/A
    lo                        127.0.0.1/16         up/up         N/A             N/A

    admin@vlab-01:~$ show ip route
    Codes: K - kernel route, C - connected, S - static, R - RIP,
        O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
        T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
        f - OpenFabric,
        > - selected route, * - FIB route, q - queued, r - rejected, b - backup
        t - trapped, o - offload failure

    C>* 10.0.0.58/31 is directly connected, PortChannel102, 01:36:45
    C>* 10.1.0.32/32 is directly connected, Loopback0, 01:36:50
    C>* 10.250.0.0/24 is directly connected, eth0, 01:37:02

    ```
* Step 4, No shutdown previous 2 member links in Step 3.
    Expect result:
    1. When no shutdown the first member link, PortChannel state should be UP and traffic would be received in PTF.
    2. When no shutdonw the second member link, PortChannel state should be UP and traffic should not be dropped.

    ```
    admin@vlab-01:~$ sudo config interface startup Ethernet0
    admin@vlab-01:~$ show interfaces portchannel
    Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
        S - selected, D - deselected, * - not synced
    No.  Team Dev        Protocol     Ports
    -----  --------------  -----------  -------------------------------------------------------
    101  PortChannel101  LACP(A)(Up)  Ethernet8(D) Ethernet0(S) Ethernet4(S) Ethernet12(S)
    102  PortChannel102  LACP(A)(Up)  Ethernet44(S) Ethernet48(S) Ethernet52(S) Ethernet40(S)

    admin@vlab-01:~$ sudo config interface startup Ethernet8
    admin@vlab-01:~$ show interfaces portchannel
    Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
        S - selected, D - deselected, * - not synced
    No.  Team Dev        Protocol     Ports
    -----  --------------  -----------  -------------------------------------------------------
    101  PortChannel101  LACP(A)(Up)  Ethernet8(S) Ethernet0(S) Ethernet4(S) Ethernet12(S)
    102  PortChannel102  LACP(A)(Up)  Ethernet44(S) Ethernet48(S) Ethernet52(S) Ethernet40(S)

    ```
