# Protocols/Technology - LLDP:
  ## TOPO requirement :  
  - DUT<--->Device1(SONiC)


## Test steps :
* STEP 1:  run "show lldp neighbor" on DUT ,if nothing return, the testcase is failed. If we got some result, pick up the lldp neighbor which is sonic device . in this case we see Device1(SONiC) is chosen . Collect all the information (local interface, remote systemname,remote management IP, remote interface,remote interface dscription)


```
    xiguan@owr01:~$ show lldp nei
    -------------------------------------------------------------------------------
    LLDP neighbors:
    -------------------------------------------------------------------------------
    Interface:    eth0, via: LLDP, RID: 1, Time: 0 day, 20:21:10
    Chassis:     
        ChassisID:    mac f4:b5:2f:56:85:40
        SysName:      STR-22EX-219-A06
        SysDescr:     Juniper Networks, Inc. ex2200-48t-4g , version 12.3R4.6 Build date: 2013-09-13 02:53:16 UTC 
        Capability:   Bridge, on
        Capability:   Router, on
    Port:        
        PortID:       local 588
        PortDescr:    ge-0/0/38.0
        TTL:          90
        MFS:          1514
        PMD autoneg:  supported: yes, enabled: yes
        Adv:          10Base-T, HD: yes, FD: yes
        Adv:          100Base-TX, HD: yes, FD: yes
        Adv:          1000Base-T, HD: no, FD: yes
        MAU oper type: unknown
    VLAN:         151, pvid: yes core
    LLDP-MED:    
        Device Type:  Network Connectivity Device
        Capability:   Capabilities, yes
        Capability:   Policy, yes
        Capability:   Location, yes
        Capability:   MDI/PSE, yes
    Unknown TLVs:
        TLV:          OUI: 00,90,69, SubType: 1, Len: 12 43,55,30,32,31,33,35,31,30,39,37,35
    -------------------------------------------------------------------------------
    Interface:    Ethernet3, via: LLDP, RID: 3, Time: 0 day, 20:11:40
    Chassis:     
        ChassisID:    mac fc:bd:67:11:b1:28
        SysName:      rwa04.str01
        SysDescr:     Arista Networks EOS version 4.26.2FX-RSVP-DPE running on an Arista Networks DCS-7808-CH
        MgmtIP:       10.3.151.63
        Capability:   Bridge, on
        Capability:   Router, on
    Port:        
        PortID:       ifname Ethernet5/35/1
        PortDescr:    DUT:Ethernet3::depishe
        TTL:          120
        MFS:          10200
        Port is aggregated. PortAggregID: 1000120
    -------------------------------------------------------------------------------
    Interface:    Ethernet2, via: LLDP, RID: 6, Time: 0 day, 01:49:12
    Chassis:     
        ChassisID:    mac 34:ed:1b:69:74:00
        SysName:      rwa03.str01.network.microsoft.com
        SysDescr:     7.3.16, 8000
        MgmtIP:       10.3.151.82
        MgmtIP:       2a01:111:e210:b::159:80
        Capability:   Router, on
    Port:        
        PortID:       ifname Bundle-Ether121
        PortDescr:    DUT:FourHundredGigE0/0/0/2::depishe
        TTL:          120
    -------------------------------------------------------------------------------
    Interface:    Ethernet2, via: LLDP, RID: 6, Time: 0 day, 01:48:44
    Chassis:     
        ChassisID:    mac 34:ed:1b:69:74:00
        SysName:      rwa03.str01.network.microsoft.com
        SysDescr:     7.3.16, 8000
        MgmtIP:       10.3.151.82
        MgmtIP:       2a01:111:e210:b::159:80
        Capability:   Router, on
    Port:        
        PortID:       ifname FourHundredGigE0/2/0/8
        PortDescr:    DUT:FourHundredGigE0/0/0/2::depishe
        TTL:          120
    -------------------------------------------------------------------------------
    Interface:    Ethernet2, via: LLDP, RID: 6, Time: 0 day, 01:48:44
    Chassis:     
        ChassisID:    mac 34:ed:1b:69:74:00
        SysName:      Device1(SONiC).network.microsoft.com
        SysDescr:     7.3.16, 8000
        MgmtIP:      10.3.151.91
        MgmtIP:       2a01:111:e210:b::159:80
        Capability:   Router, on
    Port:        
        PortID:       ifname Ethernet2
        PortDescr:    DUT:FourHundredGigE0/0/0/2::depishe
        TTL:          120
```
* STEP2: login the neighbor sonic device , in this case, we need to login Device1(SONiC). run "show lldp neighbor" on each of the neighbor devices , and pick up the entry matching the DUT(DUT), collect the local port , local port description, remote systemname , remote port. And get the management IP from the device handler. 
Pls note that the local info on the neighbor device should match the remote info of the DUT.

    ```
    Interface:    Ethernet2, via: LLDP, RID: 6, Time: 0 day, 01:48:44
    Chassis:     
        ChassisID:    mac 34:ed:1b:69:74:00
        SysName:      DUT.network.microsoft.com
        SysDescr:     7.3.16, 8000
        MgmtIP:      10.3.151.92
        MgmtIP:       2a01:111:e210:b::159:80
        Capability:   Router, on
    Port:        
        PortID:       ifname Ethernet2
        PortDescr:    Device1(SONiC):FourHundredGigE0/0/0/2::depishe
        TTL:          120
    ```

* STEP3: compare the info we got from DUT and the info from neighbor device, if something not match, then the testcase is failed, if everything match, testcase passed. 









