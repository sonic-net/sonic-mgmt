# Port Access Control(PAC)

[TOC]

## Test Plan Revision History

| Rev  | Date       | Author            | Change Description           |
| ---- | ---------- | ----------------- | ---------------------------- |
| 1    | 18/05/2023 | Lakshminarayana D | Initial Version of test plan |

## Definition/Abbreviation

| **Term**   | **Meaning**                              |
| ---------- | ---------------------------------------- |
| VLAN       | Virtual Local Area Network               |
| PAC        | Port Access Control                      |
| EAPoL      | Extensible Authentication Protocol over LAN |
| MAC        | Media Access Control                     |
| MAB        | Mac Authentication Bypass                |
| PO         | Port Channel                             |
| NAS        | Network Access Switch                    |
| DUT        | Device Under Test                        |
| RADIUS     | Remote Authentication Dial In User service |
| FDB        | Forwarding Database                      |
| Supplicant | A client that attempts to access services offered by the Authenticator |
| PAE        | Port Access Entity                       |

## Introduction

### Objective

The main objective of this document is to cover the test cases that will be executed for Port authentication methods 802.1x and MAB. Topologies and test cases for testing the feature will be discussed as part of this document.

### Scope

- PAC authentication of hosts on access port
- This functionality has been tested using the SPyTest framework. In order to emulate 802.1x and MAB clients, traffic generators like Ixia and Spirent will be used. FreeRADIUS is using for User Authentication.

### Out of scope

- Authentication on Trunk port not supported

## Feature Overview

Port Access Control (PAC) feature provides validation of client and user credentials to prevent unauthorized access to a specific switch port.

Local Area Networks (LANs) are often deployed in environments that permit unauthorized devices to be physically attached to the LAN infrastructure, or permit unauthorized users to attempt to access the LAN through equipment already attached. In such environments, it may be desirable to restrict access to the services offered by the LAN to those users and devices that are permitted to use those services. Port access control makes use of the physical characteristics of LAN infrastructures in order to provide a means of authenticating and authorizing devices attached to a LAN port that has point-to-point connection characteristics and of preventing access to that port in cases in which the authentication and authorization process fails. In this context, a port is a single point of attachment to the LAN, such as Ports of MAC bridges and associations between stations or access points in IEEE 802.11 Wireless LANs.

802.1x:

IEEE 802.1X-2004 is an IEEE Standard for Port Access Control (PAC) that provides an authentication mechanism to devices wishing to attach to a LAN. The standard defines Extensible Authentication Protocol Over LAN (EAPoL). The 802.1X standard describes an architectural framework within which authentication and consequent actions take place. It also establishes the requirements for a protocol between the authenticator and the supplicant, as well as between the authenticator and the authentication server.

MAC Authentication Bypass(MAB):

Simple devices like camera or printers which do not support 802.1x authentication can make use of MAB feature where the device gets authenticated based on the device MAC address.

## Test Framework
Using SPyTest framework to test this feature. Traffic generators like Ixia and Spirent will be using to simulate 802.1x and MAB clients. FreeRADIUS is using for User Authentication and Authorization.

## 1 Test Focus Areas

### 1.1 CLI Testing

	- Verify port authentication can be enabled only on physical interfaces and gets denied on VLAN, Portchannel, PO member ports and sub interfaces.
	- Verify configured CLI fields are updated properly in respective show commands

### 1.2 Functional Testing

	- Verify all data traffic is blocked when PAC is enabled on the port.
	- Verify 802.1x client authentication in single-host mode and verify only first authenticated user is allowed.
	- Verify 802.1x client with multi-host mode and verify all users on the port are allowed after first-user gets authenticated.
	- Verify 802.1x client authentication in multi-auth mode and verify all users with valid credentials gets authenticated.
	- Verify in multi-auth mode, one of the clients logoff does not impact other authenticated clients.
	- Verify in multi-host mode, if primary host gets logged-off, other hosts are blocked and verify after authenticating again.
	- Verify 802.1x client authentication with port-control mode as force-authorized.
	- Verify 802.1x client authentication with port-control mode as force-unauthorized.
	- Verify interface level 802.1x pae authenticator disable/enable.
	- Verify global 802.1x system-auth-control enable/disable.
	- Verify enabling re-authentication with different re-authenticate timer and disabling authentication periodic shouldn't allow re-authentication.
	- Verify client authentication with MAB auth-type as EAP-MD5.
	- Verify client authentication with MAB auth-type as PAP.
	- Verify client authentication with MAB auth-type as CHAP.
	- Verify authentication order with user-configured priorities for different authentication methods.
	- Verify non-default max-users per port and check remaining clients are denied.
	- Verify that when host mode changes, the authenticated clients gets removed and traffic is blocked.
	- Verify that when authentication order is set to 802.1x, then only 802.1x client allowed to authenticate.
	- Verify that when authentication order is set to MAB, then 802.1x client authentication is not successful.
	- Verify MAB client authentication with port-control mode toggle between force authorized/unauthorized and auto.
	- Verify that 802.1x and MAB client is not authenticated if it's RADIUS assigned VLAN is not available statically on the authenticator switch.
	- Verify 802.1x and MAB client is not authenticated if RADIUS does not assign a VLAN and the port is configured with tagged VLAN.
	- Verify a port with Multi-auth mode can have authenticated clients in different radius assigned VLANs.
	- Verify that 802.1x and MAB client is not authenticated if RADIUS does not assign a VLAN and the port's configured untagged VLAN (Access VLAN) is not available
	- Verify the same MAB client authentication on different port after authenticated and verify MAC movement of the client
	- Verify the same 802.1x client authentication on different port after authenticated and verify MAC movement of the client
	- Verify the same 802.1x and MAB client authentication when PAC and ACLs applied on a same port

### 1.3 Reboot and Trigger Testing

	- Verify Client authentication after reboot
	- Verify Client authentication after warmboot
	- Verify Client authentication after config reload
	- Verify Client authentication after port toggle

### 1.4 Scale Testing

	- Verify 128 max supported 802.1x clients on DUT.
	- Verify 128 max supported MAB clients on DUT.
	- Verify that the 128 maximum supported clients on DUT can be authenticated by using both 802.1x and MAB clients.


## 2 Topologies

## 2.1 Topology 1

![PAC](PAC_topology.png "Figure 1: Topology 1")

## 3 Test Case and objectives

### **3.1 CLI Test Cases**

### 3.1.1 Verify port authentication can be enabled only on physical interfaces and gets denied on VLAN, Portchannel, Po member ports and sub interfaces

| **Test ID**    | **PAC_CLI_001**                          |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify port authentication can be enabled only on physical interfaces and gets denied on VLAN, Portchannel, PO member ports and sub interfaces** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **CLI**                                  |
| **Steps**      | 1. Verify port authentication configuration gets denied for VLAN interface,Sub interface and Portchannel interfaces<br/>2. Verify authentication can not be enabled on Portchannel member ports<br/>3. Enable authentication on physical port and add it to Portchannel and verify it is not allowed<br/>4. Enable authentication on loopback port and verify it is not allowed<br/> |


### 3.1.2 Verify configured CLI fields are updated properly in respective show commands

| **Test ID**    | **PAC_CLI_002**                          |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify configured CLI fields are updated properly in respective show commands** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **CLI**                                  |
| **Steps**      | 1. Enable 802.1x globally using command "config dot1x system-auth-control enable" and verify administrative mode as enabled in "show dot1x" command<br/>2. Disable 802.1x globally using command "config dot1x system-auth-control disable" and verify administrative mode as disabled in "show dot1x" command<br/> 3. Configure port-control mode to auto using command "config authentication port-control interface auto Ethernet0" and verify port control mode is changed to auto from force-authorized in "show authentication interface Ethernet0"<br/>4. Configure port-control mode to force-unauthorized using command "config authentication port-control interface force-unauthorized Ethernet0" and verify port control mode is changed to force-unauthorized<br/>5. Enable pae role as authenticator on interface using command "config dot1x pae interface authenticator Ethernet0" and verify pae mode is changed to authenticator in "show dot1x detail Ethernet0" and "show dot1x detail all"<br/>6. Disable pae role on interface using command "config dot1x pae interface none Ethernet0" and verify pae mode is changed to none in "show dot1x detail Ethernet0" and "show dot1x detail all"<br/>7. Configure host-mode to multi-auth using command "config authentication host-mode interface multi-auth Ethernet0" and verify host mode is changed to multi-auth from multi-host in "show authentication interface Ethernet0"<br/>8. Configure host-mode to single-host using command "config authentication host-mode interface single-host Ethernet0" and verify host mode is changed to single-host from multi-host in "show authentication interface Ethernet0"<br/>9. Configure max-users to non-default value using command "config authentication max-users interface 8 Ethernet0" and verify max-users field is changed to 8 from 16 in "show authentication interface Ethernet0"<br/>10. Enable authentication periodic using command "config authentication periodic interface enable Ethernet0" and verify re-authentication periodic is enabled in "show authentication interface Ethernet0"<br/>11. Disable authentication periodic command "config authentication periodic interface disable Ethernet0" and verify re-authentication periodic is disabled in "show authentication interface Ethernet0"<br/>12. Configure authentication timer command "config authentication timer re-authenticate 100 Ethernet0" and verify re-authentication period is updated properly in "show authentication interface Ethernet0"<br/>13. Configure authentication order to 802.1x using command "config authentication order interface dot1x Ethernet0" and verify configured method order is updated to 802.1x in "show authentication interface Ethernet0"<br/>14. Configure authentication priority to 802.1x using command "config authentication priority interface dot1x Ethernet0" and verify configured method priority is updated to 802.1x in "show authentication interface Ethernet0"<br/>15. Enable MAB with auth-type pap on interface using command "config MAB interface enable auth-type pap Ethernet0" and verify MAB admin mode is enabled with auth-type pap in "show mab Ethernet0" or "show mab"<br/>16. Disable MAB on interface using command "config mab interface disable Ethernet0" and verify MAB admin mode is disabled in "show mab Ethernet0" and "show mab"<br/> |


### **3.2 Functional Test Cases**

### 3.2.1 Verify all data traffic is blocked when PAC is enabled on the port.

| **Test ID**    | **PAC_FUNC_001**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify all data traffic is blocked when PAC is enabled on the port** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication on an interface<br/>2. Verify all data traffic is blocked when PAC is enabled on the port<br/>3. Verify EAPoL packets are not dropped<br/> |


### 3.2.2 Verify 802.1x authentication in single-host mode and verify only first authenticated user is allowed.

| **Test ID**    | **PAC_FUNC_002**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify 802.1x authentication in single-host mode and verify only first authenticated user is allowed.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication on interface on DUT <br/>2. Configure RADIUS server on the authenticator.<br/>3. Enable authentication host mode to single-host mode on the interface.<br/>4. Initiate Authentication from 802.1x supplicant and Verify Authenticator encapsulates EAP packets and sends it to RADIUS server<br/>5. Verify Authenticator moves client to Authenticated state after sending EAP success, once authenticator receives Access-accept from RADIUS server<br/>6. Verify "show authentication clients all" to see the client authentication state<br/>7. Verify static MAC FDB entry gets populated with client mac address<br/>8. Verify traffic gets forwarded from the client after it gets authenticated on the port and Verify client's traffic forwarding from the RADIUS assigned VLAN if not port's untagged VLAN is used for authorizing the client.<br/>9. Verify Client2 is blocked from accessing the server in single-host mode<br/>10. Do clear mac address table, and check statically created FDB entry for the client is not cleared and client authentication is not disturb.<br/>11. Logoff client1 and verify FDB entry gets deleted and client1 gets blocked for all the traffic<br/>12. Verify once client1 is deleted, client2 with single-host mode can be authenticated<br/>13. Clear the clients using command 'sonic-clear authentication sessions interface <intf_name> and verify client gets deleted on the device<br/> |


### 3.2.3 Verify 802.1x with multi-host mode and verify all users on the port are allowed after first-user gets authenticated.

| **Test ID**    | **PAC_FUNC_003**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify 802.1x with multi-host mode and verify all users on the port are allowed after first-user gets authenticated.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication on interface.<br/>2. Configure RADIUS server on the authenticator.<br/>3. Enable authentication host mode to multi-host mode<br/>4. Initiate Authentication from 802.1x supplicant and Verify Authenticator encapsulates EAP packets and sends it to RADIUS server<br/>6. Verify Authenticator moves client to Authenticated state after sending EAP success, once authenticator receives Access-accept from RADIUS server<br/>7. Verify "show authentication clients all" to see the client state<br/>8. Verify client's MAC FDB entry is populated once the client sends traffic after client gets authenticated<br/>9. Verify untagged and tagged traffic gets forwarded from the client's RADIUS assigned VLAN if not port's untagged VLAN after it gets authenticated on the port, check non matching tagged traffic is not allowed.<br/>10. Verify all the subsequent Clients traffic connected to port also gets access and check MAC address gets updated for all those clients<br/>11. Logoff client1 and verify all the clients connected to the port gets blocked<br/> |


### 3.2.4 Verify 802.1x client authentication in multi-auth mode and verify all users with valid credentials gets authenticated.

| **Test ID**    | **PAC_FUNC_004**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify 802.1x in  multi-auth mode and verify all users with valid credentials gets authenticated.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication on interface.<br/>2. Configure RADIUS server on the authenticator.<br/>3. Enable authentication host mode to multi-auth mode<br/>4. Initiate Authentication from multiple 802.1x supplicants connected to the same NAS port<br/>5. Verify Authenticator encapsulates EAP packets and sends it to RADIUS server<br/>6. Verify Authenticator moves all the clients to Authenticated state after sending EAP success, once authenticator receives Access-accept from RADIUS server for each client<br/>7. Verify "show authentication clients all" to see the clients authentication state<br/>8. Verify MAC FDB entry gets populated with client mac addresses, check clear mac address table, don't clear this statically created FDB entry and client authentication should not be disturbed.<br/>9. Verify traffic gets forwarded for all the authenticated Clients on the port<br/>10. Clear the clients using command 'sonic-clear authentication sessions interface all'<br/>12. verify all clients gets deleted on the device and their access is blocked<br/> |


### 3.2.5 Verify in multi-auth mode, one of the clients logoff does not impact other authenticated clients.

| **Test ID**    | **PAC_FUNC_005**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify in multi-auth mode, one of the clients logoff does not impact other authenticated clientss.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication on port in multi-auth mode<br/>2. Verify multiple Clients gets authenticated individually <br/>3. Logoff first client and verify other clients are still in authenticated state<br/>4. Verify only Client1 blocked access and other clients are allowed access to server and traffic gets forwarded<br/>5. Try authenticate client1 again and check authentication is successful and existing clients authentication should not be disturbed.<br/>6. Clear the one of the clients using command 'sonic-clear authentication sessions mac <mac_addr>' and check only its authentication is cleared and remaining are not disturbed.<br/> |


### 3.2.6 Verify in multi-host mode, if primary host gets logged-off, other hosts are blocked and verify after authenticating again.

| **Test ID**    | **PAC_FUNC_006**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify in multi-host mode, if primary host gets logged-off,other hosts are blocked and verify after authenticating again.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication on port in multi-host method<br/>2. Verify First Client gets authenticated and all subsequent clients are allowed access to server<br/>3. Logoff the primary Client1 and verify all Clients blocked access<br/>4. Try authenticating Client2 as first user and verify all Clients are allowed access |


### 3.2.7 Verify 802.1x client authentication with port-control mode as force-authorized.

| **Test ID**    | **PAC_FUNC_007**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify 802.1x client authentication with port-control mode as force-authorized.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1.Enable 802.1x globally and at interface level <br/>2. Configure RADIUS Server on the authenticator.<br/>3. Change the port control mode of the interface to force-authorized. Verify the same using “show authentication interface <number>” <br/>4. Verify the client is not required to authenticate and is set to "force-authorized"<br/>5. Try accessing the server from 802.1x client. Client should be able to access the server <br/> |


### 3.2.8 Verify 802.1x client authentication with port-control mode as force-unauthorized.

| **Test ID**    | **PAC_FUNC_008**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify 802.1x client authentication with port-control mode as force-unauthorized.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x globally and at interface level<br/>2. Configure RADIUS Server on the authenticator.<br/>3. Change the port control mode of the interface to force-unauthorized. Verify the same using “show authentication interface <number>”<br/>4. Try accessing the server from 802.1x client. Client should not be able to access the server. Also verify that there is no EAPoL packets exchange between DUT and client<br/> |


### 3.2.9 Verify interface level 802.1x pae authenticator disable/enable.

| **Test ID**    | **PAC_FUNC_009**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify interface level 802.1x pae authenticator disable/enable.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable authentication ('config dot1x pae interface authenticator <intf_name>') on interfaces .<br/>2. Enable 802.1x single-host on one port and multi-host on another port<br/>3. Initiate Authentication from 802.1x Supplicant and Verify 802.1x aware clients gets authorized on the ports <br/>4. Verify client gets access to server<br/>5. Disable authentication ('config dot1x pae interface none <intf_name>') at interface level with 802.1x clients authenticated<br/>6. Verify 802.1x configurations are still present under interface<br/>7. Re-enable authentication and verify all 802.1x clients gets authenticated and gets access to server <br/> |


### 3.2.10 Verify global 802.1x system-auth-control enable/disable.

| **Test ID**    | **PAC_FUNC_010**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify global 802.1x authentication enable/disable.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication ('config dot1x system-auth-control enable') at global level.<br/>2. Enable 802.1x authentication with single-host on one port and multi-host on another port<br/>3. Initiate Authentication from 802.1x Supplicant and Verify 802.1x aware clients gets authorized on all the ports <br/>4. Verify client gets access to server<br/>5. Disable 802.1x authentication ('config dot1x system-auth-control disable') at global level with 802.1x clients authenticated<br/>6. Verify 802.1x configurations still present under interface and ports move to unauthorized state <br/>7. Verify authenticated 802.1x clients cleared on the authenticator<br/>8. Re-enable global 802.1x authentication and verify all 802.1x clients gets authenticated<br/> |


### 3.2.11 Verify enabling re-authentication with different re-authenticate timer and disabling authentication periodic shouldn't allow re-authentication.

| **Test ID**    | **PAC_FUNC_011**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify enabling re-authentication with different re-authenticate timer and disabling authentication periodic shouldn't allow re-authentication.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x globally and at interface level<br/>2. Configure RADIUS sever on the authenticator.<br/>3. Verify Clients connected to NAS port gets authenticated<br/>4. Verify by default no re-authentication happens for any of the authenticated clients<br/>5. Enable "config authentication periodic interface enable <intf_name>" on the port(authentication time is server on the port by default, session termination action is set to default).<br/>6. Verify client initiates re-authentication after Session-Timeout value, the client authentication is failed because the session termination action is set to default on client.<br/>7. Configure re-authentication timer using "config authentication timer re-authenticate interface <seconds> <intf_name>" on DUT between 1 to 65535 in seconds and verify client gets re-authenticated as per configured re-auth timer expires on that specific port<br/>8. Modify the RADIUS server configuration such that the client authentication failed.<br/>9. Verify clients gets deleted in re-authentication process after re-auth timer expires.<br/>10. Remove re-authentication timer configuration on a port and verify client initiates re-authentication as authentication periodic enabled on the port after server supplied timeout value, the client authentication is failed because the session termination action is set to default on client.<br/>11. Disable authentication periodic on one port and verify authenticator do not attempt any re-authentication only for that specific port<br/> |


### 3.2.12 Verify client authentication with MAB auth-type as EAP-MD5.

| **Test ID**    | **PAC_FUNC_012**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify client authentication with MAB auth-type as EAP-MD5.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable authentication on interface.<br/>2. Configure RADIUS server on the authenticator.<br/>3. Enable MAB with auth-type as EAP-MD5 and single-host mode on interface<br/>4. Initiate Authentication from 802.1x Supplicant or Send data packets from client, Verify Authenticator (DUT) sends Access-Request to RADIUS server with username and password as Mac address learnt on the port<br/>5. Verify DUT moves client to authenticated state once RADIUS server responds with Access-accept<br/>6. Verify "show authentication clients all" to see the client state<br/>7. Verify MAC FDB entry gets populated with client mac address, check clear mac address table don't clear this mac entry and client authentication is not disturbed.<br/>8. Verify traffic gets forwarded after client gets authenticated on the port<br/>9. Verify Client2 is blocked from accessing the server in single-Host mode<br/>10. Logoff client1 and verify FDB entry gets deleted and client1 gets blocked for all the traffic<br/> |


### 3.2.13 Verify client authentication with MAB auth-type as PAP.

| **Test ID**    | **PAC_FUNC_013**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify client authentication with MAB auth-type as PAP.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable authentication on interface.<br/>2. Configure RADIUS server on the authenticator.<br/>3. Enable MAB with auth-type as PAP and multi-host mode on interface<br/>4. Initiate Authentication from 802.1x Supplicant or Send data packets from client, Verify Authenticator (DUT) sends Access-Request to RADIUS server with username and password as Mac address learnt on the port<br/>5. Verify DUT moves client to Authenticated state once RADIUS server responds with Access-accept<br/>6. Verify "show authentication clients all" to see the client state<br/>7. Verify other clients connected to same port gets access to server<br/>8. Verify MAC FDB entry gets populated with all the mac addresses<br/>9. Verify traffic gets forwarded after client gets authenticated on the port<br/>10. Logoff client1 and verify FDB entry gets deleted for the client on the port and access blocked for all the hosts<br/> |


### 3.2.14 Verify client authentication with MAB auth-type as CHAP.

| **Test ID**    | **PAC_FUNC_014**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify client authentication with MAB auth-type as CHAP.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable authentication on interface.<br/>2. Configure RADIUS server on the authenticator.<br/>3. Enable MAB with auth-type as CHAP and multi-auth mode on interface<br/>4. Initiate Authentication from multiple 802.1x Supplicant or Send data packets from multiple clients connected to the same NAS port<br/>5. Verify Authenticator (DUT) sends Access-request to RADIUS server with mac address as username and password<br/>6. Verify DUT moves client to Authenticated state after authenticator receives Access-accept from RADIUS server<br/>7. Verify "show authentication clients all" to see the clients authentication state<br/>8. Verify MAC FDB entry gets populated with client mac addresses<br/>9. Verify traffic gets forwarded for all the authenticated Clients on the port<br/>10. Verify unauthenticated new Host on the port not granted access <br/>11. Logoff all the clients and verify Clients move to Unauthenticated state and access blocked<br/> |


### 3.2.15 Verify authentication order with user-configured priorities for different authentication methods.

| **Test ID**    | **PAC_FUNC_015**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify authentication order with user-configured priorities for different authentication methods.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable both 802.1x and MAB authentication on an interface<br/>2. Configure-authentication priority as [dot1x, mab]<br/>3. Send data packets from client and Verify client authenticated as a MAB client as per the authentication order<br/>4. Try authenticate the same client using 802.1x and verify authentication is successful with 802.1x(has higher priority on the interface)<br/> |


### 3.2.16 Verify non-default max-users per port and check remaining clients are denied

| **Test ID**    | **PAC_FUNC_016**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify non-default max-users per port and check remaining clients are denied** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable PAC  at interface<br/>2. Configure max-users as 10 on the interface<br/>3. Verify only 10 hosts are authenticated in multi-auth mode and proper log message generated indicating max-users reached.<br/>4. Verify 11th host will not be authenticated <br/>5. Logoff one of the clients and try to authenticate that new 11th client now, check that it is authenticated successfully.<br/>6. Delete max-user config and verify it resets to default 16 and all 16 clients got authenticated<br/> |


### 3.2.17 Verify that when host mode changes, the authenticated clients gets removed and traffic is blocked.

| **Test ID**    | **PAC_FUNC_017**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify that when host mode changes, the authenticated clients gets removed and traffic is blocked.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication on port in multi-auth mode<br/>2. Verify multiple Clients gets authenticated individually <br/>3. Verify that traffic corresponding to those clients gets forwarded.<br/>4. While clients are authenticated and traffic is forwarding, change the mode to multi-host mode on the interface.<br/>5. Verify that change of mode config is successful, authenticated clients gets removed and traffic is blocked from the client on the interface<br/>6. Now with port in multi-host mode, authenticate a single client and check traffic forwarding corresponding to this client and other clients also is successful.<br/>7. While traffic is forwarding, change the mode to single-host mode and check config is successful and earlier client authentication gets removed and traffic is blocked.<br/>8. With port in single-host mode, authenticate a client and check traffic  forwarding is successful.<br/>9. While traffic is forwarding, change the mode to multi-auth and check earlier client authentication is removed and traffic is blocked.<br/>10. With port in multi-auth mode, authenticate multiple clients and check the corresponding clients traffic forwarding is successful.<br/> |


### 3.2.18 Verify that when authentication order is set to 802.1x and host mode is set to multi-auth, then only 802.1x client allowed to authenticate.

| **Test ID**    | **PAC_FUNC_018**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify that when authentication order is set to 802.1x and host mode is set to multi-auth, then only 802.1x client allowed to authenticate.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x globally and on interface.<br/>2. Configure 'config authentication order interface dot1x <intf_name>' with mode as multi-auth and also enable MAB.<br/>3. Initiate a 802.1x client and check authentication is successful.<br/>4. Try initiate traffic for MAB client, and check it is rejected and MAB client should not get authenticated.<br/>5. Try authenticating another 802.1x client, and check authentication is successful.<br/>6. Verify that traffic from these 802.1x clients is forwarded.<br/> |


### 3.2.19 Verify that when authentication order is set to MAB and host mode is set to multi-auth, then 802.1x client authentication is not successful.

| **Test ID**    | **PAC_FUNC_019**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify that when authentication order is set to MAB and host mode is set to multi-auth, then 802.1x client authentication is not successful.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x globally and on interface.<br/>2. Configure 'config authentication order interface MAB <intf_name>' with mode as multi-auth and also enable MAB.<br/>3. Initiate a 802.1x client and check authentication is not successful as 802.1x method is not enabled.<br/>4. Try initiate traffic for MAB client, and check its authentication is successful.<br/>5. Try authenticating another MAB client, and check authentication is successful.<br/>6. Verify that traffic from these MAB clients is forwarded.<br/> |


### 3.2.20 Verify MAB client authentication with port-control mode toggle between force authorized/unauthorized and auto.

| **Test ID**    | **PAC_FUNC_020**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify MAB client authentication with port-control mode toggle between force -authorized/unauthorized and auto.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x globally and at interface level, enable MAB on the interface<br/>2. Configure the port control mode to force-authorized and verify port is set to force-authorized and client gets access to server without any authentication<br/>3. Change the port control mode to "auto" and verify Client requires authentication before granting server access<br/>4. Change the port control mode to force-unauthorized and verify no clients on the port gets authenticated<br/>5. Change it to "auto" and verify Client gets authenticated and then granted access to server<br/> |


### 3.2.21 Verify that 802.1x and MAB client is not authenticated if it's RADIUS assigned VLAN is not available statically on the authenticator switch.

| **Test ID**    | **PAC_FUNC_021**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify that 802.1x and MAB client is not authenticated if it's RADIUS assigned VLAN is not available statically on the authenticator switch.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x system auth control globally and enable pae authenticator on interface.<br/>2. Configure host mode as multi-auth, enable 802.1x and MAB on the interface.<br/>3. Configure RADIUS server as VLAN attribute to non-existing VLAN ID in NAS.<br/>4. Authenticate 802.1x and MAB clients and check authentication is not successful.<br/>5. Create RADIUS assigned VLAN on NAS.<br/>6. Try to authenticate same 802.1x and MAB client and verify authentication is successful.<br/> |


### 3.2.22 Verify 802.1x and MAB client is not authenticated if RADIUS does not assign a VLAN and the port is configured with tagged VLAN.

| **Test ID**    | **PAC_FUNC_022**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify 802.1x and MAB client is not authenticated if RADIUS does not assign a VLAN and the port is configured with tagged VLAN.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x system-auth-control globally and enable pae authenticator on interface.<br/>2. Configure host mode as multi-host, enable 802.1x and MAB on the interface.<br/>3. Configure RADIUS server as VLAN attribute to existing VLAN ID in NAS.<br/>4. Add switchport trunk VLAN configuration on 802.1x and MAB enabled interfaces.<br/>5. Authenticate 802.1x and MAB clients and check authentication is not successful.<br/>6. Change the port participation from truck to access mode on the 802.1x and MAB enabled interfaces.<br/>7. Try to authenticate same 802.1x and MAB client and verify authentication is successful.<br/> |


### 3.2.23 Verify a port with Multi-auth mode can have authenticated clients in different radius assigned VLANs.

| **Test ID**    | **PAC_FUNC_023**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify a port with Multi-auth mode can have authenticated clients in different radius assigned VLANs.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x system auth control globally and enable pae authenticator on interface.<br/>2. Configure host mode as multi-auth, enable 802.1x and MAB on the interface.<br/>3. Configure multiple users with different VLANs in RADIUS server.<br/>4. Try to authenticate client1 and verify client authentication is successful, port added in RADIUS assigned VLAN.<br/>5. Try to Authenticate client2 with different RADIUS assigned VLAN and verify authentication is not successful.<br/>6. Change the VLAN attribute to Client2 as Client1 in RADIUS server.<br/>7. Try to authenticate Client2 again and verify authentication is successful.<br/> |


### 3.2.24 Verify that 802.1x and MAB client is not authenticated if RADIUS does not assign a VLAN and the port's configured untagged VLAN (Access VLAN) is not available

| **Test ID**    | **PAC_FUNC_024**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify that 802.1x and MAB client is not authenticated if it's RADIUS assigned VLAN is not available statically on the authenticator switch.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x system auth control globally and enable pae authenticator on interface.<br/>2. Configure host mode as multi-host, enable 802.1x and MAB on the interface.<br/>3. Configure users to without VLAN attribute in RADIUS server.<br/>4. Add switchport access VLAN configuration on 802.1x and MAB enabled interfaces, do not create configured VLAN on the the switch<br/>5. Authenticate 802.1x and MAB clients and check authentication is not successful.<br/>6. Create RADIUS assigned VLAN on NAS.<br/>7. Try to authenticate same 802.1x and MAB client and verify authentication is successful.<br/> |


### 3.2.25 Verify the same MAB client authentication on different port after authenticated and verify MAC movement of the client
| **Test ID**    | **PAC_FUNC_025**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify the same MAB client authentication on different port after authenticated and verify MAC movement of the client.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x system auth control globally and enable pae authenticator on interface.<br/>2. Configure host mode as multi-host, enable MAB on the two interface port-1 and port-2.<br/>3. Authenticate MAB client on port-1 and check authentication is successful.<br/>4. Verify the FDB entry is installed properly on port-1.<br/>5. Try to authenticate same MAB client on port-2 and verify authentication is successful on port-2.<br/>6. Verify MAC is moved from port-1 to port-2 properly and verify traffic is forwarded to uplink port.<br/>7. Now again, try to authenticate same MAB client on port-1 and verify authentication is successful on port-1.<br/>6. Verify MAC is moved from port-2 to port-1 properly and verify traffic is forwarded to uplink port.<br/> |


### 3.2.26 Verify the same 802.1x client authentication on different port after authenticated and verify MAC movement of the client
| **Test ID**    | **PAC_FUNC_026**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify the same 802.1x client authentication on different port after authenticated and verify MAC movement of the client.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x system auth control globally and enable pae authenticator on interface.<br/>2. Configure host mode as multi-host, enable 802.1x on the two interface port-1 and port-2.<br/>3. Authenticate 802.1x client on port-1 and check authentication is successful.<br/>4. Verify the FDB entry is installed properly on port-1.<br/>5. Try to authenticate same 802.1x client on port-2 and verify authentication is successful on port-2.<br/>6. Verify MAC is moved from port-1 to port-2 properly and verify traffic is forwarded to uplink port.<br/>7. Now again, try to authenticate same 802.1x client on port-1 and verify authentication is successful on port-1.<br/>6. Verify MAC is moved from port-2 to port-1 properly and verify traffic is forwarded to uplink port.<br/> |

### 3.2.27 Verify the same 802.1x and MAB client authentication when PAC and ACLs applied on a same port
| **Test ID**    | **PAC_FUNC_027**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify the same 802.1x and MAB client authentication when PAC and ACLs applied on a same port.** |
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x system auth control globally and enable pae authenticator on interface.<br/>2. Configure host mode as multi-host, enable 802.1x on the two interface port-1 and port-2.<br/>3. Create static ACL and applied on PAC enabled port and verify the ACLs applied properly.<br/>4. The traffic is dropped to uplink port before clients authentication.<br/>5. Authenticate 802.1x client on port-1 and check authentication is successful.<br/>6. Send the traffic matching to configured ACL rules and verify the traffic is forwarded properly.<br/>7. Delete assign the ACLs on the port and verify the authenticated clients won't be impacted.<br/>8. Logoff the clients and verify clients removed on the port without any issue.<br/>.9. Verify applied ACLs on a port is retained and traffic forwarding to uplink port as per rules.<br/> |


### **3.3 Reboot and Trigger Test Cases**

### 3.3.1 Verify Client authentication after reboot

| **Test ID**    | **PAC_FUNC_TRIGGER_001**                 |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify Client authentication after reboot**|
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Define RADIUS server<br/>2. Enable 802.1x/MAB globally and at interface level<br/>3. Authenticate to the DUT with multiple 802.1x clients and MAB clients<br/>4. Do config save and "reboot"<br/>5. 802.1x/MAB clients are removed and authenticated again.<br/>6. Initiate 802.1x and MAB clients and verify that 802.1x/MAB clients authentication is successful after reboot.<br/> |


### 3.3.2 Verify Client authentication after warmboot

| **Test ID**    | **PAC_FUNC_TRIGGER_002**                 |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify Client authentication after warmboot**|
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Define RADIUS server<br/>2. Enable 802.1x/MAB globally and at interface level<br/>3. Authenticate to the DUT with multiple 802.1x clients and MAB clients<br/>4. Do config save and warmboot<br/>5. 802.1x/MAB clients are removed and authenticated again.<br/>6. Initiate 802.1x and MAB clients and verify that 802.1x/MAB clients authentication is successful after warm-reboot.<br/> |


### 3.3.3 Verify Client authentication after config reload

| **Test ID**    | **PAC_FUNC_TRIGGER_003**                 |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify Client authentication after config reload**|
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Define RADIUS server<br/>2. Enable 802.1x/MAB globally and at interface level<br/>3. Authenticate to the DUT with multiple 802.1x clients and MAB clients<br/>4. Do config save and perform config-reload<br/>5. 802.1x/MAB clients are removed and authenticated again.<br/>6. Initiate 802.1x and MAB clients and verify that 802.1x/MAB clients authentication is successful after config-reload.<br/> |


### 3.3.4 Verify Client authentication after port toggle

| **Test ID**    | **PAC_FUNC_TRIGGER_004**                 |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify Client authentication after port toggle**|
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Define RADIUS server<br/>2. Enable 802.1x/MAB globally and at interface level<br/>3. Authenticate to the DUT with multiple 802.1x clients and MAB clients<br/>4. Perform shutdown and no shutdown on client authenticated port.<br/>5. 802.1x/MAB clients are removed and authenticated again.<br/>6. Initiate 802.1x and MAB clients and verify that 802.1x/MAB clients authentication is successful after port flap.<br/> |


### **3.4 Scale Test Cases**

### 3.4.1 Verify 128 max supported 802.1x clients on DUT.

| **Test ID**    | **PAC_SCAL_001**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify 128 max supported 802.1x clients on DUT.**|
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication globally and at interface level on multiple ports<br/>2. Configure host mode as multi-auth on multiple ports on the DUT.<br/>3. Try authentication 128 802.1x clients across multiple interfaces(at least 16 clients from one or two interfaces to cover max clients per port) and verify 128 802.1x authenticated clients<br/>4. Verify FDB entries for all 128 clients<br/>5. Verify all client traffic gets allowed after authentication<br/>6. Logoff all the 128 clients and verify clients move to unauthorized state and gets blocked from accessing the server.<br/>7. Reinitiate the clients and check all are authenticated successfully.<br/>8. Log off the clients again and check all are cleared.<br/> |


### 3.4.2 Verify 128 max supported MAB clients on DUT.

| **Test ID**    | **PAC_SCAL_002**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify 128 max supported MAB clients on DUT.**|
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication globally and at interface level on multiple ports<br/>2. Configure host mode as multi-auth on multiple ports on the DUT.<br/>3.Try authentication 128 MAB clients across multiple interfaces and verify 128 MAB authenticated clients <br/>4. Verify FDB entries for all 128 clients<br/>5. Verify all client traffic gets allowed after authentication<br/>6. Logoff all the 128 clients and verify clients move to unauthorized state and gets blocked from accessing the server<br/>7. Reinitiate the clients and check all are authenticated successfully.<br/>8. With max clients authenticated, perform save and reload.<br/>9. Check that after DUT comes up, all clients are authenticated successfully.<br/> |


### 3.4.3 Verify that the 128 maximum supported clients on DUT can be authenticated by using both 802.1x and MAB clients.

| **Test ID**    | **PAC_SCAL_003**                         |
| -------------- | :--------------------------------------- |
| **Test Name**  | **Verify that the 128 maximum supported clients on DUT can be authenticated by using both 802.1x and MAB clients.**|
| **Test Setup** | **Topology1**                            |
| **Type**       | **Functional**                           |
| **Steps**      | 1. Enable 802.1x authentication globally and at interface level on multiple ports<br/>2. Configure host mode as multi-auth and MAB on multiple ports on the DUT.<br/>3. Try to validate the authentication of a combination of 802.1x and MAB clients across different interfaces, accommodating a scale of up to 128 clients and verify that all 802.1x and MAB clients authenticated properly on different ports.<br/>4. Verify FDB entries for all 128 clients installed properly.<br/>5. Verify all client traffic gets allowed after authentication.<br/>6. Logoff all the 128 clients and verify clients move to unauthorized state and gets blocked from accessing the server<br/>7. Reinitiate the clients and check all are authenticated successfully.<br/>|

## **4 Sample Outputs**

### 4.1 Sample configuration commands
```
config authentication port-control interface <auto \| force-authorized \| force-unauthorized \>  <interface\>
config dot1x pae interface  <authenticator \| none\> <interface\>
config authentication host-mode interface <multi-auth \|  multi-host \| single-host \> <interface\>
config dot1x system-auth-control <enable\|disable\>
config authentication max-users interface <max-users\> <interface\>
config mab interface <enable\|disable\> <interface\> \[ auth-type <pap \| eap-md5 \| chap \>\]
config authentication periodic interface <enable\|disable> <interface\>
config authentication timer reauthenticate interface <seconds \| server\> <interface\>
config authentication order interface <dot1x \[ mab \] \| mab \[ dot1x \]> <interface\>
config authentication priority interface <dot1x \[ mab \] \| mab \[ dot1x \]> <interface\>
```


### 4.2 Sample clear commands
```
sonic-clear authentication sessions <interface <all | <interface\>\>\> | <mac <mac\>\>
```


### 4.3 Sample show outputs
```
admin@sonic:~$ show authentication clients all

---------------------------------------------------------------------------------------------------------------------------------------------
Interface      User Name                          MAC-Address            Method       Host Mode      Control Mode      VLAN Assigned Reason
---------------------------------------------------------------------------------------------------------------------------------------------
Ethernet0      Userv11                            00:00:00:41:22:33      802.1x       single-host    auto              Radius (20)
Ethernet1      Userv21                            00:00:00:42:22:33      802.1x       multi-host     auto              Radius (30)


admin@sonic:~$ show authentication clients Ethernet1

Mac Address ........................................ 00:00:00:42:22:33
User Name .......................................... Userv21
VLAN Assigned Reason ............................... Radius (30)
Host Mode .......................................... multi-host
Method ............................................. 802.1x
Session time ....................................... 147
Session timeout .................................... 60
Time left for Session Termination Action ........... Not Applicable
Session Termination Action ......................... Default


admin@sonic:~$ show authentication interface Ethernet0

Interface ..................................... Eth1/46
Port Control Mode.............................. auto
Host Mode...................................... single-host
Configured method order........................ dot1x mab
Enabled method order........................... dot1x mab
Configured method priority..................... dot1x mab
Enabled method priority........................ dot1x mab
Reauthentication Enabled....................... TRUE
Reauthentication Period (secs)................. 90
Maximum Users.................................. 1
PAE role ...................................... Authenticator


admin@sonic:~$ show mab interface Ethernet0

Interface  ..................................... Ethernet0
Admin mode ..................................... Enabled
mab_auth_type .................................. EAP_MD5
Server Timeout(secs) ........................... 30


admin@sonic:~$ show mab

Interface  ..................................... Ethernet0
Admin mode ..................................... Disabled
mab_auth_type .................................. EAP_MD5
Server Timeout(secs) ........................... 30

Interface  ..................................... Ethernet1
Admin mode ..................................... Enabled
mab_auth_type .................................. EAP_MD5
Server Timeout(secs) ........................... 30

Interface  ..................................... Ethernet2
Admin mode ..................................... Disabled
mab_auth_type .................................. EAP_MD5
Server Timeout(secs) ........................... 30

Interface  ..................................... Ethernet3
Admin mode ..................................... Enabled
mab_auth_type .................................. EAP_MD5
Server Timeout(secs) ........................... 30

Interface  ..................................... Ethernet4
Admin mode ..................................... Disabled
mab_auth_type .................................. EAP_MD5
Server Timeout(secs) ........................... 30

Interface  ..................................... Ethernet5
Admin mode ..................................... Enabled
mab_auth_type .................................. EAP_MD5
Server Timeout(secs) ........................... 30


admin@sonic:~$ show dot1x detail Ethernet0

Interface ..................................... Ethernet0
PAE Capabilities .............................. authenticator
Server Timeout(secs) .......................... 30
Quiet Period(secs)............................. 30


admin@sonic:~$ show dot1x detail all

Interface ..................................... Ethernet0
PAE Capabilities .............................. none
Server Timeout(secs) .......................... 30
Quiet Period(secs)............................. 30

Interface ..................................... Ethernet1
PAE Capabilities .............................. none
Server Timeout(secs) .......................... 30
Quiet Period(secs)............................. 30

Interface ..................................... Ethernet2
PAE Capabilities .............................. none
Server Timeout(secs) .......................... 30
Quiet Period(secs)............................. 30

Interface ..................................... Ethernet3
PAE Capabilities .............................. none
Server Timeout(secs) .......................... 30
Quiet Period(secs)............................. 30

Interface ..................................... Ethernet4
PAE Capabilities .............................. none
Server Timeout(secs) .......................... 30
```

## **Reference Links**

https://github.com/sonic-net/SONiC/pull/1315
