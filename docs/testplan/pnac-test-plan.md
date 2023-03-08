**SONiC P-NAC TEST PLAN**

**Overview:**

Network access control (NAC), also known as network admission control, is the process of restricting unauthorized users and devices from accessing a network. NAC ensures that only users who are authenticated and devices that are authorized and compliant with security policies can enter the network. It restricts the availability of network resources to endpoint devices and users that are authorized and comply with the defined security policy. 

**Scope:** 

The tests outlined below are targeted towards validating the NAC functionality on a SONIC system. The testing will be done on Edgecore AS7716 target platform supporting NAC functionality. The NAC functionality should support “local” authentication

**PNAC Test Topology:             ![](Aspose.Words.67da8961-55ed-4ba3-bb13-d829cf3820c1.001.png)**

**SAI API’s:** Version 1.10.2

**SONiC Software Version:** SONiC.202205.0-X

**Tests:**

**Test1# NAC CLI Configuration/show commands**

**Test Objective:** The purpose is to test all applicable NAC CLI configuration and show  commands.

**Topology:** PNAC Test Topology 

**Related CLI Commands:**

|**Command**|**Comment**|
| :-: | :-: |
|**Configuration Commands**||
|config nac <enable | disable> |To enable/disable NAC in global mode.|
|config nac interface enable <interface\_name | all> |To enable/disable NAC in interface mode.|
|**Show Commands** ||
|show nac |To display the NAC admin state, authentication type and NAC type. |
|show nac interface <interface\_name | all>|To display the NAC status in an interface|

**Test Case (1.1): NAC Enable in Global Mode:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Configure “config nac enable” to enable NAC in global mode.

\3. Verify if the NAC admin state is UP using the “show nac” command.

**Test Case (1.2): NAC Disable in Global Mode:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Configure “config nac disable” to disable NAC in global mode.

\3. Verify if the NAC admin state is DOWN using the “show nac” command.

**Test Case (1.3): NAC Enable on an Interface:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Configure “config nac interface enable <interface\_name | all>” to enable NAC on a particular interface or on all interfaces.

\3. Verify if the NAC admin state is UP on the interface using the “show nac interface <interface\_name | all>” command.

**Test Case (1.4): NAC Disable on an Interface:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Configure “config nac interface disable<interface\_name | all>” to disable NAC on a particular interface or on all interfaces.

\3. Verify if the NAC admin state is DOWN on the interface using the “show nac interface <interface\_name | all>” command.

**Test Case (1.5): NAC Enable/Disable on an Invalid Interface:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Enter the NAC enable/disable command on an interface with an invalid interface.

\3. Check the appropriate error message “Invalid interface name” is thrown.

**Test Case (1.6): NAC Show related commands:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Enter the "show nac" command to check the NAC status.

\3. Verify the NAC admin state, NAC Type and NAC Authentication type.

**Test Case (1.7): NAC Show interface related commands:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Enter the command "show nac interface <interface\_name | all>" to check the NAC interface status.

\3. Verify the NAC admin state, Authorization state for a specific interface or for all valid interface available.

**Sample Show Output:**

**1. Show NAC:** 

admin@sonic:~$ show nac

NAC Global Information:

NAC Admin State: down

NAC Type: port

NAC Authentication Type: local

**2. Show NAC Interface:** 

admin@sonic:~$ show nac interface Ethernet16

+----------------------+--------------------------+----------------------------+

| Interface Name   | NAC Admin State   | Authorization State   | 

+=================+==================+========+

| Ethernet16         | down                        | unauthorized             |                  

+-----------------+------------------+----------------------------------+

**Test 2# Validate Port based NAC functionality with Local** 

`              `**Authentication**

**Test Objective:** The purpose is to test the port-based NAC functionality with local authentication.

**Topology:** PNAC Test Topology 

**Test Case (2.1): Port based NAC (local authentication) on an interface**

**Test Objective:** To verify the Port based NAC (local authentication) on an interface using a valid password. 

**Test Steps:** 

\1. Log in to the supplicant machine.

\2. Log in to the switch with preloaded PNAC supported SONiC image.

\3. Verify if the NAC status is UP in global mode and on the interface using show nac interface <interface\_name | all> and show nac command.

\4. Start the supplicant and verify that the authentication is successful on the supplicant side.

\5. Verify if the NAC enabled interface is authorized.

\6. Verify if that the ping between the two hosts is successful.

**Test Case (2.2): Port based NAC (local authentication) on an interface** 

**Test Objective:** To verify the Port based NAC (local authentication) on an interface using an invalid password.

**Test Steps:** 

\1. Log in to the supplicant machine.

\2. Log in to the switch which is fully configured with PNAC feature.

\3. Verify if the NAC status is UP in global mode and on the interface using show nac interface <interface\_name | all> and show nac command.

\4. Start the supplicant at the Linux machine and verify if the authentication is unsuccessful on the supplicant side.

\5. Verify if the NAC enabled interface is unauthorized.

\6. Verify if that the ping between the two hosts is unsuccessful.

**Test Case (2.3): Image Upgrade on the Switch**

**Test Objective:** Verify the local authentication after an image upgradation on the switch.

**Test Steps:** 

\1. Log in to the switch and upgrade the image which is previously installed.

\2. Verify if the image upgradation is successful.

\3. Verify if the NAC container is accessible.

\4. Start the supplicant.

\5. Verify that the local authentication is successful on the supplicant.

\6. Verify the NAC enabled interface is authorized.

\7. Ensure that the ping is successful between the hosts.

**Test Case (2.4): Warm Reboot on the Switch**

**Test Objective:** Verify the local authentication after a warm reboot on the switch.

**Test Steps:** 

\1. Log in to the switch and initiate a warm reboot through CLI (sudo reboot).

\2. After reboot, verify if the NAC container is accessible.

\3. Start the supplicant and verify if the authentication is successful.

\4. Verify if the NAC enabled port is authorized.

\5. Ensure that the ping is successful between the hosts.

**Test Case (2.5): Cold Reboot on the Switch**

**Test Objective:** Verify the local authentication after a cold reboot on the switch.

` `**Test Steps:** 

\1. Initiate a cold reboot on the switch by completely shutting down the switch.

\2. After reboot, verify if the NAC container is accessible.

\3. Start the supplicant and verify that the authentication is successful.

\4. Ensure the NAC enabled port is authorized.

\5. Ensure that the ping is successful between the hosts.

**Test Case (2.6): Port NAC (local authentication) Trigger Validation**

**Test Objective:** Validate the Port NAC functionality (local authentication) triggers (Port UP Down and NAC Enable/Disable)

` `**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Enable the NAC interface.

\3. Start the supplicant and verify if the authorization at the authenticator is successful.

\4. Disable the NAC globally and on the interface and ensure that the local authentication is interrupted. 

\5. Enable the NAC globally and on the interface again and ensure that the port is authorized and traffic is received at the network PC.


|**S. NO**|**Test Description**|**Expected Result**|
| :-: | :-: | :-: |
|**1**|**Local Authentication using Valid Password**|<p>1. Authentication should be  </p><p>`    `successful at the supplicant.</p><p>2. Port should be authorized at the </p><p>`    `authenticator.</p><p>3. Packets should be received </p><p>`    `successfully at the Linux VM.</p>|
|**2**|**Local Authentication using Invalid Password**|<p>1. Authentication should be  </p><p>`    `unsuccessful at the supplicant.</p><p>2. Port should be unauthorized at </p><p>`    `the authenticator.</p><p>3. Packets should not reach the </p><p>`    `Linux VM.</p>|
|**3**|**Image Upgrade on 7716 Board**|Local authentication should be successful after the image upgrade.|
|**4**|**Warm Reboot on 7716 Board**|Local authentication should be successful after warm reboot.|
|**5**|**Cold Reboot on 7716 Board**|Local authentication should be successful after cold reboot.|
|**6**|**Local Authentication - Trigger Validation** |Trigger Validation – Local authentication should be successful when the NAC admin state is UP and interrupted when state is DOWN. It should be able to send traffic successfully once the state is UP again. |


**Test 3# NAC Save and Reload Functionality:**

**Test Objective:** The purpose of the test is to verify the save and reload functionality on the PNAC based configurations done. 

**Topology:** PNAC Test Topology 

**Related CLI Commands:**

|**Command**|**Comment**|
| :-: | :-: |
|**Save Configuration Command**||
|config save -y|To save the NAC related configurations|
|**Reload Configuration Command**||
|config reload -y|To reload the NAC related configurations|
**Test Case (4.1): Save Functionality:**

**Test Steps:**

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Enter the save configuration command. The save configuration command should save all the configuration changes done on the authenticator.

**Test Case (4.2): Reload Functionality:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Enter the reload configuration.

\3. Verify if the NAC configurations related to the PNAC setup which were saved are loaded and ensure the working of port-based NAC on local authentication using show nac and show running configuration command. 

**Test Case (4.3): Syslog Functionality:**

**Test Steps:** 

\1. Log in to the switch with preloaded PNAC supported SONiC image.

\2. Enter the syslog path at the authenticator.

\3. Verify if the PNAC based local authentication is successful or not at the authenticator by accessing the saved syslogs. 

|**S. NO**|**Test Description**|**Expected Result**|
| :-: | :-: | :-: |
|**1**|**To save NAC related configurations**|All NAC related configurations done must be saved.|
|**2**|**To reload NAC related configurations**|All NAC related saved configurations must be reloaded when required and local authentication should be working.|
|**3**|**To verify the syslog for the authentication results**|The status of the PNAC based authentication must be verified using syslogs.|

**Appendix:**

**Pre-Requisite:**

**Supplicant Configuration File: “**wpa\_supplicant.conf**”**

#Access Point with Background Scanning

ap\_scan=0 

fast\_reauth=1

network={

#Service Set Identifier

ssid="" 

scan\_ssid=0

\# Authentication protocol to allow access to networks

key\_mgmt=IEEE8021X 

\# Password-based and one-way authentication protocol

eap=MD5 

identity="user"

password="password"

}

**Hostapd Configuration File:**

\# Arbitrary RADIUS attributes can be added into Access-Accept packets similarly

\# to the way radius\_auth\_req\_attr is used for Access-Request packet in

\# hostapd.conf. For EAP server, this is configured separately for each user

\# entry with radius\_accept\_attr=<value> line(s) following the main user entry

\# line.

\# Phase 1 users

"user"          MD5     "password"

"test user"     MD5     "secret"

"example user"  TLS

"DOMAIN\user"   MSCHAPV2        "password"

"gtc user"      GTC     "password"

"pax user"      PAX     "unknown"

"pax.user@example.com"  PAX     0123456789abcdef0123456789abcdef

"psk user"      PSK     "unknown"

"psk.user@example.com"  PSK     0123456789abcdef0123456789abcdef

"sake.user@example.com" SAKE    0123456789abcdef0123456789abcdef0123456789abcdeff

0123456789abcdef

"ttls"          TTLS

"not anonymous" PEAP

\# Default to EAP-SIM and EAP-AKA based on fixed identity prefixes

"0"\*            AKA,TTLS,TLS,PEAP,SIM

"1"\*            SIM,TTLS,TLS,PEAP,AKA

"2"\*            AKA,TTLS,TLS,PEAP,SIM

"3"\*            SIM,TTLS,TLS,PEAP,AKA

"4"\*            AKA,TTLS,TLS,PEAP,SIM

"5"\*            SIM,TTLS,TLS,PEAP,AKA

"6"\*            AKA'

"7"\*            AKA'

"8"\*            AKA'

\# Phase 2 (tunnelled within EAP-PEAP or EAP-TTLS) users

"t-md5"         MD5     "password"      [2]

"DOMAIN\t-mschapv2"     MSCHAPV2        "password"      [2]

"t-gtc"         GTC     "password"      [2]

"not anonymous" MSCHAPV2        "password"      [2]

"user"          MD5,GTC,MSCHAPV2        "password"      [2]

"test user"     MSCHAPV2        hash:000102030405060708090a0b0c0d0e0f   [2]

"ttls-user"     TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,TTLS-MSCHAPV2    "password"

[2]

\# Default to EAP-SIM and EAP-AKA based on fixed identity prefixes in phase 2

"0"\*            AKA     [2]

"1"\*            SIM     [2]

"2"\*            AKA     [2]

"3"\*            SIM     [2]

"4"\*            AKA     [2]

"5"\*            SIM     [2]

"6"\*            AKA'    [2]

"7"\*            AKA'    [2]

"8"\*            AKA'    [2]


**Related documents:**

|**Document**|**Link**|
| :-: | :-: |
|HLD document||
|||

