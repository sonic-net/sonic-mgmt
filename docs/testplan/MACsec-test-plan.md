<!-- omit in toc -->
# MACsec Test plan


- [Testbed](#testbed)
- [Common Configuration](#common-configuration)
  - [Dynamic Key(MKA)](#dynamic-keymka)
- [Common test steps](#common-test-steps)
- [Test cases](#test-cases)
  - [Testcase : Macsec Functionality](#testcase--macsec-functionality)
    - [Check Control plane](#check-control-plane)
    - [Check the Data plane](#check-the-data-plane)
    - [Rekey caused by Packet Number exhaustion](#rekey-caused-by-packet-number-exhaustion)
    - [MACsec Key rotation, Primary/Fallback CAK](#macsec-key-rotation-primaryfallback-cak)
  - [Testcase : Macsec interop with other slow protocols](#testcase--macsec-interop-with-other-slow-protocols)
    - [Verify Port Channel remains up with macsec configuration.](#verify-port-channel-remains-up-with-macsec-configuration)
    - [Verify LLDP neighbors are created with macsec configuration.](#verify-lldp-neighbors-are-created-with-macsec-configuration)
    - [Verify the BGP neighbourship is created with macsec configuration.](#verify-the-bgp-neighbourship-is-created-with-macsec-configuration)
    - [Verify PFC in MACsec](#verify-pfc-in-macsec)
      - [Bypass mode](#bypass-mode)
      - [Encrypt mode](#encrypt-mode)
      - [Strict mode](#strict-mode)
    - [Verify SNMP request/response works across interface with macsec configuration.](#verify-snmp-requestresponse-works-across-interface-with-macsec-configuration)
  - [Testcase : Deployment usecases and fault handling scenario's](#testcase--deployment-usecases-and-fault-handling-scenarios)
    - [Link flap on an interface with macsec configured.](#link-flap-on-an-interface-with-macsec-configured)
    - [Link flap of a portchannel member which has macsec configured.](#link-flap-of-a-portchannel-member-which-has-macsec-configured)
    - [MACsec session cannot be established under wrong MKA configuration](#macsec-session-cannot-be-established-under-wrong-mka-configuration)
    - [Config reload done on DUT with macsec configuration](#config-reload-done-on-dut-with-macsec-configuration)
    - [COPP](#copp)
    - [Everflow, port mirroring on macsec enabled interfaces.](#everflow-port-mirroring-on-macsec-enabled-interfaces)
  - [Testcase : Scale tests](#testcase--scale-tests)
    - [Enable macsec on all interfaces on the DUT/linecard](#enable-macsec-on-all-interfaces-on-the-dutlinecard)
    - [Rekeying in all macsec sessions happens at the same time](#rekeying-in-all-macsec-sessions-happens-at-the-same-time)
    - [Macsec enabled on all interfaces and the DUT is rebooted.](#macsec-enabled-on-all-interfaces-and-the-dut-is-rebooted)

## Testbed

```txt
+-------------------------------------------------------------------------+
|                                                                         |
| DUT                                                                     |
|                                                                         |
+-------+-------------------+-----------------+--------------+----------+-+
        *                   *                 |              |          |
        *                   *                 |              |          |
        *.........          *.........        +......        +......    |
        *        :          *        :        |     :        |     :    |
        *        :          *        :        |     :        |     :    |
  +-----+------+ :    +-----+------+ :    +---+---+ :    +---+---+ :    |
  |VM0         | :    |VM1         | :    |VM2    | :    |VM3    | :    |
  |(Controlled)| :    |(Controlled)| :    |       | :    |       | :    |
  +------------+ :    +------------+ :    +-------+ :    +-------+ :    |
                 :                   :              :              :    |
+----------------+-------------------+--------------+--------------+----+-+
|                                                                         |
| PTF                                                                     |
|                                                                         |
+-------------------------------------------------------------------------+


-----       normal link
.....       injected link
*****       protected link
VM<->DUT    up link
PTF<->DUT   down link
```

In this topology, We pick two VMs (MACsec support) that act as the MACsec participants of the DUT. These two pairs of MACsec participant belong to different MACsec connectivity association(CA).

## Common Configuration

### Dynamic Key(MKA)

***MACsec profile table***

| Field                 |                                                              Value                                                              |
| --------------------- | :-----------------------------------------------------------------------------------------------------------------------------: |
| priority              |                                                  DUT(*64*) VM0(*63*) VM1(*65*)                                                  |
| cipher suite          |                                                   *GCM-AES-128*/*GCM-AES-256*                                                   |
| CKN                   |                               *6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435*                                |
| CAK                   | GCM-AES-128(*0123456789ABCDEF0123456789ABCDEF*)/GCM-AES-256(*0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF*) |
| policy                |                                                   *integrity_only*/*security*                                                   |
| enable_replay_protect |                                                         *true*/*false*                                                          |
| replay_window         |                                    enable_replay_protect(*0*)/disable_replay_protect(*100*)                                     |
| send_sci              |                                                         *true*/*false*                                                          |
| rekey_period          |                                                            *0*/*30*                                                             |

***Port table***
| Field               |                Value                |
| ------------------- | :---------------------------------: |
| pfc_encryption_mode | *bypass*/*encrypt*/*strict_encrypt* |

All combination of values will be picked as a separated test group.

## Common test steps

This is a common set of steps for each of the testcase

1. Enable MACsec feature `sudo config feature state macsec enabled` on each device
2. Dispatches MACsec configuration to devices, as per testcase
3. Waiting 300 seconds for the MACsec session to negotiate.
4. Verify the functionality as per testcase
5. Remove all MACsec configuration on devices

## Test cases

### Testcase : Macsec Functionality
This testcase covers the macsec/MKA protocol functionality

#### Check Control plane

- Enable macsec on the interface on the DUT and remote VM.
- Check the process, `wpa_supplicant`, for the target port is running in the devices.
- Check APP DB, Check the following fields in MACsec port table are consistent with configuration

    | Config DB Field | Config DB Value |  App DB Field  | APP DB Value |
    | :-------------: | :-------------: | :------------: | :----------: |
    |                 |                 |     enable     |     true     |
    |  cipher_suite   |   GCM-AES-128   |  cipher_suite  | GCM-AES-128  |
    |  cipher_suite   |   GCM-AES-256   |  cipher_suite  | GCM-AES-256  |
    |                 |                 | enable_protect |     true     |
    |     policy      |    security     | enable_encrypt |     true     |
    |     policy      | integrity_only  | enable_encrypt |    false     |
    |    send_sci     |      true       |    send_sci    |     true     |
    |    send_sci     |      false      |    send_sci    |    false     |

- Check the following fields in MACsec SC table and MACsec SA table are consistent

    1. There should be a MACsec SA in MACsec SA table with the same AN of *encoding_an* in MACsec SC.
    1. The count of ingress MACsec SA shouldn't be lesser than the count of egress MACsec SA in the peer side.
    2. The corresponding ingress and egress MACsec SA should have same *sak* and *auth_key*.
    1. The *next_pn* of egress MACsec SA shouldn't be lesser than the *lowest_acceptable_pn* of the corresponding ingress MACsec SA in the peer side.

- Check MKA session

    1. Get the MKA session by `ip macsec show`
    2. Check the MACsec session is consistent with configuration.

  Note: This checking is only for SONiC virtual switch to verify the implementation of virtual SAI. If the DUT is SONiC virtual switch, do this checking on the DUT. And if the neighbor devices(VM0 and VM1) are SONiC virtual switch, do this on the neighbor devices too.

#### Check the Data plane

```txt
+-----------------------------------------------------------------------------------+
|                                                                                   |
| DUT                                                                               |
|                                                                                   |
+-------+-------------------+-------------------+-------------------+-------------+-+
        *                   *                   |                   |             |
        *                   *                   |                   |             |
        *.........          *.........          +.........          +.........    |
        *        :          *        :          |        :          |        :    |
        *        :          *        :          |        :          |        :    |
  +-----+------+ :    +-----+------+ :    +-----+------+ :    +-----+------+ :    |
  |VM0         | :    |VM1         | :    |VM2         | :    |VM3         | :    |
  |(Controlled)| :    |(Controlled)| :    |            | :    |            | :    |
  |ptf_nn_agent| :    |ptf_nn_agent| :    |ptf_nn_agent| :    |ptf_nn_agent| :    |
  +------------+ :    +------------+ :    +------------+ :    +------------+ :    |
                 :                   :                   :                   :    |
+----------------+-------------------+-------------------+-------------------+----+-+
|                                                                                   |
| PTF (ptf_nn_agent)                                                                |
|                                                                                   |
+-----------------------------------------------------------------------------------+

-----       normal link
.....       injected link
*****       protected link
VM<->DUT    up link
PTF<->DUT   down link
```

All VMs and PTF docker in the host need to install PTF NN agent. So, SONiC-mgmt-docker can use an unified interface, ptf_nn_client, to handle the packets sending operation in the servers and VMs.

- Check PTF to VM traffic. Verify the traffic is truly protected by MACsec.

    1. Send IPv4 packet

    |   Field   |      Value      |
    | :-------: | :-------------: |
    | ether dst | DUT mac address |
    |  ip src   |     1.2.3.4     |
    |  ip dst   | VM ipv4 address |
    |  ip ttl   |       64        |

    2. Expected IPv4 packet

    |   Field   |      Value      |
    | :-------: | :-------------: |
    | ether src | DUT mac address |
    | ether dst | VM mac address  |
    |  ip src   |     1.2.3.4     |
    |  ip dst   | VM ipv4 address |
    |  ip ttl   |       63        |

    3. Send a set of above packet on the down link of DUT
    4. The target VM should receive at least one expected above packet
    5. In the injected port of PTF, we should get at least one expected packet encapsulated by MACsec

    **Notes**
      1. The number of send packet is 100 to avoid the send packet dropped by MACsec engine or others.
      2. Set the buffer queue of PTF to the 1000 to avoid the send packet dropped by PTF
      3. We can decapsulate all MACsec packets by the activated SAK in the APP DB. Because the operation of decapsulation needs to take a long time which may cause we miss the expected packet, we collect all packets for 10 seconds firstly and decapsulate them one by one until the expected packet appearance.

- Check VM to VM traffic, This test is to verify a packet can be correctly forwarded between controlled nodes and uncontrolled nodes.
  In the following statement, we assume we send packet from VM(0) to VM(1). But in the real test, we will test all directions from VM(x) to VM(non-x)

    1. Send IPv4 packet

    |   Field   |      Value       |
    | :-------: | :--------------: |
    | ether dst | DUT mac address  |
    |  ip src   | VM0 ipv4 address |
    |  ip dst   | VM1 ipv4 address |
    |  ip ttl   |        64        |

    2. Expected IPv4 packet

    |   Field   |      Value       |
    | :-------: | :--------------: |
    | ether dst | DUT mac address  |
    | ether dst | DUT mac address  |
    |  ip src   | VM0 ipv4 address |
    |  ip dst   | VM1 ipv4 address |
    |  ip ttl   |        63        |

    3. Send a set of above packet on the VM0
    4. VM1 should receive at least one expected above packet
    5. Check the interface stats with macsec counters.

#### Rekey caused by Packet Number exhaustion

The thresholds of rekey packet number are `0xC0000000ULL` to 32bits packet number and `0xC000000000000000ULL` to 64bits packet number(XPN). It's impossible to really send many packets to trigger the rekey action. So, We use the attribute `next_pn` of `MACSEC_EGRESS_SA` in APP_DB to cheat MKA protocol for rekey action.

```txt https://asciiflow.com/#/share/eJzNU91qgzAUfpWR6xZ0uxgTdiHOlV7MDbWwi0DINFSZRomRVUrfYuxhxp5mTzI3Oig1SuJPaTgX8STfd75z%2FLIFFKcEGLRMkhlIcEUYMMAWgg0Exo1%2BNYOgqneX13q942TD6w8ILo7W9%2FuXUkBIBRSNRNu1IqNxME%2FXKe%2B8JsU2VHcLO61HhXJ6yyNGiihLwrmuaVoHvo%2Bc4aqFs5IYnBj%2FlmNUlHmexAGmXB3fu%2F6Y8fEpNbUu5dOjGXkl1eEJZ5gWaczR3njnpl44YtH095sGZpDbG2LbrdfNgPMchS9NhiArKSfs72xKDUqhjlHwvnidGXb%2FGE5cVdbrh%2F9JmllGYic6Y0GE14Ty%2F4RnLtGDaXm2hTwTmb7vImvlurbjo%2BcnZxIZyjaWY26X0sCKmn507peLlWvfIXvh2p732%2F64VUfFqtpslJCyg3Ifx6miokHYH65Y%2FfQBwQ7sfgAV2TM0)
                ┌──────────────┐
                │              │
                │  sonic-mgmt  │
                │              │
                └────┬─────────┘
                     │
            next_pn=threshold-5000
                     │    ┌───────────────────────────┐
                     │    │                           │
                     │    │       wpa_supplicant      │
                     │    │                           │
                     │    └─────────────────────────▲─┘
                     │        *                     │
                     │        *                     │
                     │      rekey            transmit_next_pn
                     │        *                     │
                     │        *                     │
                 ┌───▼────────▼─┐    ┌──────────────┴─┐
                 │              │    │                │
                 │    app_db    │    │    counter_db  │
                 │              │    │                │
                 └───┬──────────┘    └──────────────▲─┘
                     │                              │
                     │                              │
                     │                              │
      MACSEC_EGRESS_SA:next_pn                      │
                     │                              │
                 ┌───▼──────────┐                   │
                 │              │                   │
                 │   orchagent  │   SAI_MACSEC_SA_ATTR_CURRENT_XPN
                 │              │                   │
                 └───┬──────────┘                   │
                     │                              │
SAI_MACSEC_SA_ATTR_CONFIGURED_EGRESS_XPN            │
                     │                              │
                     │                              │
                 ┌───▼──────────────────────────────┴──┐
                 │                                     │
                 │                syncd                │
                 │                                     │
                 └─────────────────────────────────────┘
```

    1. Start a background thread on the DUT to ping VM0 `sudo ping VM0_ipv4_address -w 60 -i 0.01` to simulate continuous traffic.
    2. Record the SAK in APP DB.
    3. Update the next_pn of egress SA to `threshold - 5000`.
    4. Sleep for 30 seconds.
    5. Check whether the SAK was changed. If no, sleep 6 seconds and check again until waiting more 10 times(60 seconds) and this test fail. If yes, this test pass.
    6. The background thread shouldn't obverse any packet loss.

- Periodic Rekey, this testcase is only available if the field *rekey_period* in configuration is more than 0.
    1. Start a background thread on the DUT to ping VM0 `sudo ping VM0_ipv4_address -w 60 -i 0.01` to simulate continuous traffic.
    2. Record the SAK in APP DB.
    3. Sleep for 30 seconds.
    4. Check whether the SAK was changed. If no, sleep 6 seconds and check again until waiting more 10 times(60 seconds) and this test fail. If yes, this test pass.
    5. The background thread shouldn't obverse any packet loss.

#### MACsec Key rotation, Primary/Fallback CAK
   TODO

 
### Testcase : Macsec interop with other slow protocols 
  This testcase covers the behavior of slow protocols when mac security is configured on interfaces 

#### Verify Port Channel remains up with macsec configuration.
  1. Configure the macsec profile on interfaces and add them as members of a Portchannel
  2. Check the behaviour when macsec is enabled on member interfaces of a portchannel is already UP.
 
#### Verify LLDP neighbors are created with macsec configuration.
  1. Configure the macsec profile on interface and check if the LLDP neighbors are created.
  2. Check the LLDP meighbors is present after removal of macsec config.
  3. Check the behaviour when macsec is enabled on an interface where LLDP neighborship was already present.

#### Verify the BGP neighbourship is created with macsec configuration.
  1. Configure the macsec profile on interface and check if the BGP sessions are etablished.
  2. Check the BGP sessions are present after removal of macsec config.
  3. Check the behaviour when macsec is enabled on an interface where BGP session was already up with peer.

#### Verify PFC in MACsec

![MACsec_PFC_test](images/MACsec_PFC_test.png)  

Use PTF to generate and capture PFC packets and set the same mode between DUT and Neighbor device.

##### Bypass mode

1. Send clear PFC frame from the neighbor device to the DUT
   - The DUT expects to capture the clear PFC packet
2. Send clear PFC frame from the DUT to the neighbor device
   - The neighbor expect to capture the clear PFC packet
   - The inject port expects to capture the clear PFC packet
3. Send clear PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet
4. Send encrypted PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet

##### Encrypt mode

1. Send clear PFC frame from the neighbor device to the DUT
   - The DUT expects to capture the clear PFC packet
2. Send clear PFC frame from the DUT to the neighbor device
   - The neighbor expect to capture the clear PFC packet
   - The inject port expects to capture the encrypted PFC packet
3. Send clear PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet
4. Send encrypted PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet

##### Strict mode

1. Send clear PFC frame from the neighbor device to the DUT
   - The DUT expects to capture the clear PFC packet
2. Send clear PFC frame from the DUT to the neighbor device
   - The neighbor expect to capture the clear PFC packet
   - The inject port expects to capture the encrypted PFC packet
3. Send clear PFC frame on the PTF injected port
   - The DUT expects to no any PFC packet
4. Send encrypted PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet

#### Verify SNMP request/response works across interface with macsec configuration.
  Configure the macsec profile on interface and check if the snmp walk succeeds from the peer VM.

### Testcase : Deployment usecases and fault handling scenario's
  This testcase covers the various fault scenario's and the expected behavior.

#### Link flap on an interface with macsec configured.
  - MKA session can be recovered from the link flap if the port remains up for less than 6 secs (MKA protocol timeout)
  - If the port is down for more than 6 sec, MKA session will create a new session.

#### Link flap of a portchannel member which has macsec configured.
  Consider case when
    - this interface is the only member of portchannel
    - the portchannel has more member ports, all macsec enabled - and one of the member port flaps.
    - Portchannel behaviour when there is a mismatch of config in member interfaces.
 
#### MACsec session cannot be established under wrong MKA configuration
  1. If the CAK is mis-matched, the MACsec cannot be established.
  2. In this scenario, check the behaviour of interface state, If the interface status stays UP,
     how is control plane protocols eg: BGP will behave ? The session will not be established.

#### Config reload done on DUT with macsec configuration
  1. The macsec sessions to come back up.
  2. The protocols on top like LACP, LLDP, BGP have all the sessions up.

#### COPP
  TODO

#### Everflow, port mirroring on macsec enabled interfaces.
  TODO

### Testcase : Scale tests

#### Enable macsec on all interfaces on the DUT/linecard
  1. Check the CPU, ASIC behavior when there are multiple wpa_supplicant processes being spawned.
  2. When all the interfaces flap together, how much time it takes for Portchannels/BGP sessions to be up

#### Rekeying in all macsec sessions happens at the same time
  Check the sessions are all up.

#### Macsec enabled on all interfaces and the DUT is rebooted.
  Check the macsec docker comes up and macsec sessions are established.
