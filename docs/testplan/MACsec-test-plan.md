<!-- omit in toc -->
# MACsec Test plan

- [Testbed](#testbed)
- [Configuration](#configuration)
  - [Dynamic Key(MKA)](#dynamic-keymka)
- [Test steps](#test-steps)
- [Test cases](#test-cases)
  - [Control plane](#control-plane)
    - [Check WPA Supplicant](#check-wpa-supplicant)
    - [Check APP DB](#check-app-db)
      - [Check the following fields in MACsec port table are consistent with configuration](#check-the-following-fields-in-macsec-port-table-are-consistent-with-configuration)
      - [Check the following fields in MACsec SC table and MACsec SA table are consistent](#check-the-following-fields-in-macsec-sc-table-and-macsec-sa-table-are-consistent)
    - [Check MKA session](#check-mka-session)
  - [Data plane](#data-plane)
    - [PTF to VM](#ptf-to-vm)
    - [Notes](#notes)
    - [VM to VM](#vm-to-vm)
  - [Functionality](#functionality)
    - [Rekey caused by Packet Number exhaustion](#rekey-caused-by-packet-number-exhaustion)
      - [Test Steps](#test-steps-1)
    - [Periodic Rekey](#periodic-rekey)
      - [Test steps](#test-steps-2)
    - [Primary/Fallback CAK](#primaryfallback-cak)
    - [PFC in MACsec](#pfc-in-macsec)
      - [Bypass mode](#bypass-mode)
      - [Encrypt mode](#encrypt-mode)
      - [Strict mode](#strict-mode)

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

## Configuration

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

## Test steps

1. Enable MACsec feature `sudo config feature state macsec enabled` on each device
2. Dispatches MACsec configuration to devices
3. Waiting 300 seconds for the MACsec session to negotiate.
4. Run every testcases
5. Remove all MACsec configuration on devices

## Test cases

### Control plane

#### Check WPA Supplicant

Check the process, `wpa_supplicant`, for the target port is running in the devices.

#### Check APP DB

##### Check the following fields in MACsec port table are consistent with configuration

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

##### Check the following fields in MACsec SC table and MACsec SA table are consistent

1. There should be a MACsec SA in MACsec SA table with the same AN of *encoding_an* in MACsec SC.
2. The count of ingress MACsec SA shouldn't lesser than the count of egress MACsec SA in the peer side.
3. The corresponding ingress and egress MACsec SA should have same *sak* and *auth_key*.
4. The *next_pn* of egress MACsec SA shouldn't lesser than the *lowest_acceptable_pn* of the corresponding ingress MACsec SA in the peer side.

#### Check MKA session

This checking is only for SONiC virtual switch to verify the implementation of virtual SAI. If the DUT is SONiC virtual switch, do this checking on the DUT. And if the neighbor devices(VM0 and VM1) are SONiC virtual switch, do this on the neighbor devices too.

1. Get the MKA session by `ip macsec show`
2. Check the MACsec session is consistent with configuration.

### Data plane

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

#### PTF to VM

This test is to verify the traffic is truly protected by MACsec.

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

3. Send a set of above packet on the PTF up port
4. The target VM should receive at least one expected above packet
5. In the injected port of PTF, we should get at least one expected packet encapsulated by MACsec

#### Notes

1. The number of send packet is 100 to avoid the send packet dropped by MACsec engine
2. Set the buffer queue of PTF to the 1000 to avoid the send packet dropped by PTF
3. We can decapsulate all MACsec packets by the SAK in the activated APP DB. Because the operation of decapsulation needs to take a long time which may cause we miss the expected packet, we collect all packets for 10 seconds firstly and decapsulate them one by one until the expected packet appearance.

#### VM to VM

This test is to verify a packet can be correctly forwarded between controlled nodes and uncontrolled nodes.

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

### Functionality

#### Rekey caused by Packet Number exhaustion

The thresholds of rekey packet number are `0xC0000000ULL` to 32bits packet number and `0xC000000000000000ULL` to 64bits packet number(XPN). So, to set the attribute `next_pn` of `MACSEC_EGRESS_SA` in APP_DB cheats MKA protocol for rekey action.

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

##### Test Steps

1. Start a background thread on the DUT to ping VM0 `sudo ping VM0_ipv4_address -w 60 -i 0.01` to simulate continuous traffic.
2. Record the SAK in APP DB.
3. Update the next_pn of egress SA to `threshold - 5000`.
4. Sleep for 30 seconds.
5. Check whether the SAK was changed. If no, sleep 6 seconds and check again until waiting more 10 times(60 seconds) and this test fail. If yes, this test pass.
6. The background thread shouldn't obverse the remarkable packet loss (packet loss lesser than 1%).

#### Periodic Rekey

This testcase is only available if the field *rekey_period* in configuration is more than 0.

##### Test steps

1. Start a background thread on the DUT to ping VM0 `sudo ping VM0_ipv4_address -w 60 -i 0.01` to simulate continuous traffic.
2. Record the SAK in APP DB.
3. Sleep for 30 seconds.
4. Check whether the SAK was changed. If no, sleep 6 seconds and check again until waiting more 10 times(60 seconds) and this test fail. If yes, this test pass.
5. The background thread shouldn't obverse the remarkable packet loss (packet loss lesser than 1%).

#### Primary/Fallback CAK

TODO

#### PFC in MACsec

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
