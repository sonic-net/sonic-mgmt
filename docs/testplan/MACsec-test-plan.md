# Testbed

```
+----------------------------------------------------------------------+
|                                                                      |
| DUT                                                                  |
|                                                                      |
+-----+----------------+----------------+----------------+-----------+-+
      |                |                |                |           |
      |                |                |                |           |
      +-----+          +-----+          +-----+          +-----+     |
      |     |          |     |          |     |          |     |     |
      |     |          |     |          |     |          |     |     |
  +---+---+ |      +---+---+ |      +---+---+ |      +---+---+ |     |
  |VM0    | |      |VM1    | |      |VM2    | |      |VM3    | |     |
  |       | |      |       | |      |       | |      |       | |     |
  +-------+ |      +-------+ |      +-------+ |      +-------+ |     |
            |                |                |                |     |
+-----------+----------------+----------------+----------------+-----+-+
|                                                                      |
| PTF                                                                  |
|                                                                      |
+----------------------------------------------------------------------+

```

In this topology, VMs (SONiC virtual Switch) act as the MACsec participant of the DUT. Each pair of MACsec participant belongs to different MACsec connectivity association(CA).
All VMs and PTF need to install PTF NN Server and SONiC-mgmt-docker need to install PTF NN Client. SONiC-mgmt-docker can use each PTF NN Server instance to send packets by PTF NN Client.

## Configuration

One VM(VM0) should have higher priority than DUT and others should have lower priority than DUT. This design is for two scenarios that whether DUT is correct when it's or not as the MACsec Key server.

# Test cases

## Control plane connectivity

### Test steps

1. Dispatches configuration to VMs and DUT
2. Reload config to establish MACsec connection

### Check points

To use `ip macsec show` in every VMs to check whether the MACsec connection has been created. We should find the following phenomena in each VM
- One MACsec device was created
- Two MACsec Security Channel(SC), Egress and Ingress SC, belong to the above device
- Each SC has one MACsec Security Association(SA)

Here is an example to demonstrate an expected output in VMs.

```
admin@sonic:~$ ip macsec show
112: macsec_eth1: protect on validate strict sc off sa off encrypt on send_sci on end_station off scb off replay off
    cipher suite: GCM-AES-128, using ICV length 16
    TXSC: 5254001234560001 on SA 0
        0: PN 4, state on, key c2c31ab98c04f55a7765f2efe22e8aa9
    RXSC: fe54002ace420001, state on
        0: PN 35, state on, key c2c31ab98c04f55a7765f2efe22e8aa9
```

## Data plane connectivity

We should test three scenarios

- VM to VM (Encrypted traffic to encrypted traffic)
- VM to PTF (Encrypted traffic to plaintext traffic)
- PTF to VM (plaintext traffic to encrypted traffic)

### Test steps

We assume the above test case, **[Control plane connectivity](##Control-plane-connectivity)**, passed so that we can directly use its configuration to verify the connectivity in data plane. 

1. Send a packet *P0* from *VM0* to *VM1* by SONiC-mgmt-docker PTF NN Client
2. Send a packet *P1* from *VM1* to *VM0* by SONiC-mgmt-docker PTF NN Client
3. Send a packet *P2* from *VM0* to *PTF regular port* by SONiC-mgmt-docker PTF NN Client
4. Send a packet *P3* from *VM1* to *PTF regular port* by SONiC-mgmt-docker PTF NN Client
5. Send a packet *P4* from *PTF regular port* to *VM0* by SONiC-mgmt-docker PTF NN Client
6. Send a packet *P5* from *PTF regular port* to *VM1* by SONiC-mgmt-docker PTF NN Client
7. Send a packet *P6* from *PTF injected port* to *VM0* by PTF

### Check point

1. *VM1's PTF injected port* should receive *the encrypted packet of P0*, and *VM1* should receive *the plaintext packet of P0*
2. *VM0's PTF injected port* should receive *the encrypted packet of P1*, and *VM0* should receive *the plaintext packet of P1*
3. *PTF regular port* should received *the plaintext packet of P2*
4. *PTF regular port* should received *the plaintext packet of P3*
5. *VM0's PTF injected port* should received *the encrypted packet of P4*, and *VM0* should received *the plaintext packet of P4*
6. *VM1's PTF injected port* should received *the encrypted packet of P5*, and *VM0* should received *the plaintext packet of P5*
7. *P6* should be dropped by DUT which means on one port can received any encrypted or plaintext packet of P6

## Rekey caused by Packet Number exhaustion

TODO

<!--

### Test steps

1. Recompile the wpa_supplicant to reduce the rekey threshold. (Maybe we can enhance the wpa_supplicant to make this threshold can be configurable)
2. Dispatches configuration
3. Reload config to establish MACsec connection
4. Get the MACsec information by `ip macsec show`
5. Send several ping packets to trigger the rekey action
6. Get a new MACsec information by `ip macsec show`

### Check point

1. These ping packets should be any lost
2. The new MACsec information should have different MACsec SA to the first MACsec information

-->

## Periodic Rekey

TODO

## Primary/Fallback CAK

TODO

## PFC in MACsec

![MACsec_PFC_test](images/MACsec_PFC_test.png)  

Use PTF to generate and capture PFC packets and set the same mode between DUT and Neighbor device.

### Bypass mode

1. Send clear PFC frame from the neighbor device to the DUT
   - The DUT expects to capture the clear PFC packet
2. Send clear PFC frame from the DUT to the neighbor device
   - The neighbor expect to capture the clear PFC packet
   - The inject port expects to capture the clear PFC packet
3. Send clear PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet
4. Send encrypted PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet

### Encrypt mode

1. Send clear PFC frame from the neighbor device to the DUT
   - The DUT expects to capture the clear PFC packet
2. Send clear PFC frame from the DUT to the neighbor device
   - The neighbor expect to capture the clear PFC packet
   - The inject port expects to capture the encrypted PFC packet
3. Send clear PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet
4. Send encrypted PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet

### Strict mode

1. Send clear PFC frame from the neighbor device to the DUT
   - The DUT expects to capture the clear PFC packet
2. Send clear PFC frame from the DUT to the neighbor device
   - The neighbor expect to capture the clear PFC packet
   - The inject port expects to capture the encrypted PFC packet
3. Send clear PFC frame on the PTF injected port
   - The DUT expects to no any PFC packet
4. Send encrypted PFC frame on the PTF injected port
   - The DUT expects to capture the clear PFC packet

