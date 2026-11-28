# HWSFLOW mirror session sampling test plan

## Rev 0.1

- [1 Revision](#1-revision)
- [2 Overview](#2-overview)
- [3 Scope](#3-scope)
- [4 Testbed](#4-testbed)
- [5 Setup](#5-setup)
- [6 Checks](#6-checks)
- [7 Test cases](#7-test-cases)

## 1 Revision

| Rev | Date       | Author        | Change Description |
|:---:|:----------:|:--------------|:-------------------|
| 0.1 | 11/24/2026 | Darius Grassi | Initial version    |

## 2 Overview

An `HWSFLOW` mirror session makes the ASIC build sFlow datagrams and send them to a collector.
The session sets the collector address, the UDP ports, the sample rate and the truncate size.
`PORT_MIRROR_SAMPLE` bindings attach source ports and PortChannels to the session. A binding sets no sample rate or truncate size.

```
MIRROR_SESSION|hws0                      PORT_MIRROR_SAMPLE|Ethernet100|rx
    type          = HWSFLOW                  mirror_session = hws0
    src_ip        = 10.1.0.32                admin_state    = up
    dst_ip        = 10.20.0.33
    dscp, ttl
    udp_src_port, udp_dst_port   (optional, default 6343)
    sample_rate   = 16           (mandatory)
    truncate_size = 128          (optional)
```

The test uses the fixtures of the sampled ERSPAN test (`test_erspan_sampling_truncation.py`) for port selection, routes and cleanup.

## 3 Scope

The test checks the datapath of a running SONiC switch:

- The datagrams reach the collector with the configured addresses and UDP ports.
- Each flow sample reports the rate of its session.
- The sampled header is cut to the truncate size.
- The number of samples agrees with the rate.
- A PortChannel source samples on each member.
- A removed binding stops sampling. The other bindings continue.
- A disabled binding stops sampling. The other bindings continue. An enabled binding samples again at the session rate.

Out of scope: rejected configuration. The YANG, CLI and orchagent unit tests cover it.

## 4 Testbed

Topology: any. The DUT needs three routed paths to the PTF: a source, a second source and the collector path.

The test reads `STATE_DB SWITCH_CAPABILITY|switch` and skips on capability only:

| Key | Effect when not `true` |
|---|---|
| `MIRROR_SESSION_HWSFLOW_CAPABLE` | All cases skip |
| `PORT_INGRESS_SAMPLE_MIRROR_CAPABLE` | rx cases skip |
| `PORT_EGRESS_SAMPLE_MIRROR_CAPABLE` | tx case skips |
| `MIRROR_SESSION_TRUNCATION_CAPABLE` and `SAMPLEPACKET_TRUNCATION_CAPABLE` | The truncation case skips when both are not `true` |
| `LAG_INGRESS_SAMPLE_MIRROR_CAPABLE` | No skip. It selects where the test looks for the PortChannel binding in ASIC_DB: the LAG object or each member port |

The test also skips when:

- `SFLOW|global` exists. sFlow and sampled bindings cannot be configured together.
- `sflowtool` is not on the PTF.
- The DUT has no routed PortChannel apart from the collector path (PortChannel case only).

## 5 Setup

```
          probes                     sFlow datagrams
  PTF ----------------> DUT source port
  PTF ----------------> DUT second source port
  PTF <---------------- DUT collector path (route to dst_ip)
        tcpdump + sflowtool
```

## 6 Checks

| Level | Check |
|---|---|
| Datagram | sFlow version 5. Agent address = session `src_ip`. UDP source port = `udp_src_port`. UDP destination port = `udp_dst_port` |
| Flow sample | Sampling rate field = session `sample_rate` |
| Flow sample, rx | Input interface = SNMP ifIndex of the port that received the probe. For a PortChannel, that is the member port |
| Sampled header | Length = min(frame length, `truncate_size`). For rx, the bytes are the first bytes of the probe |
| Count | Number of samples within ±20% of probes / `sample_rate` |

## 7 Test cases

### 7.1 `test_hwsflow_port_source[rx|tx]`

1. Create a session with rate 16, truncate size 128, UDP source port 6400 and UDP destination port 6344.
2. Bind the source port in the test direction. When the port is a PortChannel member, the test binds the PortChannel.
3. Check CONFIG_DB: the session has the sample rate, the truncate size and the UDP ports. The binding has no `sample_rate` and no `truncate_size`.
4. Send 300-byte probes. For tx, send them into the second port so that the DUT routes them out of the source port.
5. Do all the checks in the Checks table.

### 7.2 `test_hwsflow_two_sessions_different_rates`

1. Create one session with rate 16 and one with rate 32, to the same collector.
2. Bind the source port to the first session and the second port to the second session, rx.
3. Send probes into both ports.
4. Check that the samples of each port report the rate of its session, and that each count agrees with that rate.

### 7.3 `test_hwsflow_portchannel_source`

1. Create a session with rate 16.
2. Bind a routed PortChannel, rx. The test uses the PortChannel with the most members.
3. Send probes into each member.
4. Check that each member gives samples at the session rate, with the correct count, and that each member reports its own ifIndex as the input interface.

### 7.4 `test_hwsflow_binding_admin_state`

1. Create a session with rate 16. Bind the source port and the second port, rx.
2. Disable the binding of the source port with `config mirror_session sample disable`.
3. Send probes into both ports.
4. Check that the source port gives no samples and that the second port gives the correct count.
5. Enable the binding with `config mirror_session sample enable`.
6. Send probes into both ports. Check that both ports give the correct count at the session rate.

### 7.5 `test_hwsflow_binding_remove`

1. Create a session with rate 16. Bind the source port and the second port, rx.
2. Remove the binding of the source port.
3. Send probes into both ports.
4. Check that the source port gives no samples and that the second port gives the correct count.
5. Remove the second binding and the session. Check that the number of mirror session and samplepacket objects in ASIC_DB is the same as before the test.
