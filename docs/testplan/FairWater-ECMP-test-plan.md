## Technical Test Plan

### ECMP across Differing ASNs in SONiC Environment using FRR Docker

### Objective

Validate that the `bgp bestpath as-path multipath-relax` configuration in FRR, running as a docker within a SONiC environment, successfully enables Equal Cost Multi-Path (ECMP) routing for the same prefix advertised by multiple BGP peers with different ASNs.

### Background

In the FairWater deployment, backend ToR (Top-of-Rack) routers connect to frontend ToR routers via a low-speed 10G link. Backend ToR routers aggregate backend loopback prefixes and advertise them to frontend ToR routers using eBGP. It is critical to validate ECMP functionality over eBGP sessions; otherwise, all backend loopback prefixes may route through a single 10G link, which is undesirable.

### Test Environment

- SONiC device with FRR running inside a docker container.
- ExaBGP instances to simulate multiple eBGP peers with different ASNs.

### Test Cases

#### Test Case 1: Verify Configuration Presence

- **Step 1:** Access FRR docker CLI:

```
docker exec -it bgp bash
vtysh
```

- **Step 2:** Verify FRR BGP configuration:

```
show running-config | include multipath-relax
```

- **Expected Result:** Configuration displays:

```
bgp bestpath as-path multipath-relax
```

#### Test Case 2: ECMP Routing Verification

- **Step 1:** Configure two ExaBGP peers (ASNs 65001 and 65002) advertising the same prefix `1.1.1.1/32`.
- **Step 2:** Establish eBGP sessions between FRR in SONiC and these peers.
- **Step 3:** Verify the BGP routing table:

```
show ip bgp 1.1.1.1/32
```

- **Expected Result:** Routing table displays two active paths (ASNs 65001 and 65002), indicating multipath status.

- **Step 4:** Verify ECMP in SONiC forwarding table:

```
show ip route 1.1.1.1/32
```

- **Expected Result:** Routing table entry shows multiple next hops indicating ECMP.

#### Test Case 3: Traffic Load Distribution

- **Step 1:** Initiate traffic destined for `1.1.1.1/32`.
- **Step 2:** Capture traffic or statistics on each ExaBGP peer.
- **Expected Result:** Traffic is evenly distributed across both paths, confirming ECMP functionality.

### Test Cleanup

- None

### Notes

- Document any deviations, anomalies, or unexpected behavior observed during the tests.
- Capture relevant logs and command outputs for validation purposes.

### Success Criteria

- `bgp bestpath as-path multipath-relax` configuration is present and effective.
- ECMP is successfully enabled across differing ASNs.
- Traffic load is balanced across multiple paths as expected.

