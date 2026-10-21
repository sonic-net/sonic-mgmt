# Dynamic HWSKU and Generic Topology

**SONiC | Three-page design summary | Draft v0.1**

October 21, 2026 | Proposed architecture; not implemented or lab-validated

## 1. Goal and overall flow

Generate one mixed-breakout testbed and its logical network without editing
`links.csv` for each setup. Reuse the complete flow across supported DUTs through
capability adapters, rather than hard-coded port names or vendor commands.

Dynamic HWSKU means selecting a supported operational port layout within the
existing platform/base-HwSKU environment. Dynamic topology means assigning
forwarding roles, addresses, VLANs, routes, and traffic mappings to those resulting
ports.

| Input | Responsibility |
| --- | --- |
| Unchanged maximum-breakout `links.csv` | Physical connections and existing lab-transport VLAN information |
| DUT and peer capability data | Supported modes, child/lane layouts, and hardware constraints |
| Existing `pg_profile_lookup.ini` | Valid speed/cable cases for the lookup-backed buffer policy |
| Shared recipe and inventory policy | Logical groups, address/VLAN defaults, overrides, and exclusions |

```text
Discover and normalize
          |
Dynamically generate breakout, peers, cable cases, and logical roles
          |
Generate configuration candidates and effective topology
          |
     Validate
          |
Accept/persist, or restore both affected ends and mappings
```

Normalization creates one consistent model. Example: a CSV row written
`leaf-X -> DUT` is represented in the same `DUT -> peer` form as its reverse.
Preserve evidence and explicit channel connections; never infer wiring from
Ethernet numbers.

Initial scope: one DUT and one selected forwarding ASIC. For the discussed
testbed, only eligible Mellanox-connected resources participate;
Arista-connected DUT resources remain unchanged. The common engine must not
hard-code that vendor restriction.

## 2. Breakout, cable coverage, and topology

### Generate a feasible mixed layout

Select breakout per physical parent cage/group, then assign configured cable
lengths to the resulting child interfaces. Coordinate compatible peer groupings
through the actual wiring. Validate module, speed, FEC/AN, shared-resource,
protection, and buffer-capacity constraints.

Cover every required supported mode and every required existing lookup pair.
Repeat a mode across additional cages when more children are needed. Do not
manufacture missing lookup rows or silently drop cases.

| Cage | Mode | Child 0 | Child 1 |
| --- | --- | --- | --- |
| A | `2x200G` | 200G / 5m | 200G / 40m |
| B | `2x200G` | 200G / 30m | 200G / 5m (repeat) |

Illustrative only: three required cases need at least two two-child cages for
this placement. Other required modes also need resources. If one layout cannot
fit everything, report why; extra runs require an explicit decision. Configured
lengths are buffer inputs, not physical cable changes.

### Build the logical network

A shared recipe requests routed/access groups and explicit uplink/downlink
policy groups. The allocator chooses eligible generated ports; it does not
require per-DUT Ethernet lists. Interface mode and link role remain independent.

The proposed `ansible\vars\topo_generic.yml` stores shared allocation defaults.
Explicitly merge group overrides, then host overrides, at field level. Generate
final assignments separately; never overwrite the shared file.

| Item | Illustrative allocation |
| --- | --- |
| Routed Ethernet0 | DUT 192.0.2.0/31; traffic next hop 192.0.2.1 |
| Routed Ethernet4 | DUT 192.0.2.2/31; traffic next hop 192.0.2.3 |
| Access group | VLAN 1000; one SVI at 198.51.100.1/24; endpoint addresses from that pool |
| Static-route destination | 203.0.113.1/32 via 192.0.2.1 on Ethernet0 |

Use reserved, non-conflicting pools sized for the layout. The CSV transport VLAN
is not the DUT access VLAN. Provision traffic endpoints and mappings together
with DUT configuration; do not assume the intervening leaf owns the endpoint IPs.
