# ECN Marking ACL Test Plan

- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)
  - [test_ecn_acl_control_plane](#test-case-1-control-plane)
  - [test_ecn_acl_data_plane](#test-case-2-data-plane)
- [TODO](#todo)

## Overview

Verify the `ECN_ACTION` ACL action, which rewrites the ECN field (the low 2 bits
of the IPv4 TOS / IPv6 Traffic Class byte) of matching packets in hardware, per
[RFC 3168](https://www.rfc-editor.org/rfc/rfc3168). `ECN_ACTION` takes a value in
`[0..3]` (`0`=Non-ECT, `1`=ECT(1), `2`=ECT(0), `3`=CE) and maps to the SAI
attribute `SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN`. See the
[ACL High Level Design](https://github.com/sonic-net/SONiC/blob/master/doc/acl/ACL-High-Level-Design.md)
for the feature design.

The test is implemented in
[`acl/test_ecn_acl.py`](../../tests/acl/test_ecn_acl.py); the data-plane packet
check runs in the PTF test
[`ecn_acl_ptftest.ECNMarkingTest`](../../ansible/roles/test/files/ptftests/ecn_acl_ptftest.py).

### Scope

The test verifies that an ingress `L3`/`L3V6` ACL rule carrying `ECN_ACTION` is
programmed to hardware (control plane) and that matching traffic is ECN-marked on
egress (data plane). It does not cover WRED/ECN congestion marking, which lives
under [`docs/testplan/ecn/`](ecn/).

### Testbed

Supported topologies: `t0`, `t1`, `t2`.

`ECN_ACTION` depends on SAI support for `SAI_ACL_ENTRY_ATTR_ACTION_SET_ECN`. The
test is gated by
[`conditional_mark`](../../tests/common/plugins/conditional_mark) to ECN-capable
ASIC generations (validated on Broadcom Tomahawk-5 and NVIDIA Spectrum-5) and is
skipped on platforms that do not advertise the capability.

## Setup configuration

No pre-configuration is required. The test discovers two routed uplink ports from
the minigraph (IPv4 preferred, else IPv6), applies an ingress ACL table and rule,
and removes them on teardown. The rule is applied via two parametrized methods:

- **operator** &ndash; `config acl add table` followed by a GCU
  `config apply-patch`, which also exercises the `sonic-acl` YANG `ECN_ACTION`
  leaf validation.
- **configdb** &ndash; a direct `CONFIG_DB` write (`sonic-cfggen --write-to-db`),
  isolating the orchagent / ASIC path from YANG and GCU.

Example rule &ndash; an `L3`/`L3V6` table bound to the ingress uplink, matching
UDP source port 5000, action `ECN_ACTION: 3` (CE):

```json
{
    "ACL_RULE": {
        "ECN_TEST|MARK_UDP_5000": {
            "PRIORITY": "9990",
            "L4_SRC_PORT": "5000",
            "ECN_ACTION": "3"
        }
    }
}
```

## Test cases

### Test case 1: control plane

`test_ecn_acl_control_plane`

#### Test objective

Verify the rule is accepted and programmed to hardware.

#### Test steps

- Apply the ECN rule via the **operator** and **configdb** methods.
- Verify `show acl rule` renders the action as `ECN: 3` (not the raw
  `ECN_ACTION` key) and the rule reports `Active`.

### Test case 2: data plane

`test_ecn_acl_data_plane`

#### Test objective

Verify matching traffic is ECN-marked in hardware.

#### Test steps

- PTF sends a routed UDP packet (source port 5000) with `ECN=0` to the DUT.
- Verify the packet forwarded out of the egress uplink has `ECN=3` (CE), with the
  rest of the packet unchanged.

## TODO

- ECN marking interaction with SRv6 forwarding (encap / decap / transit).
