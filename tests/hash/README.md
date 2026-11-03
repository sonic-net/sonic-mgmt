# Generic hash test prerequisites

The configurable hash module is `test_generic_hash.py`. Its static capability
lists describe expected SONiC/SAI advertisements, not proof of dataplane
programming or packet distribution.

## Collection

Run `test_pretest.py::test_update_testbed_metadata` for the selected testbed and
DUTs before executing VPP `t1-lag` hash tests. Collection does not query a DUT:
it preserves the legacy default capabilities when metadata is absent, so the
hosted offline collection job remains supported. When selected-DUT metadata
identifies VPP on `t1-lag`, it must identify all selected DUTs consistently.
Unselected inventory DUTs do not need metadata.

Before VPP `t1-lag` test execution changes configuration, the recovery fixture
uses the actual DUT ASIC type to require matching VPP metadata for the selected
DUTs. Missing, empty, unknown or stale non-VPP metadata fails before traffic or
hash configuration. Other topologies retain legacy metadata selection and
hash-only restoration. Refresh conditional-mark facts (`--cache-clear`) and
regenerate metadata after changing the testbed or image. Topology names alone
do not establish ASIC identity: `TestbedInfo` normalizes `t1-lag-vpp` to `t1-lag`.

For VPP, `--reboot all` selects `cold` and `reload`. Explicit unsupported reboot
types, including `warm` and `fast`, are rejected during setup of the selected
VPP `t1-lag` reboot case, before hash configuration changes. Collection and
non-reboot selections do not reject that irrelevant option, and other
topologies retain their existing explicit reboot handling.

With valid VPP metadata, the current all-option matrix has 83 nodes:

| Cases | Parameters | Nodes |
| --- | --- | ---: |
| ECMP, LAG, combined, nexthop flap, member flap, member remove/add | Five fields, CRC, IPv4/IPv6 | 60 |
| Reboot | The same fields and families, cold/reload | 20 |
| Capability, backend errors, algorithm configuration | Not parameterized | 3 |

The default options select random parameters, not this full matrix. The five
fields are `IP_PROTOCOL`, `SRC_IP`, `DST_IP`, `L4_SRC_PORT`, and `L4_DST_PORT`.
Inner fields, L2 fields, alternate algorithms, and warm/fast reboot are not part
of VPP's generated matrix. Inner-aware transit hashing and policy-based hashing
are separate features; their implementation does not establish support for
configurable generic-hash fields.

## VPP enablement gate

VPP uses fixed dataplane field selections; independent ECMP/LAG configuration
tests remain skipped. For the enabled `t1-lag` scope, its four address/port fields are checked for both ECMP
and LAG balance. `IP_PROTOCOL` contributes ECMP entropy, but not LAG-member
entropy for the protocol-only packets generated here. Combined, nexthop, and
reboot cases explicitly check ECMP balance **and exactly one receiving member
per LAG** for that field. Their JUnit property and PTF parameters identify this
scope. Protocol-only LAG-member flap/remove cases are skipped precisely; those
operations still run with all four address/port fields. The 83 collected IDs
remain unchanged (24 unsupported cases, 59 runnable with all options).

SAI's `SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST` capability query and SWSS's
`HASH|NATIVE_HASH_FIELD_LIST` advertisement are shared between ECMP and LAG.
The capability case validates that advertisement, not two independently
programmable dataplane capabilities. The test does not remove `IP_PROTOCOL`
from the shared advertisement or add a VPP hashing feature to satisfy an
incorrect LAG expectation.

Only VPP on normalized topology `t1-lag` is excluded from the module, capability,
algorithm, and backend-error xfails. T0 VPP and other ASICs retain their marks.
Passing VPP `t1-lag` cases must produce real PASS, not XPASS.
Algorithm configuration checks control-plane readback of the sole
advertised CRC algorithm, not dataplane algorithm switching. An allowlist
entry is not execution evidence.

### Finite protocol-domain contract

On VPP `t1-lag` only, plain `IP_PROTOCOL` traffic exhausts the existing eligible
protocol domain: values 0 through 254 excluding 2, 4, 6, 17, 41, 253 and 254,
and also excluding 0 for IPv6 (248 IPv4 / 247 IPv6 distinct flows).
Those exclusions preserve the existing packet/parser constraints; this is not
a claim about all 256 protocol values. Source/destination addresses, payload,
transport bytes and ingress port stay fixed. Three complete passes, alternating
forward/reverse order, must deliver every packet without retransmission and
keep every protocol on the same receiving port. After each expected packet,
a 100 ms packet-specific negative check rejects additional matching copies on
any PTF port before sending the next protocol. This check remains active under
`ptf_runner`'s `--relax` mode and ignores unrelated background packets. It adds
about 74 seconds per complete IPv4 or IPv6 protocol-domain invocation.

Every eligible ECMP path must receive traffic, with exactly one receiving
member per LAG. Distribution is measured using **distinct protocols**, not
repeated packets. For `N` protocols and `K` equal-cost paths, each path count is
checked against `Binomial(N, 1/K)`: both inclusive tails must be at least
`0.01 / (2*K)`. This predeclared Bonferroni rule has at most 1% family-wise
false-alarm probability under an ideal-uniform hash model. It is a gross-bias
check, not a guarantee that each deterministic tuple satisfies a fixed percentage.
The repeats establish stability and delivery, not additional entropy.

This deliberately replaces the fixed 30% **protocol-only** contract: the known
248-flow mapping with a minimum path count of 21 versus an ideal 31 still has
32.26% skew. That imbalance is not a dataplane fix. The four address/port
fields retain their existing 30% checks on this topology; t0, other ASICs,
legacy FIB hashing and PBH tests retain their existing packet checks. No unmerged
PBH/parameter-filter PR, seed change, tuple tuning or 70% tolerance is required.
Regression controls reject ignored protocol hashing, missing paths, severe
bias, unstable flows, missing protocols/repeats, loss, duplicate copies and
unexpected LAG entropy.

`hash/test_generic_hash.py` is included in the `t1-lag-vpp` allowlist in
`.azure-pipelines/pr_test_scripts.yaml`. Preserve the supported normal-CI
selection and precise unsupported-case treatment above when extending coverage.
Use impacted-area selection, not `pr-test.yaml`; shared conditional-mark and
PTF changes select broader CI coverage than an explicit hash-only input.

Before disruptive tests, preserve both the running configuration and the saved
`config_db.json`, and establish recovery that survives the planned disruption.
Verify hash fields and algorithms, interface state, port-channel membership,
IP/VLAN configuration, routes/BGP, and VXLAN settings afterward. The function
fixture snapshots running and saved configuration in a private directory on
the DUT's `/host` for VPP `t1-lag` only; t0 and other ASICs keep the existing
hash-value-only restoration. It restores initially present hash values using the existing
setters, then reloads the original running snapshot if configuration differs,
a disruptive invocation failed, or affected interfaces/members are not operationally
ready. Per-invocation recovery tracking survives `no_shutdown` and member re-add;
CONFIG_DB equality alone does not establish operational recovery. After reload,
affected interfaces must be up and affected LAG members linked and selected.
This also restores initially absent fields and failed interface/member cleanup.
The original saved file is restored byte-for-byte even if reload fails, and
failed cleanup retains the snapshots for recovery.

Only the recovery reload uses the shared `config_reload` log-analyzer ignore
boundary for service-restart messages. Log analysis remains enabled during
test execution; packet assertions, reload health checks, and exact configuration
comparison are unchanged. No module-wide log suppression is added.

The three link-disruption cases also recognize one expected VPP hostif message:
`syncOnLinkMsg: skipping newlink ... name not found in map`. The shared VS
netlink listener sees Linux-CP TAP names outside its lane map during link churn.
Following the existing VXLAN-underlay test's precedent, the hash tests register
that exact message only for ports selected for disruption, only on VPP `t1-lag`,
and only in that test's function-scoped analyzer. T0 and other topologies keep
their existing log handling. Other ports and other errors
remain visible. Route-path, forwarding, member, and recovery checks still run;
this is not a general log-analyzer disable or a claim of a dataplane fix.

On VPP `t1-lag` only, nexthop-flap readiness checks the packet's IP family and requires
exactly the expected number of distinct resolved nexthops in VPP's forwarding
buckets before traffic, after withdrawal, and after recovery. Repeated buckets
do not count as additional nexthops; drop or unresolved forwarding is not ready.
The `len` printed beside `path-list` belongs to the uRPF interface list, not the
forwarding bucket set. Other topologies, including VPP `t0`, retain the existing
readiness check. T0 packet assertions, balance limits, xfail marks, metadata,
options, recovery and log handling are unchanged.

On VPP `t1-lag`, member deletion attempts restoration even when the delete
command raises after applying its change. Interface flaps require an initially
admin-up interface and register recovery before shutdown. Member flaps and
remove/add wait for the affected member's link and teamd selection, not just
aggregate PortChannel oper-up. Combined ECMP/LAG address/port checks require
positive observations on every expected port before applying the unchanged
30% balancing bound. This opt-in does not apply to protocol-domain validation,
which still expects exactly one stable receiving member per LAG. The new safeguards
do not change the legacy helpers' behavior on other topologies.
Fixture cleanup handles test/setup failures;
it is not a watchdog for a killed runner or unreachable DUT. Unattended
disruptive qualification also needs an external recovery guard that survives
DUT reboot.

## Focused regression tests

From the repository root:

```bash
python3 -m pytest --noconftest --confcutdir=tests/hash/unit_tests \
  tests/hash/unit_tests/unit_test_generic_hash_options.py -q
python3 -m flake8 --max-line-length=120 \
  tests/hash/generic_hash_helper.py tests/hash/unit_tests/unit_test_generic_hash_options.py \
  ansible/roles/test/files/ptftests/py3/generic_hash_test.py
```

These tests cover prerequisites, finite-domain controls, balance scope, and recovery failure paths without a DUT.
They do not replace packet or reboot validation.
