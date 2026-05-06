# VXLAN VPP Random Hash Debug Strategy

## Scope

This note tracks the debug strategy for the VPP failure in:

```text
vxlan/test_vxlan_ecmp.py::Test_VxLAN_ecmp_random_hash::test_vxlan_random_hash[v4_in_v4]
```

The observed failure was that traffic to existing destination `150.0.3.1` received no VXLAN reply even though its active endpoint was still listed as `100.0.1.10`. The goal is to determine whether the stale or missing forwarding state is in SONiC orchestration, ASIC DB / SAI translation, or the VPP dataplane.

## Confidence statement

We are not yet 100% confident in the root cause. We are confident in the debug strategy because the main loopholes were identified and closed:

1. Running only `Test_VxLAN_ecmp_random_hash` is not enough for route-churn debugging because it skips prior module tests. The repro must run the full `test_vxlan_ecmp.py` module sequence for the target encap type.
2. VPP state must be collected after PTF failure even if full pre-PTF dumps are not enabled.
3. ASIC DB route keys must be read safely because JSON route keys can contain spaces.
4. sonic-sairedis changes should be logging-only until evidence identifies the failing layer.

## sonic-mgmt debug changes

Add an opt-in option in `tests/vxlan/conftest.py`:

```text
--vxlan_dump_vpp_state
```

Add the following behavior in `tests/vxlan/test_vxlan_ecmp.py`:

1. Store the VPP dump flag in the VXLAN setup data.
2. Add VPP-only state collection before PTF runs when `--vxlan_dump_vpp_state` is set.
3. Always collect VPP-only state after PTF failures on VPP.
4. Use `while read -r` loops when reading Redis keys so ASIC DB JSON route keys are not split by whitespace.

Add minimal PTF breadcrumbs in `tests/ptftests/py3/vxlan_traffic.py`:

1. When no VXLAN reply is received, include:
   - destination
   - active endpoints
   - ignored non-VXLAN packet count
   - ignored wrong-port packet count
   - up to five ignored packet samples

## sonic-sairedis debug changes

Add NOTICE-level logging only in the VPP SAI backend:

```text
vslib/vpp/TunnelManager.cpp
vslib/vpp/SwitchVppNexthop.cpp
vslib/vpp/SwitchVppRoute.cpp
```

The logs should show:

1. VXLAN tunnel encap next-hop create/delete events.
2. Tunnel source, destination, VNI, VRF, `sw_if_index`, and bridge-domain mapping.
3. Next-hop resolution to endpoint and tunnel `sw_if_index`.
4. Route member and route-path programming for add/remove operations.

These changes must not alter route, tunnel, or dataplane behavior.

## Correct test command

Run the full VXLAN ECMP module sequence for the target encap type through `tests/run_tests.sh`.
The script already adds common pytest options such as inventory, host pattern, testbed, `--showlocals`,
`--assert plain`, `--show-capture no`, and `-rav`, so only pass the VXLAN-specific debug options through
`-e`.

```bash
cd tests

./run_tests.sh \
  -n <testbed-name> \
  -c vxlan/test_vxlan_ecmp.py \
  -i <inventory-file-or-list> \
  -e "--include_long_tests=True -k 'v4_in_v4' --maxfail=1" \
  -u
```

Example using the same style as other VPP runs:

```bash
cd tests

./run_tests.sh \
  -n vms64-t1-7260-14 \
  -c vxlan/test_vxlan_ecmp.py \
  -i ../ansible/str3,../ansible/veos \
  -e "--trim_inv --include_long_tests=True -k 'v4_in_v4' --maxfail=1" \
  -u
```

Add `--vxlan_dump_vpp_state` inside `-e` only if you want VPP state before every PTF call. Without it,
failures still force an after-failure VPP dump on VPP.

Do not use only:

```text
vxlan/test_vxlan_ecmp.py::Test_VxLAN_ecmp_random_hash::test_vxlan_random_hash
```

That node-only run skips the prior route churn and can produce misleading evidence.

## Result interpretation

| Result | Interpretation |
| --- | --- |
| `tc11` PTF failure with missing ASIC DB route | Focus on SONiC orchestration or config flow. |
| ASIC DB has the route but VPP FIB or tunnel state is missing | Focus on sonic-sairedis VPP SAI translation. |
| ASIC DB and VPP state look correct but no packet returns | Focus on VPP dataplane or tunnel forwarding. |

## Image rebuild loop

1. First run the sonic-mgmt debug test against the current image.
2. Collect pytest logs and PTF logs, especially files matching:

```text
/tmp/vxlan-tests.tc11.*.log
```

3. Build a new SONiC-VPP image with the instrumented sonic-sairedis.
4. Rerun the same `run_tests.sh` command.
5. Collect syncd logs matching:

```bash
show logging | grep -E 'VXLAN tunnel nexthop|Resolved next hop| route .* endpoint| path in route'
```

6. Compare SONiC route state, ASIC DB route / next-hop state, VPP FIB state, and PTF packet observations at the first failing step.
