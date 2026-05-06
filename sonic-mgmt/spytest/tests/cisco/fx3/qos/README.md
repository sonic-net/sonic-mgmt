# FX3 QoS Spytests

SpyTest + IXIA validation of FX3 QoS: DSCP→TC mapping, scheduler (DWRR / strict
priority), WRED, and buffer behavior. ASIC: Tahoe (Sundown1). SDK: Nexus SDK.

## Layout

The directory mirrors the FX3 QoS SAI test layout in `cisco-nx-sai`
(`test/python/hw/mig_hw/fx3/qos/`) so the same area exists on both sides.

```text
qos/
├── conftest.py                    # registers `smoke` marker, hoists smoke first
├── qos_helpers.py
├── test_qos_integration.py        # cross-area end-to-end (DWRR + SP + WRED)
├── test_simple_connect.py         # topology sanity
├── buffer/
├── qos_map/
├── scheduler/
└── wred/
```

`test_qos_integration.py` holds the multi-port end-to-end scenarios (the
"tortuga" use case). The area subdirectories hold focused per-feature tests.

## Running

Tests are invoked via `bin/spytest` from `sonic-mgmt/spytest/`. See the
[Testbed Setup wiki](https://ciscoteams.atlassian.net/wiki/spaces/WHITEBOX/pages/967479575/Testbed+Setup)
for environment prerequisites (spytest container, mounts, IXIA access).

### Run modes

A curated 12-test smoke set is split across two topology-targeted markers so
smoke runs cover both the non-breakout and breakout testbeds without
duplicating coverage:

- `@pytest.mark.smoke_non_breakout` (9 IDs) — pin to `fx3_qos_testbed.yaml`
  (cheaper, 1 DUT). Covers config / DB / SAI checks plus the tests where
  topology doesn't add coverage.
- `@pytest.mark.smoke_breakout` (3 IDs) — pin to
  `fx3_qos_testbed_breakout.yaml` so the 4×25G peer-link egress path gets
  exercised in smoke.

For IPv4/IPv6 traffic-test pairs, the two AFs are split across topologies —
same egress queueing/drop machinery either way; topology is what's worth
varying. Total smoke count is 12, distributed 9 + 3.

`-m smoke` is auto-applied as the union (so `-m smoke` and
`git grep smoke` keep working). `conftest.py` also hoists any smoke item to
the front of the collection, so the full-suite invocation runs smoke first.

| Goal | Command |
|---|---|
| Smoke (non-breakout topology) | `bin/spytest --testbed-file testbeds/fx3/fx3_qos_testbed.yaml ... -m smoke_non_breakout cisco/fx3/qos/` |
| Smoke (breakout topology) | `bin/spytest --testbed-file testbeds/fx3/fx3_qos_testbed_breakout.yaml ... -m smoke_breakout cisco/fx3/qos/` |
| Smoke union | `bin/spytest ... -m smoke cisco/fx3/qos/` |
| Smoke first, then the rest | `bin/spytest ... cisco/fx3/qos/` (default) |
| Same, fail fast on smoke | `bin/spytest ... --maxfail 3 cisco/fx3/qos/` |
| Just non-smoke | `bin/spytest ... -m "not smoke" cisco/fx3/qos/` |
| Smoke for one area only | `bin/spytest ... -m smoke cisco/fx3/qos/scheduler/` |
| One specific test | `bin/spytest ... cisco/fx3/qos/<file>::<test>` |

To see what is in each smoke set:
`git grep -E 'smoke_(non_)?breakout' sonic-mgmt/spytest/tests/cisco/fx3/qos/`.

Canonical full-suite command (smoke first, then everything else):

```bash
bin/spytest --testbed-file testbeds/fx3/fx3_qos_testbed.yaml \
  --device-feature-group master \
  --module-init-max-timeout=72000 \
  --tc-max-timeout=72000 \
  --port-init-wait 1 \
  --skip-init-checks \
  --breakout-mode none \
  --logs-path run_logs/ \
  cisco/fx3/qos/ 2>&1 | tee log
```

### Testbed YAMLs

Available in `testbeds/fx3/`:

- `fx3_qos_testbed.yaml` — default 2×100G ingress → 1×100G egress
- `fx3_qos_testbed_breakout.yaml` — breakout topology
- `fx3_qos_testbed_config_only.yaml` — config-only (no traffic)
- `fx3_qos_testbed_peer_link.yaml` — peer-link variant

Swap YAMLs to run the same tests against a different topology.

## What a passing run looks like

### Scheduler DWRR (`test_scheduler_dwrr_validation`)

DWRR weight distribution validated across Q0–Q5; observed TX share within
±20% of configured weight. Strict-priority Q6/Q7 see zero drops.

```text
DWRR TX-SHARE VALIDATION  —  Tolerance ±20%
Total weight: 170  (Q0=20  Q1=20  Q2=20  Q3=40  Q4=40  Q5=30)

Queue  Weight  Expected %  Actual %  Acceptable Range  Result
Q0     20      11.8%       11.6%     [9.4% .. 14.1%]   PASS
Q1     20      11.8%       11.6%     [9.4% .. 14.1%]   PASS
Q2     20      11.8%       11.6%     [9.4% .. 14.1%]   PASS
Q3     40      23.5%       23.5%     [18.8% .. 28.2%]  PASS
Q4     40      23.5%       23.5%     [18.8% .. 28.2%]  PASS
Q5     30      17.6%       18.0%     [14.1% .. 21.2%]  PASS
DWRR share result: 6 passed, 0 failed

Strict-Priority (zero drops expected):
Q6   Drop Delta 0  PASS
Q7   Drop Delta 0  PASS
```

### WRED linearity (`test_wred_linearity`)

Oversubscription drives queue depth from ~1.1 MB to ~3.0 MB; measured drop
rate tracks expected probability in linear region (Zone B).

```text
WRED LINEARITY SUMMARY (egress 100000M)
Margin    Rate%     Avg Depth  Est. Prob  WRED Drop  Zone  Status
250M      100.250%  1.12MB     0.30%      0.25%      B     OK
500M      100.500%  1.20MB     0.51%      0.50%      B     OK
1000M     101.000%  1.43MB     1.06%      0.99%      B     OK
2000M     102.000%  1.80MB     2.00%      1.96%      B     OK
5500M     105.500%  3.00MB     5.00%      5.29%      B     OK
```

## References

- Testbed setup: <https://ciscoteams.atlassian.net/wiki/spaces/WHITEBOX/pages/967479575/Testbed+Setup>
- SAI suite: <https://wwwin-github.cisco.com/whitebox/cisco-nx-sai> (`test/python/hw/mig_hw/fx3/qos/`)
