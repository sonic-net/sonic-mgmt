# KubeSonic test profiles

Profiles are version-controlled test recipes. They define test selectors,
structured pytest options, and compatible physical-testbed requirements.

## Queue a manual run

Run the `kubesonic.manual` pipeline from its default `internal` branch:

- `PR_ID`: the active pull request that contains the test code.
- `TEST_CONFIG`: `from-pr` when the pull request changes exactly one profile,
  or an existing profile name such as `gnmi-golden`.
- `TESTBED`: `auto`, or one exact physical testbed name when a specific
  eligible device is required.

The pipeline resolves the pull request to an immutable commit. For `auto`, it
reads the current Elastictest inventory, excludes unavailable or reserved
testbeds, selects one matching the profile, and derives the topology from that
testbed.

## Join the nightly run

The `kubesonic.nightly` pipeline runs `nightly-default.json` from the exact
scheduled `internal` commit. The profile initially contains the
canary-validated gNMI golden selector and options. The scheduled default is
`testbed-bjw-can-720dt-3`; a manual run may provide another exact eligible
testbed that satisfies the same profile requirements.

Compatible Kubernetes-container tests can piggyback on the same physical run
by adding their selectors and structured options to `nightly-default.json`.
Every addition requires a reviewed profile change. The launcher YAML does not
need to change.

Keep one aggregate profile only while every included test is compatible with
the same topology, testbed-name prefixes, DUT count, installed-image policy,
preparation, pretest, posttest, restart-PTF, teardown, and release behavior.
The job keeps test-case retries at zero and stops on failure. Do not weaken the
requirements to admit an incompatible test. A test that needs a different
physical boundary requires a separately reviewed profile and scheduled job.

## Add a profile

Add one JSON file under this directory:

```json
{
  "version": 1,
  "description": "What this profile validates.",
  "selectors": [
    "k8s_container/test_example.py"
  ],
  "parameters": {
    "k8s-container-test": true,
    "k8s-example-option": "value"
  },
  "requirements": {
    "topologies": [
      "m0"
    ],
    "name_prefixes": [
      "testbed-example-"
    ],
    "dut_count": 1
  }
}
```

Profile rules:

- Selectors must reference `test_*.py` files under `k8s_container/`.
- Parameters must use `k8s-*` or `minikube-*` names.
- `k8s-container-test` must be `true`.
- Requirements must list allowed topologies and testbed-name prefixes.
- `dut_count` must match the required number of devices under test (DUTs).
- Shell syntax, traversal, quotes, and unknown fields are rejected.

An exact `TESTBED` override must still be ready, unlocked, non-nightly, outside
the `AIBE test only` pool, and compatible with the selected profile.
