# KubeSonic test profiles

Profiles are version-controlled selector lists. Version 2 profiles choose
tests only. They do not own testbeds, topology, device count, pytest
overrides, or container images.

## Queue a manual run

Run the `kubesonic.manual` pipeline from its default `internal` branch:

- `PR_ID`: an active or completed pull request that changes exactly one
  profile.
- `TESTBED`: one exact physical testbed name.

An active pull request resolves to its immutable source commit. A completed
pull request resolves to its merge commit. Zero or multiple changed profiles
fail clearly. The pipeline reads live Elastictest inventory to validate the
exact testbed and derive its topology and associated execution inventory.

Container images belong in reviewed YAML under `../container_specs/`. To test
another image, change that YAML in the same pull request. The manual queue has
no runtime image override.

## Join the nightly run

The `kubesonic.nightly` pipeline runs `nightly-default.json` from the exact
scheduled `internal` commit. The profile initially contains the
canary-validated gNMI selector. The scheduled default is
`testbed-bjw-can-720dt-3`.

The trusted nightly resolver keeps the reviewed target boundary outside the
profile: topology `m0` or `mx`, the `testbed-bjw-can-720dt-` lab prefix, and
exactly one DUT.

Compatible Kubernetes-container tests can piggyback on the same physical run
by adding their selectors to `nightly-default.json`. Every addition requires a
reviewed profile change. The launcher YAML does not need to change.

`dummy-golden.json` is the manual-only reference for onboarding another
container. It exercises the shared Minikube, workload, image-staging,
readiness, and cleanup contract without joining `nightly-default.json`.

Keep one aggregate profile only while every included test is compatible with
the same physical execution boundary. The job keeps test-case retries at zero
and stops on failure. A test that needs a different boundary requires a
separately reviewed profile and scheduled job.

## Add a profile

Add one JSON file under this directory:

```json
{
  "version": 2,
  "description": "What this profile validates.",
  "selectors": [
    "k8s_container/test_example.py"
  ]
}
```

Profile rules:

- Selectors must reference `test_*.py` files under `k8s_container/`.
- Only `version`, `description`, and `selectors` are accepted.
- Traversal, invalid selectors, and unknown fields are rejected.

The exact testbed must be ready, unlocked, non-nightly, and outside the
`AIBE test only` pool. An explicitly selected test fails if that inventory is
incompatible with its own runtime requirements.
