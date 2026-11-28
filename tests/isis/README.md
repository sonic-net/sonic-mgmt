# IS-IS device acceptance

These modules exercise the installed SONiC CLI, ConfigDB, and FRR daemon. The
image must contain the backend implementation from sonic-buildimage PR #28789
and the CLI implementation from sonic-utilities PR #4738. A stock master image
without those changes is not an acceptance image.

The `acceptance_*.py` modules are selected explicitly by file path. The native
PR impacted-area scanner and the default `run_tests.sh` scan select `test_*.py`,
so ordinary PR regression does not schedule this separate image-dependent
acceptance. No skip list, conditional skip for a missing CLI, or xfail is used
to turn an acceptance failure into a pass.

Run from `tests/` in the normal sonic-mgmt test environment:

```bash
./run_tests.sh -n <MULTI_ASIC_TESTBED> -d <DUT> \
  -c isis/acceptance_isis_cli_namespace.py -i <INVENTORY>

./run_tests.sh -n <FORCE10_7NODES_TESTBED> -d <DUT> \
  -c isis/acceptance_isis_cli_force10.py -i <INVENTORY>
```

The namespace module requires at least two frontend ASIC namespaces. The
seven-node module requires the existing `force10-7nodes` topology and its
ConfigDB profiles. The configured testbed must already use the matching image.

For cloud namespace acceptance, use the native `.azure-pipelines/test_plan.py`
entry with `--scripts isis/acceptance_isis_cli_namespace.py`, the actual matching
`--kvm-build-id`, its `--kvm-image-build-pipeline-id`, and the intended mgmt
commit. Do not substitute the ordinary PR build ID: the main buildimage PR
retains the upstream sonic-utilities gitlink until the companion CLI is merged.

Record the actual image and source revisions, test plan ID, and final JUnit
report for each acceptance run. A successful ordinary regression run is
independent of acceptance results.
