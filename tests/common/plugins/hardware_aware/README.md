# Hardware-Aware Collection Plugin

This pytest plugin evaluates collected tests against hardware-aware test
capabilities. It can either write a report or deselect tests during collection.

The plugin is disabled by default.

Report only:

```bash
--hardware-aware-report-only
```

Deselect during collection:

```bash
--hardware-aware-deselect
```

Normal catalog setup mode:

```bash
--hardware-aware-setup x86_64-8122_64ehf_o-r0:t0
```

Or provide a complete/override setup YAML:

```bash
--hardware-aware-setup-input my_setup.yaml
```

The plugin reads `hardware_aware/setup_profiles.yaml` and
`hardware_aware/skip_rules.yaml` by default, then generates runtime
`run_context` and `test_capabilities` rules internally.

Explicit runtime files are still supported for debugging or backward
compatibility:

```bash
--hardware-aware-run-context-file out/run_context.json
--hardware-aware-test-capabilities-file out/test_capabilities.json
```

See `hardware_aware/README.md` for setup keys, override files, and catalog
maintenance details.

Optional report path:

```bash
--hardware-aware-report-path logs_hwaware/hardware_aware_report.json
```

Optional generated-rule filters:

```bash
--hardware-aware-min-confidence high
--hardware-aware-candidate-status ready_for_report_only
```

The report includes `summary`, `collected_nodeids`, `filtered_test_capabilities`,
and one decision entry for each matched test capability.
