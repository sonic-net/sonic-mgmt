# Cisco-vendored migration scripts

The files in this directory are vendored from Cisco's upstream toolchain and
are used to drive the XR → SONiC migration flow exercised by
`tests/conversion/test_cisco_conversion.py`.

| File | Source | Purpose |
|------|--------|---------|
| `sonic_migration_xr.py` | Cisco upstream | Core script that performs the XR-side preparation and SONiC migration on the chassis. |
| `sonic-migutil.py`      | Cisco upstream | Helper utility invoked by the migration flow. |

## Update policy

**Do not modify these files in place.** They are intended to track Cisco's
upstream releases verbatim. To pick up a fix or a new image-bundle compatibility
change, re-vendor the file from the upstream source (replace the whole file)
and record the upstream version / commit reference in the commit message.

If a behavioural change is required for testing purposes only, prefer wrapping
or invoking the script differently from the test rather than patching the
vendored copy.
