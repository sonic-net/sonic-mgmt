# reduce_and_add_sonic_images

- [Overview](#overview)
- [Examples](#examples)
- [SONiC version compatibility](#sonic-version-compatibility)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Removes excess sonic images and installs a new image if requested.

By default, image installation retains the legacy minigraph preference: when
`/host/old_config/minigraph.xml` exists, the module deletes the saved
`/host/old_config/config_db.json` and `/host/old_config/golden_config_db.json`
backups, except when the existing SmartSwitch detection exemption applies.

Set `preserve_config_db=True` to retain **both** saved JSON backups regardless
of minigraph presence or device type. Missing JSON files are not synthesized
or required; the existing minigraph fallback remains available. Minigraph
itself is never changed by this option. Cleanup-only calls are unaffected.

Configuration backup and migration by `sonic_installer` remain enabled (no
`--skip_migration`). The existing `--skip-package-migration` option, when
supported, affects package migration rather than configuration migration.
This preserves **saved files**, not unsaved running configuration: the module
does not run `config save` or otherwise save running changes before installation.
Existing caller post-upgrade actions are unchanged. This option applies only
to module-based SONiC image installation, not ONIE, DPU, or direct-installer
upgrade workflows.

## Examples
duthost.reduce_and_add_sonic_images(new_image_url={URL_TO_SONIC_IMAGE})

Opt in to saved JSON preservation:

```python
duthost.reduce_and_add_sonic_images(new_image_url=image_url, preserve_config_db=True)
```

The option is also exposed by these upgrade entry points (all default to false):

| Entry point | Opt-in usage |
| --- | --- |
| `.azure-pipelines/upgrade_image.py` | Add `--preserve-config-db`; applies to both previous and target SONiC images |
| `ansible/upgrade_sonic.py` | Add `--preserve-config-db` for SONiC upgrades |
| `ansible/upgrade_sonic.yml` | Add `-e '{"preserve_config_db": true}'` to the playbook invocation |
| `devutil.devices.sonic.upgrade_image` / `upgrade_by_sonic` | Pass `preserve_config_db=True` |
| `tests.common.helpers.upgrade_helpers.install_sonic` | Pass `preserve_config_db=True` for URL or local images |

## SONiC version compatibility

### Which versions support this option?

**The intended supported version range is SONiC 202605 or newer.** Earlier
releases are outside this option's documented support scope. This version
scope is not a validated source/destination compatibility matrix: availability
of the option in **sonic-mgmt** is separate from compatibility of the saved
configuration with the **SONiC images** being installed.

| Component / release | Availability and validation status |
| --- | --- |
| sonic-mgmt revisions containing [PR #28649](https://github.com/sonic-net/sonic-mgmt/pull/28649) | Provide the CLI/module option. The scripts, helpers, and module used by the runner must all include the change; older scripts reject the flag. |
| SONiC 202605 or newer | Intended supported version range. Validate the specific source/destination image pair and saved configuration before enabling; a newer release alone does not guarantee compatibility. |
| SONiC master images | No live image-upgrade compatibility validation is recorded for this change. Local mocked tests of a master-based sonic-mgmt branch do not establish image support. |
| SONiC / sonic-mgmt 202605 | Backport requested, not release-validated. Neither availability on the release branch nor safe preservation across 202605 image transitions should be assumed. |
| SONiC releases older than 202605 | Outside the documented support scope; do not enable preservation for transitions involving these images. |

This is a management-layer option, not a new `sonic_installer` flag. There is
no SONiC-version gate or ConfigDB compatibility check in the implementation.
Keeping installer configuration migration enabled does **not** guarantee that
an older image can consume configuration saved by a newer image. Differences
in schema, feature support, and platform-specific configuration can matter
even when both images belong to the same release branch.

### Both previous-image and target-image hops are affected

When a previous image is available, `.azure-pipelines/upgrade_image.py` performs:

```text
Currently running image -> previous image -> target image
```

By default, the previous-image URL is the target URL plus `.PREV.1`; an explicit
`--prev-url` can select another image. **`--preserve-config-db` applies to both
hops**, not just the final target installation. There is no separate per-hop
preservation switch.

The DUT may initially run an arbitrary or newer image. Therefore, the first
hop can be a **downgrade**, and its destination may not understand the saved
ConfigDB. The `.PREV.1` suffix is not evidence that the first hop is an upgrade
or configuration-compatible. A compatible final target does not make an
incompatible intermediate hop safe.

Before enabling, verify compatibility for both:

1. The actual running image and its saved main/golden JSON to the selected
   previous image.
2. The previous image's saved configuration to the target image, including
   changes made by existing post-upgrade actions after the first hop.

If the previous image is unavailable, the script skips that hop; the actual
running-image-to-target transition still needs validation. Do not rely on a
failed previous-image download as a compatibility policy. When a hop is
unvalidated or incompatible, leave preservation disabled for the two-hop
workflow or use a separately validated single-hop upgrade procedure. The same
compatibility expectations apply to single-hop module/helper calls.

Missing JSON files are not synthesized or required. The natural minigraph
fallback is left untouched when JSON is absent; this is **not** a guarantee
of automatic fallback when present JSON is incompatible. The existing
SmartSwitch preservation exemption does not itself establish cross-version
configuration compatibility.

### Evidence required before claiming release support

Use an isolated testbed with a recovery path and external copies of the saved
configuration. Record the sonic-mgmt revision, exact running/previous/target
image build versions, platform/topology, and configuration features under test.
For each applicable hop, verify installer backup retention, configuration
migration/loading after reboot, intended main/golden configuration semantics,
management reachability, and relevant service/feature health. Successful
installation or byte-for-byte backup retention alone is insufficient to prove
the destination understands the configuration.

For the requested **202605 backport**, run the release-branch implementation
against the intended exact image transitions, including a newer-running-image
to previous-image downgrade if that can occur in the workflow. Publish that
release-specific evidence and its limitations before describing 202605 as
validated. Also verify the omitted/false path retains existing behavior.

The current evidence consists of local mocked unit tests for preservation,
legacy defaults, propagation, and cleanup/failure handling. No live DUT/VS
upgrade or 202605 release-specific validation is claimed by this document.

## Arguments
- `disk_used_pcent` - If disk_space usage is above this percent after old disks are removed, module makes best effort to remove uneeded files
    - Required: `False`
    - Type: `Integer`
    - Default: `50`
- `new_image_url` - URL for new sonic image. If URL is not provided, no image will be downloaded.
    - Required: `False`
    - Type: `String`
    - Default: `None`
- `preserve_config_db` - Keep both saved JSON backups rather than deleting them when minigraph exists. False retains legacy deletion and the SmartSwitch exemption. Does not save running configuration, create JSON files, or affect cleanup-only calls.
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`

## Expected Output
Simple dictionary showing which image was downloaded. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `downlaoded_iamge_version` - version of image downloaded
