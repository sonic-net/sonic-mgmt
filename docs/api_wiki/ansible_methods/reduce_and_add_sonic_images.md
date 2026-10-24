# reduce_and_add_sonic_images

- [Overview](#overview)
- [Examples](#examples)
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
