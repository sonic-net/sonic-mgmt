# reduce_and_add_sonic_images

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Removes excess sonic images and installs a new image if requested.

SONiC-to-SONiC installation now defaults to the **saved `config_db.json`**.
It retains the installer's `/host/old_config/config_db.json` and
`golden_config_db.json`, even when `minigraph.xml` exists. Previously, an XML
file's presence caused those JSON files to be deleted. `config save` does not
regenerate minigraph, so that behavior could restore stale configuration.

This preserves saved configuration, not unsaved running state. If running
changes should survive the upgrade, save them deliberately **before** image
installation (for example, `config save -y`). The module does not save running
configuration automatically. Post-upgrade saves cannot recover settings lost
at the first reboot.

The selected source must be readable and parseable both in `/etc/sonic` before
installation and in `/host/old_config` afterward. JSON must be an object;
existing per-ASIC JSON and golden JSON are also checked. Minigraph is checked
with `sonic-cfggen`. Validation does not guarantee schema compatibility with a
different SONiC release. Missing or invalid configuration fails the upgrade
instead of silently choosing the other source. Cleanup-only calls do not
validate or select configuration.

### Explicit minigraph rebuilds

Workflows that intentionally regenerate configuration must opt in with
`config_source="minigraph"`. Only after successful installation and validation
of the staged XML does this remove the main and golden JSON files.
SmartSwitch minigraph rebuilds are rejected to protect DPU configuration;
use `config_db` instead. Minigraph also fails if SmartSwitch detection fails
or the installed SONiC lacks `device_info.is_smartswitch`.

The upgrade-path base-image setup explicitly requests minigraph on conventional
switches and retains JSON on SmartSwitches. Installation failures now stop that
setup rather than bypassing source validation after a package-migration error.
Target-image installations retain the JSON default.

This policy applies to the module-based SONiC upgrade paths, not ONIE reimages,
the separate DPU image installer, or advanced-reboot workflows that invoke
`sonic_installer` directly. It does not add configuration persistence to those
workflows.

## Examples

```python
# Preserve saved JSON (default).
duthost.reduce_and_add_sonic_images(new_image_url=image_url)

# Intentionally regenerate from minigraph on a supported conventional switch.
duthost.reduce_and_add_sonic_images(new_image_url=image_url, config_source="minigraph")
```

The same option is available through:

- `ansible/upgrade_sonic.py --config-source minigraph`
- `.azure-pipelines/upgrade_image.py --config-source minigraph` (applies to both previous and target images)
- `ansible-playbook ansible/upgrade_sonic.yml ... -e config_source=minigraph`
- `devutil.devices.sonic.upgrade_image(..., config_source="minigraph")`
- `tests.common.helpers.upgrade_helpers.install_sonic(..., config_source="minigraph")` (URL or local image)

Omit the option to preserve saved JSON. CLI and playbook configuration-source
options apply only when the upgrade type is `sonic`, not `onie`.

## Arguments
- `disk_used_pcent` - If disk_space usage is above this percent after old disks are removed, module makes best effort to remove uneeded files
    - Required: `False`
    - Type: `Integer`
    - Default: `50`
- `new_image_url` - URL for new sonic image. If URL is not provided, no image will be downloaded.
    - Required: `False`
    - Type: `String`
    - Default: `None`
- `config_source` - Saved configuration source for image installation.
    - Required: `False`
    - Type: `String`
    - Choices: `config_db`, `minigraph`
    - Default: `config_db`

## Expected Output
Simple dictionary showing which image was downloaded. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
    - `downlaoded_iamge_version` - version of image downloaded
