# Persist management and console settings after MGFX migration

A temporary Linux interface change is not a persisted SONiC configuration change.
The selected DUT's running CONFIG_DB and `/etc/sonic/config_db.json` must contain
the migrated management prefix and gateway. Correct SONiC inventory alone does not
write these on-device settings.

This procedure is independent of any migration phase or inventory-backfill PR.
It is an opt-in repair, not an automatically deployed fleet change.

## Before applying

1. Confirm the device identity and the desired IPv4/IPv6 prefixes and gateways from
   the migration plan and current metadata. Do not derive a gateway from an address
   or reuse another device's values.
2. Establish working console access. Changes to management addressing can disconnect
   SSH. Do not invoke the apply step through the management connection being changed.
3. Confirm the terminal-server line's baud rate. Select 9600 only for links whose
   metadata and terminal-server configuration require 9600.
4. Copy `ansible/scripts/repair_mgfx_config.py` to the selected DUT using the approved
   lab access path. Run with the DUT's Python 3 and SONiC utilities.

## Preview and apply

The supplied example is an eth0 IPv4 prefix of `10.3.144.70/27` and gateway
`10.3.144.65`. Use that pair only on the device explicitly assigned those values.
The corresponding persisted table must be:

```json
{
    "MGMT_INTERFACE": {
        "eth0|10.3.144.70/27": {
            "gwaddr": "10.3.144.65"
        }
    }
}
```

For that confirmed device, replace `EXPECTED_HOSTNAME` below with its actual
hostname. This first command is a read-only preview:

```bash
sudo python3 repair_mgfx_config.py --hostname EXPECTED_HOSTNAME --ipv4-prefix 10.3.144.70/27 --ipv4-gateway 10.3.144.65 --set-console-9600
```

Review the running, saved, and desired management tables. Then run through the
working console:

```bash
sudo python3 repair_mgfx_config.py --hostname EXPECTED_HOSTNAME --ipv4-prefix 10.3.144.70/27 --ipv4-gateway 10.3.144.65 --set-console-9600 --apply --confirm-console-access
```

Supply `--ipv6-prefix` and `--ipv6-gateway` together to migrate IPv6 too. Omitting
IPv6 preserves its existing settings; it does not verify that they are correct.
An IPv6 gateway may be an address in the management prefix or a link-local router
on `eth0`, such as `--ipv6-prefix 2001:db8::70/64 --ipv6-gateway fe80::1`.
IPv4 gateways must remain in the specified subnet. Both families reject a gateway
equal to the host address, an unspecified gateway, or a multicast gateway.
Omit `--set-console-9600` when the selected link does not require a baud change.

The helper:

- Refuses a hostname mismatch, unsupported multi-ASIC device, invalid address/gateway,
  unfamiliar boot layout, or unconfirmed console-access write.
- Makes unique private backups of files it will change and prints their paths.
- Uses `config interface ip add eth0 PREFIX GATEWAY` to replace each requested
  address family in running CONFIG_DB, then `config save -y` and JSON readback.
- Refuses to save if unrelated running tables or unrequested management families
  differ from startup configuration.
  Reconcile those changes with their author first; do not blindly save them.
- Changes only the GRUB serial speed and serial console rate on SONiC kernel
  entries, from 115200 to 9600. It preserves ONIE, other kernel arguments, and
  unrelated occurrences of those numbers.
- Does not reload, reboot, change terminal-server settings, or deploy the repository.

Both boot stages need the correct rate:

```text
serial --port=0x3f8 --speed=9600 --word=8 --parity=no --stop=1
console=ttyS0,9600n8
```

If an apply step fails, it exits nonzero. Running configuration may already have
changed; the error is not a successful rollback. Stay on the console, retain the
printed backups, and inspect running and saved state before any restart.

## Completion is an on-device check

After applying, rerun the preview and independently read the persisted
`MGMT_INTERFACE` entry and both relevant settings in `/host/grub/grub.cfg`.
Check the live eth0 addresses, routes, and management reachability as well.
Arrange a separately authorized reboot or configuration reload and verify that
management connectivity survives and the console remains readable. The helper
does not claim that this physical verification has occurred.

An image installation can regenerate `grub.cfg`. Recheck both boot settings after
image changes; this repair does not change the image installer or platform defaults.
Keep the source inventory/minigraph consistent too, or a later deployment can
replace the repaired configuration.

## Offline regression tests

```bash
python3 -m pytest ansible/scripts/tests/test_repair_mgfx_config.py
```

These tests exercise the reported stale startup entry and both boot-rate settings
using temporary files and a mocked SONiC CLI. A passing offline run is not device,
image, or hardware validation.
