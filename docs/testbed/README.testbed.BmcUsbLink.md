# Switch-Host BMC USB link provisioning

`ansible/roles/bmc_usb_link` is an **opt-in** provisioning role for Switch-Host
platforms with a dedicated, otherwise unmanaged `usbN` link to a BMC. It installs
an enabled systemd oneshot to bring the interface up and assign an explicit IPv4
link-local address on each normal boot. It does not configure the BMC, Redis,
firewall rules, routes to other networks, or temperature-mirroring daemons.
No inventory entry enables it by default.

## Prerequisites and ownership

The target is the **Switch-Host**, not the BMC DUT in a BMC testbed. It needs
Python 3, iproute2 with JSON output, systemd, `sonic-cfggen`, and `sonic_py_common.device_info`
with `is_switch_host()`, `is_switch_bmc()` and `get_bmc_address()`. The platform
must identify itself as Switch-Host (`switch_host=1` in `platform_env.conf`).
The platform's existing `bmc_addr` must be a different usable address in the
requested subnet. An absent/unsupported platform API or missing BMC configuration
fails provisioning rather than guessing.

Use the platform's existing interface provisioning instead if one exists. Before
opting in, confirm that no other service, vendor script or DHCP client owns this
link. The helper rejects interfaces enslaved to another link, other existing IPv4
addresses, overlapping subnets on other interfaces, ifupdown definitions,
systemd-networkd assignments, NetworkManager ownership, and interface definitions
in live CONFIG_DB. These checks are repeated on boot but cannot discover
arbitrary vendor scripts. Do not configure this link
through another manager while the role owns it. Failed ownership probes are
errors, not permission to take ownership.

The supported address range is IPv4 link-local (`169.254.0.0/16`) with a prefix
between /16 and /30; network and broadcast addresses are rejected. Only `usbN`
interface names are accepted. This deliberately does not support arbitrary
Ethernet/management interfaces, routed BMC networks, or automatic USB discovery.

## Enable and provision

Set these variables in the intended **Switch-Host's** private `host_vars`, using
the interface and subnet required by its platform. This example is illustrative,
not a universal platform default:

```yaml
bmc_usb_link_enabled: true
bmc_usb_link_interface: usb0
bmc_usb_link_address: 169.254.100.2/30
```

In this example the platform's existing BMC address is `169.254.100.1`. No BMC
address, Redis listener, authentication or security configuration is changed.
Do not add real lab inventory to the public repository.

For a fresh install or an already-running host, run from `ansible/` inside the
sonic-mgmt container, selecting **only** the intended Switch-Host:

```bash
ansible-playbook provision_bmc_usb_link.yml -i <inventory> -l <switch-host>
```

The same role runs after the SONiC initialization wait in `upgrade_sonic.yml`
for both SONiC and ONIE installs, including the `testbed-cli.sh install-image`
path. It affects only opted-in entries among the actual upgrade targets: it does
not automatically provision a paired Switch-Host when only the BMC is targeted.
Other installation paths must invoke the standalone playbook after SONiC boots.

Each provisioning run restarts the oneshot, even if its files are unchanged,
so a lost address or administratively down link is reapplied. Such runs report
the service restart as changed. Different existing IPv4 addresses are rejected:
remove the old configuration explicitly before changing the requested address.
Check mode performs the read-only preflight, but does not apply link changes.

## Boot behavior, validation and limitations

The service requires the USB device and SONiC's `config-setup.service`, waits
for configuration initialization, and orders its link configuration before
`pmon.service` when both participate in the boot transaction. It uses a bounded
300-second job timeout covering dependency waits, so a missing device does not
hold boot indefinitely. Helper execution itself is limited to 30 seconds.
Ordering does **not** make PMON depend on successful link configuration, and
running provisioning after boot does not restart PMON or thermalctld. The role
does not guarantee daemon recovery if they already attempted a blocked connection;
use the platform's supported recovery procedure if needed.

An ordinary reboot of the same installed image should retain the service and
helper. USB disconnect/reconnect, interface renaming, warm/fast reboot semantics,
and cross-image filesystem preservation are not guaranteed. Reapply provisioning
after every image install/upgrade; a standalone `sonic-installer` invocation is
not covered automatically. Do not assume that `config save` preserves these files.

On the intended hardware, verify the following before relying on persistence:

```bash
systemctl is-enabled sonic-bmc-usb-link.service
systemctl status sonic-bmc-usb-link.service
ip -4 address show dev usb0
ip route get 169.254.100.1
```

Use the platform's authorized Redis connectivity check and confirm that
Switch-Host temperatures reach BMC STATE_DB. Then reboot the Switch-Host and repeat
the checks, inspecting `journalctl -b -u sonic-bmc-usb-link.service` and PMON
ordering. Also verify rerun recovery after deliberately removing only this
address or bringing this dedicated link down in a maintenance window.

The equivalent manual link-up/address workaround restored connectivity and
temperature mirroring during troubleshooting. That is **not** hardware validation
of this role, and reboot persistence of that workaround was not tested.

For controller-only regression checks, run from the repository root:

```bash
python3 -m pytest ansible/roles/bmc_usb_link/tests -q
```

These mock network/platform operations. On Linux they also verify the rendered
unit with `systemd-analyze` in an isolated root using representative PMON
dependencies; they do not exercise a real USB device or SONiC boot.

## Disable and remove

Setting `bmc_usb_link_enabled: false` only prevents future provisioning; it does
not remove an existing installation or IPv4 address. With alternate access to the
host, stop and disable the service, remove the two files, reload systemd, and
delete only the address this role assigned:

```bash
sudo systemctl disable --now sonic-bmc-usb-link.service
sudo rm /etc/systemd/system/sonic-bmc-usb-link.service
sudo rm /usr/local/sbin/sonic-bmc-usb-link
sudo systemctl daemon-reload
sudo ip address del 169.254.100.2/30 dev usb0
```

Substitute the actual configured address/interface. Stopping the service
intentionally does not flush addresses or bring the link down. Do not use
`ip address flush`; it could remove another owner's configuration.
