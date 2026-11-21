# Generic DUT port configuration

Generic uses the existing testbed commands and Ansible roles. There is no
separate authentication, health, deployment, recovery or packet-test framework.
Fanout ports retain their existing configuration; normal `fanout_connect.yml`
behavior is unchanged.

## Usage

Add a normal single-DUT, single-ASIC testbed entry with `topo: generic`. Keep the actual base
HWSKU in the DUT inventory and supply the usual PTF, server and inventory fields.
No neighbor VM base, `generic_hwsku` policy section or separate request file is
needed. The group-name and PTF fields identify existing PTF resources, not VMs.

The shared `vm_set` role still provides the PTF container and interfaces.
Generic clears its neighbor VM context and skips neighbor inventory, VM helper
setup, libvirt discovery and VM-specific permissions on physical testbeds.
Libvirt discovery needed by a virtual DUT itself is separate from neighbor VMs.
Generic does not export a PTF image for deployment on a neighbor.

```bash
./testbed-cli.sh add-topo <testbed> <vault-password-file>
./testbed-cli.sh deploy-mg <testbed> <inventory> <vault-password-file>
./testbed-cli.sh remove-topo <testbed> <vault-password-file>
```

`add-topo` calculates the DUT layout using the installed `platform.json`,
SONiC breakout parser, base HWSKU and `pg_profile_lookup.ini`. It maps the selected
ports onto existing lab VLANs, then uses the normal `vm_set` role to create the
PTF container and interfaces. Generated configuration is stored in
`ansible/vars/topo_generic_<testbed>.yml`, outside the Git diff.
This is a controller-local generated artifact, not a topology to commit.
Keep it in the same workspace for `deploy-mg`, `remove-topo` and pytest.

`deploy-mg` keeps the real HWSKU in inventory, minigraph and `DEVICE_METADATA`.
It writes the generated map to `/etc/sonic/port_config_generic.ini` without
changing installed HWSKU assets. Golden configuration generation passes this
file explicitly to `sonic-cfggen -p` and retains the complete native minigraph
configuration, including VLANs and interfaces, before applying the calculated
ports, cable lengths and breakout modes. Native autoneg/FEC and real-HWSKU
policies are retained.

Minigraph link metadata and golden link-training overrides use a Generic view
of only the generated ports compatible with the existing PTF mapping. PTF indices
are translated through the generated alias map; the original connection graph
remains unchanged for the normal fanout/PTF flow. Unmapped generated ports remain
in the port configuration without invented link metadata.

Minigraph rendering uses the native template action's backup and atomic replacement.
A rendering failure leaves the existing file and original backup intact; a successful
change preserves the previous file as `/etc/sonic/minigraph.xml.orig`. An unchanged
Docker proxy template does not restart the daemon or pause for container recovery.

Native HWSKU QoS/buffer templates render against the selected ports and cable
lengths before loading the complete configuration. A temporary buffer-template
wrapper supplies the calculated cable lookup without changing installed SKU
assets; a template that replaces those lengths fails explicitly.
Generic does not run a later `config qos reload`, which would clear the chosen
cable lengths and regenerate platform defaults.
After reload completes, Generic reads the loaded default PFC watchdog policy
and starts the native default watchdog only when enabled; full-lossy policies
remain disabled.

The complete `/etc/sonic/golden_config_db.json` is loaded directly with standard
`config reload`. Startup configuration changes only at the normal `save` step;
`save=false` leaves it unchanged. IPv6-only management transitions reload
asynchronously and reconnect before checking completion.
Generic does not call `config load_minigraph`,
which would resolve the base port map again without an explicit generated map.
Subsequent native reloads and startup use the saved configuration, not a derived
HWSKU. `port_override_from_links` cannot be combined with the generated layout.
The normal inventory credentials and Ansible errors are used throughout.

`remove-topo` removes the PTF topology through the normal role. Like an ordinary
testbed removal, it does not restore the DUT configuration. Redeploy the original
testbed to recreate its declared baseline, not to recover preexisting custom state.
This feature does not capture an original snapshot or provide rollback. Preserve
any custom configuration through the operator's normal backup/restore procedure
before deployment.

## Port calculation

The only new Python runtime file, `ansible/module_utils/port_layout.py`, calculates
port configuration and PTF indices. It does not execute commands or access devices.
Names, aliases, lane ordering, subports and supported speed variants come from the
installed canonical parser rather than interface-number arithmetic.

For each data-port mode/speed, the requested count is the maximum of its canonical
same-speed child count, its lookup cable-length count and an optional
`generic_min_subports` lower bound. Deterministic bounded backtracking selects
legal cage modes from the installed capabilities. Coverage counts generated
ports, not only ports compatible with the old lab wiring. This allows a uniform
base HWSKU to generate mixed breakout modes. Compatible PTF choices are preferred,
but the first complete layout is not a globally optimal allocation.

The existing connection graph's speeds/VLANs and the base port's ordered ASIC
lanes still constrain usable PTF ports. A generated data port without a compatible
mapping remains administratively down and is not added to the PTF topology.
Configured coverage is not evidence of link or traffic coverage; no new peer
breakout, fanout speed, VLAN or physical wiring is fabricated.

On mixed-width platforms, single-lane auxiliary cages retain their running
mode and PORT fields, including speed, administrative state, autonegotiation
and FEC. The existing alias module reads the running PORT table before generation,
and golden generation preserves these fields through native policy rendering.
They are excluded from data-mode coverage, but their selected speed must still
have a buffer lookup. On entirely single-lane platforms all cages are data cages.
This structural rule does not identify arbitrary multi-lane service ports.

Effective native minigraph autoneg/FEC settings are retained for data ports without
restoring old port names, speeds or lane assignments. The calculation does not
reconfigure a fanout to make a DUT layout fit. A layout whose configured coverage
cannot fit the available cages fails the ordinary `add-topo` Ansible task.
Image/platform support and deployment errors remain the responsibility of the
standard SONiC commands; generated configuration is not hardware qualification.
