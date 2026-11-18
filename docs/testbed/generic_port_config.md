# Generic DUT port configuration

Generic uses the existing testbed commands and Ansible roles. There is no
separate authentication, health, deployment, recovery or packet-test framework.
Fanout ports retain their existing configuration; normal `fanout_connect.yml`
behavior is unchanged.

## Usage

Add a normal single-DUT, single-ASIC testbed entry with `topo: generic`. Keep the actual base
HWSKU in the DUT inventory and supply the usual PTF, server and inventory fields.
No `generic_hwsku` policy section or separate request file is needed.

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

`deploy-mg` creates a `<base-HWSKU>_Generic` directory containing the generated
port map and links to the base HWSKU's other assets. It does not modify the base
HWSKU. Standard minigraph generation, golden configuration, native QoS/buffer
templates and configuration save load the resulting DUT configuration.
The normal inventory credentials and Ansible errors are used throughout.

`remove-topo` removes the PTF topology through the normal role. Like an ordinary
testbed removal, it does not restore the DUT configuration. Redeploy the original
testbed to return to its configuration.

## Port calculation

The only new Python runtime file, `ansible/module_utils/port_layout.py`, calculates
port configuration and PTF indices. It does not execute commands or access devices.
Names, aliases, lane ordering, subports and supported speed variants come from the
installed canonical parser rather than interface-number arithmetic.

For each data-port mode/speed, the requested count is the maximum of its canonical
same-speed child count, its lookup cable-length count and an optional
`generic_min_subports` lower bound. Deterministic bounded backtracking selects
compatible cage modes. Single-lane auxiliary cages retain a compatible baseline
mode; on an entirely single-lane platform they participate as data ports.

The existing connection graph's speeds and VLANs constrain usable PTF ports.
The calculation does not reconfigure a fanout to make a DUT layout fit. An
infeasible layout fails the ordinary `add-topo` Ansible task.
Image/platform support and deployment errors remain the responsibility of the
standard SONiC commands; generated configuration is not hardware qualification.
