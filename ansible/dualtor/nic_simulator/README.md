# NIC simulator IPv4/IPv6 listeners

Each active NIC interface gets one `NiCServer` and one `OVSBridge`. Its IPv4
address and all stable global-scope IPv6 addresses bind to the **same** gRPC
server and share forwarding, drop/recovery and flap-counter state. The
management interface also supports both families, or IPv6 alone. No wildcard
listeners are used.

IPv4 discovery retains the existing ioctl path. IPv6 discovery uses shell-free
`ip -j -6 addr show dev INTERFACE`; ULA addresses are supported. Link-local,
tentative, DAD-failed, deprecated and temporary addresses are excluded. Addresses
are discovered at startup; restart after changing interface addresses. Missing
IPv6 tooling does not prevent IPv4-only startup. Interfaces without either a
usable IPv4 or IPv6 address are skipped; management must have a usable address.

## CLI

Run inside the existing simulator network namespace, with its `mgmt` and `ethN`
addresses and OVS bridges already provisioned. For example, from the repository
root (replace the example namespace, VM set and addresses with your configuration):

```bash
ip netns exec ns-example .venv-nic-simulator/bin/python \
  ansible/dualtor/nic_simulator/nic_simulator.py \
  -p 50075 -v example -l info \
  -d 10.1.0.36,10.1.0.38,10.1.0.39 \
  --ipv6-loopback-ips fc00::36,fc00::38,fc00::39
```

Both triplets are ordered **Loopback2, upper-ToR Loopback3, lower-ToR Loopback3**.
Each must contain three bare literals of the correct family (no prefixes or zone
IDs). The optional `--ipv6-loopback-ips` adds IPv6 counterparts to the existing
loopback and per-ToR TCP return flows; it does not assign addresses or enable
IPv6 in the namespace. Listener discovery is independent of this option. Omit
it to retain the default flow configuration; IPv4 defaults are unchanged.

`-n` / `--duplicate_nic_upstream` duplicates NIC upstream traffic for both
families, omitting both families' per-ToR TCP return overrides. Normal mode
routes TCP return traffic to the corresponding ToR. Drop/recovery applies to
both families, using the existing shared ECMP group.

Management RPC `nic_addresses` can contain either family. IPv6 aliases refer to
the same NIC server as its IPv4 address, including for server start/stop. Channel
targets use `IPv4:port` or `[IPv6]:port`; protobufs are unchanged. Every requested
bind must succeed or startup fails rather than leaving a partial listener set.

## Standalone unit tests

No testbed, OVS daemon, root privileges, proto regeneration, or integration
conftest is needed. From the repository root, use a dedicated virtual environment:

```bash
python3 -m venv .venv-nic-simulator
.venv-nic-simulator/bin/python -m pip install \
  -r ansible/dualtor/nic_simulator/unit_tests/requirements.txt
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv-nic-simulator/bin/python -m pytest \
  -c ansible/dualtor/nic_simulator/unit_tests/pytest.ini \
  --confcutdir=ansible/dualtor/nic_simulator/unit_tests \
  ansible/dualtor/nic_simulator/unit_tests -q
```

If the OS lacks `ensurepip`, an already-installed `virtualenv` can create the
environment instead. Tests mock the OVS command boundary and also run real
loopback gRPC RPCs for dual-bind and IPv6-only operation. Only those real IPv6
tests skip when the host cannot bind `::1`.

Not covered by these local tests: actual OVS flow acceptance/packet forwarding,
namespace provisioning, routing/firewall policy, deployment templates, external
client IPv6 configuration, or ycabled end-to-end validation. This change does not
configure or deploy to a testbed.
