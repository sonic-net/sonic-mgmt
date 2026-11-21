# SONiC-to-SONiC Environment

This environment package describes a physical Ranking testbed in which both
ends of every data link are SONiC devices. The controller reaches both devices
over their management interfaces; it does not forward test packets.

```text
                         management network
                    +--------------------------+
                    |                          |
              +-----+------+             +-----+------+
              | SONiC DUT  |             | SONiC PTF  |
              | SAI RPC    |             | PTF runner |
              | port 9092  |             | + mirror   |
              +------------+             +------------+
                 |  |  |                       |  |  |
                 +==+==+==== 32 data links ====+==+==+
```

The DUT owns the SAI implementation under test. The PTF-side SONiC device is
used as the packet generator and receiver: Ranking runs PTF cases in its
`saiserverv2` container while the host `swss`/`syncd` stack mirrors ingress
traffic to the CPU.

`environment.yml` defines management access, the DUT SAI RPC endpoint, the PTF
container paths, and the ordered DUT-to-PTF port mapping. Files under `dut/`
and `ptf/` are topology-specific inputs applied by `prepare.py`. Replace these
files and the port map together when adapting this package to another lab.

The checked-in port names, lanes, aliases, indexes, and management addresses
are synthetic placeholders. They describe a consistent 32-port 400G example,
not a deployable hardware platform configuration. Replace them with values
exported from both devices before running Prepare.

The current PTF preparation uses Broadcom `bcmcmd` through `mirror_port.py`.
That requirement belongs to this environment package, not to the generic
Ranking Prepare or Run contracts.
