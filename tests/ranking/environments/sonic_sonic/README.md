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

## Prepare service changes

Reserve both devices before running Prepare. It stops DUT `swss` and starts
SAIserver on the DUT. On PTF it starts the tooling container, verifies that its
SAIserver is stopped or exited, restarts `swss`, and configures ingress
mirroring. Restarting PTF `swss` may also restart its `syncd` container.

## Configure `environment.yml`

Fill in `environment.yml` for your lab before running Prepare or Run in the
[Ranking workflow](../../README.md). Keep the template values for the PTF
container and paths if they match your image.

| Field | How to fill it in |
| --- | --- |
| `schema_version` | Keep `1`. |
| `type` | Keep `sonic_sonic` to use this environment implementation. |
| `asic` | Set the DUT ASIC family, for example `td5`. Report displays it when given this YAML. |
| `controller.testbed` | Give this lab a name, such as `lab-a`. |
| `controller.host_pattern` | Keep `all` to select both devices. |
| `controller.connection` | Optional, defaults to `ssh` for key authentication. Use `paramiko` for password authentication. |
| `hosts.dut.name`, `hosts.ptf.name` | Give the DUT and PTF different inventory names. |
| `hosts.dut.address`, `hosts.ptf.address` | Set management addresses reachable from the controller. The PTF address must be IPv4. The DUT address also serves SAI RPC. Provide a route from PTF to this address and verify TCP 9092 from the PTF container. |
| `hosts.dut.user`, `hosts.ptf.user` | Set the SSH account for each device. The accounts need permission to perform the operations for the selected stage. |
| `hosts.<role>.auth.password` | Optional. Set only for the device that uses password authentication, in a local untracked copy. |
| `dut.platform` | Set the SAI platform used by the case suite, for example `broadcom`. Run passes it as `PLATFORM`. |
| `dut.rpc_port` | Keep `9092`. |
| `ptf.container` | Name of the tooling container on the PTF host. Keep `saiserverv2` if using this package's Prepare implementation. |
| `ptf.workdir` | Absolute working directory in the PTF container, typically `/SAI-TEST`. |
| `ptf.executable` | Absolute path to the PTF launcher, typically `/SAI-TEST/test/ptf/ptf`. |
| `ptf.case_dir` | Absolute path to the deployed cases, typically `/SAI-TEST/ptf`. |
| `ptf.binding_dir` | Absolute path to the directory containing the `sai_thrift` package, typically `/usr/lib/python3/dist-packages`. |
| `ptf.collector_dir` | Keep `/tmp/sai_test_results` for the included cases. For a different case suite, use the absolute path where that suite actually writes its results. |
| `ptf.timeout_s` | Timeout per case in seconds. The template uses `180`. Increase it for longer cases. |
| `ptf.arguments` | Keep `[--relax]`. |
| `ports` | Use DUT port names as keys. Set `interface` to the connected PTF interface and assign consecutive, unique `id` values starting at 1. Use 32 or 64 entries for the standard `ptf32` or `ptf64` topology. |

The first two links in the template look like this. List all links for your
testbed and supply the corresponding port files in `dut/` and `ptf/`.

```yaml
ports:
  Ethernet0: {id: 1, interface: Ethernet1}
  Ethernet4: {id: 2, interface: Ethernet2}
```

## SSH authentication

For key authentication, keep `controller.connection: ssh`. Install the
corresponding public key for the configured user on each device. On the
controller host, make sure `~/.ssh/known_hosts` contains the verified host keys
for the addresses in `environment.yml`.

In the controller host shell, start an agent with `ssh-agent bash` if you do
not already have one, then load the device key.

```bash
ssh-add /path/to/lab_private_key
```

From the repository root in that shell, start the container with the agent
socket and a read-only `known_hosts` mount. The private key stays on the
controller host.

```bash
docker run --rm -it \
  --network host \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD,target=/work/sonic-mgmt" \
  --mount "type=bind,source=$SSH_AUTH_SOCK,target=/run/ranking-ssh-agent" \
  --mount "type=bind,source=$HOME/.ssh/known_hosts,target=/etc/ssh/ssh_known_hosts,readonly" \
  --env SSH_AUTH_SOCK=/run/ranking-ssh-agent \
  --env HOME=/tmp \
  --env ANSIBLE_CONFIG=/work/sonic-mgmt/ansible/ansible.cfg \
  --workdir /work/sonic-mgmt \
  sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest bash
```

Inside the container, replace each user and address with the corresponding
values from `hosts.dut` and `hosts.ptf`. Both commands should exit with status
0 without a password prompt.

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -T DUT_USER@DUT_ADDRESS true
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -T PTF_USER@PTF_ADDRESS true
```

For password authentication, start the controller as shown in the main README.
Set `controller.connection: paramiko` and supply `auth.password` for the
applicable hosts in a local, untracked copy of `environment.yml`. Prepare uses
those credentials for SSH. On an already configured lab, run just the
`check_env` step to verify device access and readiness.
