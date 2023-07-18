# Device Minigraph Generation and Deployment

Different topologies requires different configuration/minigraph on the DUT.
```testbed-cli.sh gen-mg|deploy-mg``` allows to generate and deploy minigraph to
the DUT based on the topology type.

Before you run the command, first prepare [inventory](/ansible/lab) file and
[testbed.csv](/ansible/testbed.csv) file. In the command line, `vms-sn2700-t0`
is the testbed name defined in `testbed.csv`, `lab` is the inventory file.
`password.txt` is the vault password file.

```
./testbed-cli.sh deploy-mg vms-sn2700-t0 lab password.txt
```

**Note**

- To configure your SONiC switch with different port speeds, you need to specify port speed in `port_config.ini`. Example [port_config.ini](https://github.com/sonic-net/sonic-buildimage/blob/master/device/arista/x86_64-arista_7260cx3_64/Arista-7260CX3-D108C8/port_config.ini).
- You have to make sure that the hwsku in 'lab' can be found in [port_utils.py](https://github.com/sonic-net/sonic-mgmt/blob/master/ansible/module_utils/port_utils.py#L15). If you cannot find the hwsku of your SONiC device in the port-utils file, you should add your SONiC switch 'portname-to-alias' mapping information in [port_utils.py](https://github.com/sonic-net/sonic-mgmt/blob/master/ansible/module_utils/port_utils.py#L15).
## How it works

The tool works as follows:

- Read the testbed info from `testbed.csv` using the testbed name.

- Read the topology information defined in topology file `vars/topo_{{ topology_name}}.yml`

- Read the VMs information from the `veos` inventory file.

- Generate minigraph based on minigraph templates in `templates` folder.

- Deploy minigraph to the DUT.

- Load the minigraph on DUT.

- Save the configuration in config db.

For more details, please refer the comments in [`config_sonic_basedon_testbed.yml`](/ansible/config_sonic_basedon_testbed.yml).
