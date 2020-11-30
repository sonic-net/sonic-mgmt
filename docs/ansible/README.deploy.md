# Deploy SONiC with ansible playbook

This doc describes the steps for deploy SONiC software on top of SONiC base image. By default,
the playbook will use public [sonicdev debian APT repository](http://packages.microsoft.com/repos/sonic-dev/)
and public [sonicdev Docker registry](https://sonicdev-microsoft.azurecr.io/).

## Requirements

- Prepare a switch with the SONiC base image. See [this link](https://github.com/Azure/SONiC/blob/gh-pages/quickstart.md)
- If you are using your own APT repo or docker registry, packages and docker images must be uploaded to the repositories before running following steps.

## Deploy SONiC

- Update [inventory](/ansible/inventory/) file with correct information for your environment.
  - ansible_host = management ip address
  - sonic_hwsku = Supported Hardware SKU, e.g. Force10-S6000, ACS-MSN2700
- Update [group_vars/sonic/variables](/ansible/group_vars/sonic/variables) file with:
  - Replace `sonicadmin_user` and `ansible_ssh_user` with the username you built into the baseimage
  - Replace `sonicadmin_initial_password` with the password you built into baseimage.
  - Update `[ntp,syslog,dns]_servers` with a list of your server IPs for these services.
  - Update APT repository if you are using private repo.
  - Update Docker [registry](/ansible/vars/docker_registry.yml/) if you are using private registry.
- Update management IP of switch1
  - Find the ManagementIPInterfaces xml block in [minigraph/switch1.xml](/ansible/minigraph/switch1.xml/) and change both IP addresses.

- Run the playbook:

```
  ansible-playbook deploy_sonic.yml -i inventory --limit switch1 --become -e "bootstrap=yes"
```

*Note: `-e "bootstrap=yes"` passes a special flag to update the initial admin password to the permanent password. This is not required after the first run.*
