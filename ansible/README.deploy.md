# Deploy SONiC with ansible playbook

This doc describes the steps for deploy SONiC software on top of SONiC base image.

## Requirements

- Prepare a switch with the SONiC base image. See [this link](https://github.com/Azure/SONiC/blob/gh-pages/quickstart.md)
- Setup debian APT repository for deb packages to be installed into the base image directly, such as [DELL platform drivers](https://github.com/Azure/sonic-platform-modules-s6000).
- Setup Docker registry for docker images, such as syncd docker built from [sonic-buildimage](https://github.com/Azure/sonic-buildimage)

Packages and docker images must be uploaded to the repositories before running following steps.

### Setup docker registry

- Prepare docker registry (HOWTO)
  * TBD

- Update vars/docker_registry.yml:
  * docker_registry_host = FQDN:port of your docker registry
  * docker_registry_username = username of your docker registry
  * docker_registry_password = password of your docker registry

### Setup debian repository 

- Prepare debian repository
  * TBD

- Update roles/sonic-common/files/apt/sonic.gpg.key with the contents of your apt repo signing key.

## Deploy SONiC

- Update inventory file with appropriate information for your environment:
  * ansible_host = management ip address
  * sonic_hwsku = Supported Hardware SKU, e.g. ACS-S6000
- Update group_vars/sonic/vars file with:
  * Replace 'password' with your own passwords. Note: Leave the initial_password as 123456.
  * apt_repo_ip = The ip address (or FQDN) of your APT mirror, typically private.
  * [ntp,syslog,dns]_servers = A list of your server IPs for these services. 
  * snmp_rocommunity = your internal snmp community string.
  * Replace sonicadmin_user and ansible_ssh_user with the username you built into the baseimage
- Update host_vars/switch1/minigraph_facts.yml:
  * Update minigraph_mgmt_interface block with the address/gateway/mask/prefix information for your management interface
- Run the playbook:

  ansible-playbook deploy_sonic.yml -i inventory --limit switch1 --become -e "bootstrap=yes"

Note: '-e "bootstrap=yes"' passes a special flag to update the initial admin password to the permenant password. This is not required after the first run.
