#Installing Ansible
1. git clone https://github.com/ansible/ansible
2. cd ansible
3. git checkout v2.0.0.2-1 -b v2.0.0.2-1
4. git submodule update --init --recursive
5. make
6. sudo make install

Note: v2.0.0.2 is the currently tested Ansible version.  Other versions may not work correctly.


#How to use this Ansible sample playbook to deploy SONiC:

1. Prepare a switch with the SONiC base image. See: https://github.com/Azure/SONiC/blob/gh-pages/quickstart.md
2. Update inventory file with appropriate information for your environment:
  * ansible_host = management ip address
  * sonic_hwsku = Supported Hardware SKU, e.g. ACS-S6000
3. Update group_vars/sonic/vars file with:
  * Replace 'password' with your own passwords. Note: Leave the initial_password as 123456.
  * apt_repo_ip = The ip address (or FQDN) of your APT mirror, typically private.
  * [ntp,syslog,dns]_servers = A list of your server IPs for these services. 
  * snmp_rocommunity = your internal snmp community string.
  * Replace sonicadmin_user and ansible_ssh_user with the username you built into the baseimage
4. Update vars/docker_registry.yml:
  * docker_registry_host = FQDN:port of your docker registry
  * docker_registry_username = username of your docker registry
  * docker_registry_password = password of your docker registry
5. Update host_vars/switch1/minigraph_facts.yml:
  * Update minigraph_mgmt_interface block with the address/gateway/mask/prefix information for your management interface
6. Update roles/sonic-common/files/apt/sonic.gpg.key with the contents of your apt repo signing key.
7. Run the playbook:

  ansible-playbook deploy_sonic.yml -i inventory --limit switch1 --become -e "bootstrap=yes"

Note: '-e "bootstrap=yes"' passes a special flag to update the initial admin password to the permenant password. This is not required after the first run.


``` 
# Ansible top level file and directory structure
# adapted from http://docs.ansible.com/ansible/playbooks_best_practices.html

prod                      # inventory file for production servers
pre_prod                  # inventory file for staging environment
lab                       # inventory file for test lab environment

group_vars/
   prod                   # here we assign variables to particular groups
   pre_prod               # groups can be environments, geographical, role based
   lab

host_vars/
   hostname1              # if an individual system must have specific variables, put them here
   hostname2              # (use of host_vars should be avoided)

library/                  # if any custom modules, put them here (optional)
filter_plugins/           # if any custom filter plugins, put them here (optional)

deploy_sonic.yml          # playbook to initialize a SONiC switch after imaging process is complete
integration_test.yml      # playbook to run all integration tests

roles/
    sonic_common/         # common "role" for the SONiC switch, only add tasks here that are for all SONiC switches
        tasks/            #
            main.yml      #  <-- tasks file can include smaller files if warranted
        handlers/         #
            main.yml      #  <-- handlers file
        templates/        #  <-- files for use with the template resource
            ntp.conf.j2   #  <------- templates end in .j2
        files/            #
            bar.txt       #  <-- files for use with the copy resource
            foo.sh        #  <-- script files for use with the script resource
        vars/             #
            main.yml      #  <-- variables associated with this role
        defaults/         #
            main.yml      #  <-- default lower priority variables for this role
        meta/             #
            main.yml      #  <-- role dependencies
    sonicv2/              # role for installing SONiC v2 components (syncd, orchagent, quagga, etc)

    sonic_test/           # same kind of structure as above, but for the integration test role, 
                          #        see http://github.com/Azure/sonic-integrationtest
    sonic_vm/             # for a future, vm based deployment of sonic
    sonic_s6000/          # place Dell s6000 specific tasks here
    sonic_msn2700/        # place Mellanox msn2700 specific tasks here
```
