# Overview of SONiC deployment, testbed setup and tests

This ansible playbook consists following functionalities:
- [Deploy SONiC](README.deploy.md)
- [Setup SONiC testbed](README.testbed.md)
- [Run SONiC tests](README.test.md)

# Installing Ansible
```
apt-get install git gcc make python python-dev python-pip python-cffi libffi-dev libssl-dev sshpass
pip install setuptools # version from the distribution is too old
git clone https://github.com/ansible/ansible
cd ansible
git checkout v2.0.0.2-1 -b v2.0.0.2-1
git submodule update --init --recursive
make
sudo make install
```
Note: v2.0.0.2 is the currently tested Ansible version.  Other versions may not work correctly.

# Ansible playbood layout

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
