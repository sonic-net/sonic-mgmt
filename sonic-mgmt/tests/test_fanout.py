import pytest
from tests.common.helpers.pfc_storm import PFCStorm

'''
Script to check if the fanout is working as required.
./run_tests.sh -n t0-yy38 -d t0-yy38 -u -e '-s --disable_loganalyzer' -c test_fanout.py

The following config changes are needed to make it work.
1-a. Add a user called : "shelladmin/shellpassword" in the fanout host.
config t
username shelladmin password 0 shellpassword  role priv-15
username shelladmin shelltype bash
username shelladmin role network-admin
username shelladmin passphrase  lifetime 99999 warntime 7 gracetime 3

1-b. Add the shell user to sudoers group in fanout.
run bash
sudo vi /etc/sudoers
search for admin in the file, and change it to admin,shelladmin
BE CAREFUL, WRONG FORMAT IN THIS FILE WILL RESULT IN "SUDO" FAILING
IN THE DEVICE.

2. Add the following to the ansible/group_vars/fanout/secrets.yaml:
ansible_ssh_user: admin
ansible_ssh_pass: roZes@123
fanout_network_user: admin
fanout_network_password: roZes@123
fanout_shell_user: shelladmin
fanout_shell_password: shellpassword

3. Add the following entry to "[defaults]" section in ansible/ansible.cfg:
allow_world_readable_tmpfiles = true

4. 
'''

@pytest.mark.parametrize("mode", ["nxos", "shell"])
def test_fanout(fanouthosts, duthosts, mode):
    for host in fanouthosts:
        try:
            if mode == "shell":
                fanouthosts[host].shell("sudo who am i")
            else:
                fanouthosts[host].nxos_command(commands=["show version"])
        except:
            raise RuntimeError("host:{} is not in {} mode.".format(host, mode))

