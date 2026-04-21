import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']
).get_hosts('all')


def test_mongodb_cgroup_module_installed(host):
    cmd = host.run("semodule --list-modules | grep mongodb_cgroup_memory")

    assert cmd.rc == 0
