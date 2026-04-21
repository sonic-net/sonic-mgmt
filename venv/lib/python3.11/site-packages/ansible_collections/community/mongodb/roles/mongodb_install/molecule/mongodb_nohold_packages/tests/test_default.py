import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']
).get_hosts('all')


def test_mongodb_lock_file(host):
    f = host.file("/root/mongo_version_lock.success")
    assert not f.exists


def test_mongodb_packages_installed(host):
    p = host.package("mongodb-org")
    assert p.is_installed
    p = host.package("mongodb-org-server")
    assert p.is_installed
    p = host.package("mongodb-org-mongos")
    assert p.is_installed
    p = host.package("mongodb-org-tools")
    assert p.is_installed


def test_mongodb_packages_held(host):
    test_apt = host.run("which apt-mark")
    if test_apt.rc == 0:
        c = "apt-mark showhold"
    else:
        c = "yum versionlock list"
    cmd = host.run(c)
    assert cmd.rc == 0
    assert 'mongodb-org' not in cmd.stdout
