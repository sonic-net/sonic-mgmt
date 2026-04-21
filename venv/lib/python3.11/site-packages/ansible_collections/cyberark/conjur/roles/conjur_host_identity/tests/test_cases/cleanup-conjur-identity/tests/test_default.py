from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    '/cyberark/dev/inventory.tmp').get_hosts('testapp')


def test_hosts_file(host):
    f = host.file('/etc/hosts')

    assert f.exists
    assert f.user == 'root'
    assert f.group == 'root'


def test_is_not_conjurized(host):
    identity_file = host.file('/etc/conjur.identity')
    assert not identity_file.exists

    conf_file = host.file('/etc/conjur.conf')
    assert not conf_file.exists
