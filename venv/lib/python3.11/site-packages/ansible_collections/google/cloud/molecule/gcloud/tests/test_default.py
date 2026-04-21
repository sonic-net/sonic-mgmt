from __future__ import (absolute_import, division, print_function)
import os
import testinfra.utils.ansible_runner

__metaclass__ = type

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_service(host):
    service = host.service('docker')

    assert service.is_running
    assert service.is_enabled


def test_hosts_file(host):
    f = host.file('/etc/hosts')

    assert f.exists
    assert f.user == 'root'
    assert f.group == 'root'
