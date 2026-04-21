from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import testinfra.utils.ansible_runner
import os

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    '/cyberark/dev/inventory.tmp').get_hosts('testapp')


def test_hosts_file(host):
    f = host.file('/etc/hosts')

    assert f.exists
    assert f.user == 'root'
    assert f.group == 'root'


def test_is_conjurized(host):
    identity_file = host.file('/etc/conjur.identity')

    assert identity_file.exists
    assert identity_file.user == 'root'

    conf_file = host.file('/etc/conjur.conf')

    assert conf_file.exists
    assert conf_file.user == 'root'


def test_retrieve_secret_with_summon(host):
    # Get the environment variable
    is_cloud = os.getenv('IS_CLOUD')

    # Construct the path based on flavour
    if is_cloud == 'true':
        path = 'data/ansible/target-password'
    else:
        path = 'ansible/target-password'

    # Run the command with the constructed path
    result = host.check_output(f"summon --yaml 'DB_USERNAME: !var {path}' bash -c 'printenv DB_USERNAME'", shell=True)

    assert result == "target_secret_password"
