from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ["MOLECULE_INVENTORY_FILE"]
).get_hosts("all")


def test_directories(host):
    dirs = [
        "/etc/otel-collector",
    ]
    files = ["/etc/otel-collector/config.yaml"]
    for directory in dirs:
        d = host.file(directory)
        assert d.is_directory
        assert d.exists
    for file in files:
        f = host.file(file)
        assert f.exists
        assert f.is_file


def test_service(host):
    s = host.service("otel-collector")
    # assert s.is_enabled
    assert s.is_running


def test_socket(host):
    assert host.socket("tcp://127.0.0.1:9999").is_listening
