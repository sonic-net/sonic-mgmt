import os
import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_hosts_file(host):
    f = host.file('/etc/hosts')

    assert f.exists
    assert f.user == 'root'
    assert f.group == 'root'


proxysql_user_attributes = ("user_name,"
                            "group_name")


@pytest.mark.parametrize(proxysql_user_attributes, [
    ("proxysql", "proxysql"),
])
def test_proxysql_users(host,
                        user_name,
                        group_name):
    u = host.user(user_name)

    assert u.exists
    assert u.group == group_name


proxysql_file_attributes = ("proxysql_file,"
                            "proxysql_file_user,"
                            "proxysql_file_group,"
                            "proxysql_file_mode")


@pytest.mark.parametrize(proxysql_file_attributes, [
    ("/root/.my.cnf", None, None, 0o600),
    ("/etc/proxysql.cnf", "proxysql", "proxysql", 0o644),
])
def test_proxysql_files(host,
                        proxysql_file,
                        proxysql_file_user,
                        proxysql_file_group,
                        proxysql_file_mode):
    f = host.file(proxysql_file)

    assert f.exists
    assert f.is_file
    if proxysql_file_user:
        assert f.user == proxysql_file_user
    if proxysql_file_group:
        assert f.group == proxysql_file_group
    if proxysql_file_mode:
        assert f.mode == proxysql_file_mode


@pytest.mark.parametrize("proxysql_package", [
    ("percona-server-client-5.7"),
    ("proxysql"),
])
def test_proxysql_packages(host,
                           proxysql_package):

    pkg = host.package(proxysql_package)

    assert pkg.is_installed


@pytest.mark.parametrize("proxysql_service", [
    ("proxysql"),
])
def test_proxysql_services(host,
                           proxysql_service):
    svc = host.service(proxysql_service)

    assert svc.is_enabled
    assert svc.is_running
