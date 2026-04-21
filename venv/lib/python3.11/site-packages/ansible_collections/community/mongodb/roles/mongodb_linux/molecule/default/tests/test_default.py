import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']
).get_hosts('all')


def test_ntp_package(host):
    ntp = host.package("ntp")
    chrony = host.package("chrony")
    ntpsec = host.package("ntpsec")
    timesyncd = host.package("systemd-timesyncd")
    assert ntp.is_installed or chrony.is_installed or ntpsec.is_installed or timesyncd.is_installed


def test_ntpd_service(host):
    ntpd = host.service("ntpd")

    if ntpd.is_running:
        assert ntpd.is_enabled
    else:
        ntp = host.service("ntp")
        if ntp.is_running:
            assert ntp.is_enabled
        else:
            chronyd = host.service("chronyd")
            if chronyd.is_running:
                assert chronyd.is_enabled
            else:
                timesyncd = host.service("systemd-timesyncd")
                assert timesyncd.is_running
                assert timesyncd.is_enabled


def test_swappiness_value(host):
    cmd = host.run("cat /proc/sys/vm/swappiness")

    assert cmd.rc == 0
    assert cmd.stdout.strip() == "1"


def test_thp_service_file(host):
    f = host.file("/etc/systemd/system/manage-transparent-huge-pages.service")

    assert f.exists
    assert f.user == "root"
    assert f.group == "root"


def test_thp_service(host):
    '''
    Validates the service actually works
    '''
    switches = ["/sys/kernel/mm/transparent_hugepage/enabled",
                "/sys/kernel/mm/transparent_hugepage/defrag"]

    facts = host.ansible("setup")["ansible_facts"]
    virt_types = facts.get("ansible_virtualization_tech_guest", [facts["ansible_virtualization_type"]])
    in_docker = "container" in virt_types or "docker" in virt_types
    # in_docker is false on GHA here since they use custom parent cgroup (actions_job)
    if not in_docker and facts["ansible_virtualization_role"] == "guest":
        # inspecting cgroups is iffy on GHA, so use the /.dockerenv file
        in_docker = host.file("/.dockerenv").exists

    for d in switches:
        cmd = host.run("cat {0}".format(d))

        assert cmd.rc == 0
        assert "[never]" in cmd.stdout


def test_limit_file(host):
    f = host.file("/etc/security/limits.conf")

    assert f.exists
    assert f.user == "root"
    assert f.group == "root"

    assert f.contains("mongodb	hard	nproc	64000")
    assert f.contains("mongodb	hard	nofile	64000")
    assert f.contains("mongodb	soft	nproc	64000")
    assert f.contains("mongodb	soft	nofile	64000")
    assert f.contains("mongodb	hard	memlock	1024")
    assert f.contains("mongodb	soft	memlock	1024")
