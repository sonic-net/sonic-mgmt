import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']
).get_hosts('all')


def include_vars(host):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    path_components = current_dir.split(os.sep)
    trim_count = 0
    # Weird bug where the path of this file is incorrect
    # It seems the ansible module, at least when used here
    # Used to run in a different directory, meaning the
    # relative path was not correct. This method should mean it's
    # always correct whatever the context.
    for component in path_components:
        if component.startswith("mongodb_"):
            break
        else:
            trim_count += 1
    trim_count = (len(path_components) - 1) - trim_count
    # Trim off the dirs after the role dir
    trimmed_components = path_components[:-trim_count]
    trimmed_path = os.sep.join(trimmed_components)
    vars_file_path = os.path.join(trimmed_path, 'defaults', 'main.yml')
    ansible = host.ansible('include_vars',
                           f'file="{vars_file_path}"',
                           False,
                           False)
    # print(str(ansible))
    return ansible


def get_mongodb_version(host):
    return include_vars(host)['ansible_facts']['mongodb_version']


def test_redhat_mongodb_repository_file(host):
    # with capsys.disabled(): #Disable autocapture of output and send to stdout N.B capsys must be passed into function
    # print(include_vars(host)['ansible_facts'])
    mongodb_version = get_mongodb_version(host)
    if host.system_info.distribution == "redhat" \
            or host.system_info.distribution == "centos" \
            or host.system_info.distribution == "amazon":
        f = host.file("/etc/yum.repos.d/mongodb-{0}.repo".format(mongodb_version))
        assert f.exists
        assert f.user == 'root'
        assert f.group == 'root'
        assert f.mode == 0o644
        assert f.md5sum == "dbcb01e2e25b6d10afd27b60205136c3"


def test_redhat_yum_search(host):
    mongodb_version = get_mongodb_version(host)
    if host.system_info.distribution == "redhat" \
            or host.system_info.distribution == "centos" \
            or host.system_info.distribution == "amazon":
        cmd = host.run("yum search mongodb --disablerepo='*' \
                            --enablerepo='mongodb-{0}'".format(mongodb_version))

        assert cmd.rc == 0
        assert "MongoDB database server" in cmd.stdout


def test_debian_mongodb_repository_file(host):
    mongodb_version = get_mongodb_version(host)
    if host.system_info.distribution == "debian" \
            or host.system_info.distribution == "ubuntu":
        f = host.file("/etc/apt/sources.list.d/mongodb-{0}.list".format(mongodb_version))

        assert f.exists
        assert f.user == 'root'
        assert f.group == 'root'
        assert f.mode == 0o644
        assert "repo.mongodb.org" in f.content_string
        assert mongodb_version in f.content_string


def test_debian_apt_search(host):
    if host.system_info.distribution == "debian" \
            or host.system_info.distribution == "ubuntu":
        cmd = host.run("apt search mongodb")

        assert cmd.rc == 0
        assert "mongodb" in cmd.stdout
