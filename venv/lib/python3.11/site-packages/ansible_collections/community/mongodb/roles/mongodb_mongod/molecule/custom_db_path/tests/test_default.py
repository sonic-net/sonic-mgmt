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

    if host.system_info.distribution == "debian" \
            or host.system_info.distribution == "ubuntu":
        vars_file_path = os.path.join(trimmed_path, 'vars', 'Debian.yml')
        ansible = host.ansible('include_vars',
                               f'file="{vars_file_path}"',
                               False,
                               False)
    else:
        vars_file_path = os.path.join(trimmed_path, 'vars', 'RedHat.yml')
        ansible = host.ansible('include_vars',
                               f'file="{vars_file_path}"',
                               False,
                               False)
    return ansible


def test_mongod_cnf_file(host):
    mongodb_user = include_vars(host)['ansible_facts']['mongodb_user']
    mongodb_group = include_vars(host)['ansible_facts']['mongodb_group']
    f = host.file('/etc/mongod.conf')

    assert f.exists
    assert f.user == mongodb_user
    assert f.group == mongodb_group


def test_mongod_service(host):
    mongod_service = include_vars(host)['ansible_facts']['mongod_service']
    s = host.service(mongod_service)

    assert s.is_running
    assert s.is_enabled


def test_mongod_port(host):
    try:
        port = include_vars(host)['ansible_facts']['mongod_port']
    except KeyError:
        port = 27017
    s = host.socket("tcp://0.0.0.0:{0}".format(port))
    assert s.is_listening


def test_mongod_replicaset(host):
    '''
    Ensure that the MongoDB replicaset has been created successfully
    '''
    try:
        port = include_vars(host)['ansible_facts']['mongod_port']
    except KeyError:
        port = 27017
    cmd = "mongosh --port {0} --eval 'rs.status()'".format(port)
    # We only want to run this once
    if host.ansible.get_variables()['inventory_hostname'] == "ubuntu2204":
        r = host.run(cmd)
        assert "rs0" in r.stdout
        assert "amazon2023:{0}".format(port) in r.stdout
        assert "debian12:{0}".format(port) in r.stdout
        assert "ubuntu2204:{0}".format(port) in r.stdout
        assert "almalinux9:{0}".format(port) in r.stdout
        assert "rockylinux9:{0}".format(port) in r.stdout


def test_mongod_config_custom_path(host):
    '''
    Ensure that the custom path is respected
    '''
    default_path = "/data/db"

    # assert path exists
    f = host.file(default_path)
    assert f.exists
    assert f.is_directory
    # assert mongodb.conf contains path
    conf = host.file('/etc/mongod.conf').content_string
    assert "dbPath: {0}".format(default_path) in conf
