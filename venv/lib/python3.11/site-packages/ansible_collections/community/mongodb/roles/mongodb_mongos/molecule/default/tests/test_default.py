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
    if host.ansible.get_variables()['inventory_hostname'] != 'config1':
        mongodb_user = include_vars(host)['ansible_facts']['mongodb_user']
        mongodb_group = include_vars(host)['ansible_facts']['mongodb_group']
        f = host.file('/etc/mongos.conf')

        assert f.exists
        assert f.user == mongodb_user
        assert f.group == mongodb_group


def test_mongod_service(host):

    if host.ansible.get_variables()['inventory_hostname'] != 'config1':
        mongos_service = include_vars(host)['ansible_facts']['mongos_service']
        s = host.service(mongos_service)

        assert s.is_running
        assert s.is_enabled


def test_mongod_port(host):
    if host.ansible.get_variables()['inventory_hostname'] != 'config1':
        port = include_vars(host)['ansible_facts']['mongos_port']
        s = host.socket("tcp://0.0.0.0:{0}".format(port))

        assert s.is_listening


def test_mongos_shell_connectivity(host):
    '''
    Tests that we can connect to mongos via the shell annd run a cmd
    '''
    if host.ansible.get_variables()['inventory_hostname'] != 'config1':
        port = include_vars(host)['ansible_facts']['mongos_port']
        cmd = host.run("mongosh admin --username admin --password admin --port {0} --eval 'db.runCommand({{listDatabases: 1}})'".format(port))

        assert cmd.rc == 0
        assert "config" in cmd.stdout
        assert "admin" in cmd.stdout
