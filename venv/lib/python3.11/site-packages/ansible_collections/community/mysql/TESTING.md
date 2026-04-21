# Tests

This collection uses GitHub Actions to run ansible-test to validate its content. Three type of tests are used: Sanity, Integration and Units.

The tests covers plugins and roles (no role available yet, but tests are ready) and can be found here:

- Plugins: *.github/workflows/ansible-test-plugins.yml*
- Roles: *.github/workflows/ansible-test-roles.yml* (unused yet)

Everytime you push on your fork or you create a pull request, both workflows runs. You can see the output on the "Actions" tab.


## Integration tests

You can use GitHub to run ansible-test either on the community repo or your fork. But sometimes you want to quickly test a single version or a single target. To do that, you can use the Makefile present at the root of this repository.

For now, the makefile only supports Podman.


### Requirements

- python >= 3.8
- make
- podman
- Minimum 15GB of free space on the device storing containers images and volumes. You can use this command to check: `podman system info --format='{{.Store.GraphRoot}}'|xargs findmnt --noheadings --nofsroot --output SOURCE --target|xargs df -h --output=size,used,avail,pcent,target`
- Minimum 2GB of RAM


### ansible-test environment

Integration tests use the default container from ansible-test. Then required packages for the tests are installed from the `setup_controller` target located in the `tests/integration/targets` folder.


### Makefile options

The Makefile accept the following options

- `local_python_version`
  - Mandatory: false
  - Choices:
    - "3.8"
    - "3.9"
    - "3.10"
    - "3.11" (for stable-2.15+)
  - Description: If `Python -V` shows an unsupported version, use this option to select a compatible Python version available on your system. Use `ls /usr/bin/python3*|grep -v config` to list the available versions (You may have to install one). Unsupported versions are those that are too recent for the Ansible version you are using. In such cases, you will see an error message similar to: 'This version of ansible-test cannot be executed with Python version 3.12.3. Supported Python versions are: 3.9, 3.10, 3.11'.

- `ansible`
  - Mandatory: true
  - Choices:
    - "stable-2.15"
    - "stable-2.16"
    - "stable-2.17"
    - "devel"
  - Description: Version of ansible to install in a venv to run ansible-test

- `db_engine_name`
  - Mandatory: true
  - Choices:
    - "mysql"
    - "mariadb"
  - Description: The name of the database engine to use for the service containers that will host a primary database and two replicas.

- `db_engine_version`
  - Mandatory: true
  - Choices:
    - "8.0.38" <- mysql
    - "8.4.1" <- mysql (NOT WORKING YET, ansible-test uses Ubuntu 20.04 which is too old to install mysql-community-client 8.4)
    - "10.11.8" <- mariadb
    - "11.4.5" <- mariadb
  - Description: The tag of the container to use for the service containers that will host a primary database and two replicas. Do not use short version, like `mysql:8` (don't do that) because our tests expect a full version to filter tests precisely. For instance: `when: db_version is version ('8.0.22', '>')`. You can use any tag available on [hub.docker.com/_/mysql](https://hub.docker.com/_/mysql) and [hub.docker.com/_/mariadb](https://hub.docker.com/_/mariadb) but GitHub Action will only use the versions listed above.

- `connector_name`
  - Mandatory: true
  - Choices:
    - "pymysql"
    - "mysqlclient"
  - Description: The python package of the connector to use. In addition to selecting the test container, this value is also used for tests filtering: `when: connector_name == 'pymysql'`.

- `connector_version`
  - Mandatory: true
  - Choices:
    - "0.9.3" <- pymysql
    - "0.10.1" <- pymysql
    - "1.0.2" <- pymysql
    - "1.1.1" <- pymysql
  - Description: The version of the python package of the connector to use. This value is used to filter tests meant for other connectors.

- `target`
  - Mandatory: false
  - Choices:
    - "test_mysql_db"
    - "test_mysql_info"
    - "test_mysql_query"
    - "test_mysql_replication"
    - "test_mysql_role"
    - "test_mysql_user"
    - "test_mysql_variables"
  - Description: If omitted, all test targets will run. But you can limit the tests to a single target to speed up your tests.

- `keep_containers_alive`
  - Mandatory: false
  - Description: This option keeps all tree databases containers and the ansible-test container alive at the end of tests or in case of failure. This is useful to enter one of the containers with `podman exec -it <container-name> bash` for debugging. Rerunning the
tests will overwrite the 3 databases containers so no need to kill them in advance. But nothing will kill the ansible-test container. You must do that using `podman stop` and `podman rm`. Add any value to activate this option: `keep_containers_alive=1`

- `continue_on_errors`
  - Mandatory: false
  - Description: Tells ansible-test to continue on errors. This is the way the GitHub Action's workflow runs the tests. This can be used to catch all errors in a single run, but you'll need to scroll up to find them. Add any value to activate this option: `continue_on_errors=1`


#### Makefile usage examples:

```sh
# Run all targets
make ansible="stable-2.16" db_engine_name="mysql" db_engine_version="8.0.31" connector_name="pymysql" connector_version="1.0.2"

# A single target
make ansible="stable-2.16" db_engine_name="mysql" db_engine_version="8.0.31" connector_name="pymysql" connector_version="1.0.2" target="test_mysql_info"

# Keep databases and ansible tests containers alives
# A single target and continue on errors
make ansible="stable-2.17" db_engine_name="mysql" db_engine_version="8.0.31" connector_name="mysqlclient" connector_version="2.0.3" target="test_mysql_query" keep_containers_alive=1 continue_on_errors=1

# If your system has an usupported version of Python:
make local_python_version="3.10" ansible="stable-2.17" db_engine_name="mariadb" db_engine_version="11.4.5" connector_name="pymysql" connector_version="1.0.2"
```


### Run all tests

GitHub Action offer a test matrix that run every combination of MySQL, MariaDB and Connector against each other. To reproduce this, this repo provides a script called *run_all_tests.py*.

Examples:

```sh
python run_all_tests.py
```


### Add a new Connector or Database version

New components version should be added to this file: [.github/workflows/ansible-test-plugins.yml](https://github.com/ansible-collections/community.mysql/tree/main/.github/workflows)

Be careful to not add too much tests. The matrix creates an exponential number of virtual machines!
