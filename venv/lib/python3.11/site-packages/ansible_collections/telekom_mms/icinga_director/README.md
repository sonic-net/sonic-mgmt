# Icinga Director Collection for Ansible

[![ci-ansible-test](https://github.com/telekom-mms/ansible-collection-icinga-director/workflows/ansible-test/badge.svg)](https://github.com/telekom-mms/ansible-collection-icinga-director/actions?query=workflow%3Aansible-test)
[![codecov](https://codecov.io/gh/telekom-mms/ansible-collection-icinga-director/branch/master/graph/badge.svg)](https://codecov.io/gh/telekom-mms/ansible-collection-icinga-director)

This Ansible collection contains:

1. Ansible [modules](plugins/modules/) to change objects in Icinga 2 using the director API. 
Additionally all supported modules have an appropriate `*_info`-module to gather facts about the existing objects in the director.

    * `icinga_command_template`
    * `icinga_command`
    * `icinga_endpoint`
    * `icinga_host_template`
    * `icinga_host`
    * `icinga_hostgroup`
    * `icinga_notification`
    * `icinga_notification_template`
    * `icinga_service`
    * `icinga_service_apply`
    * `icinga_service_template`
    * `icinga_servicegroup`
    * `icinga_serviceset`
    * `icinga_timeperiod`
    * `icinga_timeperiod_template`
    * `icinga_user_group`
    * `icinga_user_template`
    * `icinga_user`
    * `icinga_zone`

2. A module to deploy changes in the director and a corresponding info-module.

3. A [role](roles/ansible_icinga/) to change objects in Icinga 2 using the the provided modules.

4. An [inventory plugin](plugins/inventory) to use hosts and groups defined in Icinga as a dynamic inventory.

Required Ansible version: 2.14.0

Recommended Icinga-Director version: 2.11.1

## Installation

If you use Ansible >=3.0.0, this collection is included in Ansible.

If you use an older version, you can install it with Ansible Galaxy:

```
ansible-galaxy collection install telekom_mms.icinga_director
```

Alternatively put the collection into a `requirements.yml`-file:

```
---
collections:
- telekom_mms.icinga_director
```

## Documentation

Our modules include documentation.

You can find the complete documentation for the modules in the [docs-folder](docs) or in the [Ansible documentation](<https://docs.ansible.com/ansible/latest/collections/telekom_mms/icinga_director/index.html#plugins-in-telekom-mms-icinga-director>).

To display it on the command-line you can use the `ansible-doc` command.

For example, to see the documentation for the module `icinga_host` run the following command on the cli:

```
ansible-doc telekom_mms.icinga_director.icinga_host
```

To see the documentation for the inventory plugin, run:

```
ansible-doc -t inventory telekom_mms.icinga_director.icinga_director_inventory
```

## Examples using the modules

See the `examples` directory for a complete list of examples.

```
- hosts: localhost
  collections:
    - telekom_mms.icinga_director
  tasks:
    - name: create a host in icinga
      telekom_mms.icinga_director.icinga_host:
        state: present
        url: "https://example.com"
        url_username: "{{ icinga_user }}"
        url_password: "{{ icinga_pass }}"
        object_name: "{{ ansible_hostname }}"
        address: "{{ ansible_default_ipv4.address }}"
        display_name: "{{ ansible_hostname }}"
        groups:
          - "foo"
        imports:
          - "StandardServer"
        vars:
          dnscheck: "no"
```

```
- name: Query a service apply rule in icinga
  telekom_mms.icinga_director.icinga_service_apply_info:
    url: "{{ icinga_url }}"
    url_username: "{{ icinga_user }}"
    url_password: "{{ icinga_pass }}"
    query: "SERVICE_dummy"
  register: result
```

## Examples using the role

Please see the [README](roles/ansible_icinga/README.md) of the role.

## Examples using the inventory plugin

Create a file that ends with `icinga_director_inventory.yaml`, for example `inventory.icinga_director_inventory.yaml`.

The content should look like this:

```
plugin: telekom_mms.icinga_director.icinga_director_inventory
url: "https://example.com"
url_username: foo
url_password: bar
force_basic_auth: False
```

Then you can use the dynamic inventory like this:

```
ansible-playbook -i inventory.icinga_director_inventory.yaml path/to/your/playbook.yml
```

## Example using module defaults groups

With ansible-core >= 2.12 it is possible to specify defaults parameters for all modules in this collection using [Module defaults groups](https://docs.ansible.com/ansible/latest/user_guide/playbooks_module_defaults.html#module-defaults-groups). Use it like this:

```
- hosts: localhost

  module_defaults:
    group/telekom_mms.icinga_director.icinga:
      url: "https://example.com"
      url_username: foo
      url_password: bar

  tasks:
    - name: Create host
      telekom_mms.icinga_director.icinga_host:
        object_name: myhost
        address: 172.0.0.1

    - name: Create command
      telekom_mms.icinga_director.icinga_command:
        object_name: my-command
        command: my-command.sh
```

## Examples for defining multiple assign_filter conditions

The Icinga Director API expects multiple conditions for the `assign_filter` in a different format than what is rendered to the configuration files.

Example: An assign condition in the config looking like this:

```
assign where host.vars.something == "foo" || host.vars.something_else == "bar"
```

would have to look like this when using the module:

```
assign_filter: 'host.vars.something="foo"|host.vars.something_else="bar"'
```

## Contributing

See [Contributing](CONTRIBUTING.md).

## Troubleshooting

If one of the following errors is thrown, your Icinga Director is probably sitting behind a basic authentication prompt. Use `force_basic_auth: true` in your tasks to fix the problem.
If you are using this collections' ansible role, you have to use `icinga_force_basic_auth: true` to fix this problem.

```
fatal: [localhost]: FAILED! => {"changed": false, "msg": "bad return code while creating: -1. Error message: Request failed: <urlopen error Tunnel connection failed: 302 Found>"}
```

```
failed: [localhost] => {"ansible_loop_var": "item", "changed": false, "item": "localhost", "msg": "AbstractDigestAuthHandler does not support the following scheme: 'Negotiate'", "status": -1, "url": "https://icinga-director.example.com/director/host?name=foohost"}
```

## Known Errors with different Director versions

### Director 1.11.1

When creating notifications that contain the `users`-parameter, the task might not be idempotent ([see](https://github.com/Icinga/icingaweb2-module-director/issues/2882)).

### Director 1.11.0

You cannot create usergroups because of invalid property assign_filter ([see](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/228)).

### Director 1.10.0

Existing service apply rule objects cannot be modified ([see](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/190)):

```
TASK [Add service apply rule to icinga] ********************************************************************************************
fatal: [localhost]: FAILED! => {"changed": false, "msg": "exception when deleting: 'id'"}
```

### Director 1.9.0

When creating service checks, the tasks fails ([see](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/160)):

```
failed: [icinga2-master1.localdomain] (item={'name': 'director-generic-service', 'enable_active_checks': True, 'enable_event_handler': True, 'enable_flapping': True, 'enable_notifications': True, 'eanble_passive_checks': True, 'enable_perfdata': True, 'use_agent': True, 'volatile': False}) => {"ansible_loop_var": "item", "changed": false, "item": {"eanble_passive_checks": true, "enable_active_checks": true, "enable_event_handler": true, "enable_flapping": true, "enable_notifications": true, "enable_perfdata": true, "name": "director-generic-service", "use_agent": true, "volatile": false}, "msg": "bad return code while creating: 422. Error message: Trying to recreate icinga_service (\"{\"object_name\":\"director-generic-service\"}\")"}
```

## Extras

* Use our code snippets template supported in Visual Studio Code

Please see the [README](vsc-snippets/README.md) for more information.

## License

GPLv3

## Author Information

* Sebastian Gumprich
* Lars Krahl
* Michaela Mattes
* Martin Schurz
