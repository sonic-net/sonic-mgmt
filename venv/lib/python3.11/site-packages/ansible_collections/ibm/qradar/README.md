# IBM QRadar Ansible Collection

[![CI](https://zuul-ci.org/gated.svg)](https://dashboard.zuul.ansible.com/t/ansible/project/github.com/ansible-collections/ibm.qradar) <!--[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/vyos)](https://codecov.io/gh/ansible-collections/ibm.qradar)-->
[![Codecov](https://codecov.io/gh/ansible-collections/ibm.qradar/branch/main/graph/badge.svg)](https://codecov.io/gh/ansible-collections/ibm.qradar)
[![CI](https://github.com/ansible-collections/ibm.qradar/actions/workflows/tests.yml/badge.svg?branch=main&event=schedule)](https://github.com/ansible-collections/ibm.qradar/actions/workflows/tests.yml)

This is the [Ansible
Collection](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html)
provided by the [Ansible Security Automation
Team](https://github.com/ansible-security) for automating actions in [IBM
QRadar SIEM](https://www.ibm.com/us-en/marketplace/ibm-qradar-siem).

This Collection is meant for distribution through
[Ansible Galaxy](https://galaxy.ansible.com/) as is available for all
[Ansible](https://github.com/ansible/ansible) users to utilize, contribute to,
and provide feedback about.

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.15.0**.

For collections that support Ansible 2.9, please ensure you update your `network_os` to use the
fully qualified collection name (for example, `cisco.ios.ios`).
Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

## Collection Content
<!--start collection content-->
### Httpapi plugins
Name | Description
--- | ---
[ibm.qradar.qradar](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.qradar_httpapi.rst)|HttpApi Plugin for IBM QRadar

### Modules
Name | Description
--- | ---
[ibm.qradar.deploy](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.deploy_module.rst)|Trigger a qradar configuration deployment
[ibm.qradar.log_source_management](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.log_source_management_module.rst)|Manage Log Sources in QRadar
[ibm.qradar.offense_action](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.offense_action_module.rst)|Take action on a QRadar Offense
[ibm.qradar.offense_info](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.offense_info_module.rst)|Obtain information about one or many QRadar Offenses, with filter options
[ibm.qradar.offense_note](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.offense_note_module.rst)|Create or update a QRadar Offense Note
[ibm.qradar.qradar_analytics_rules](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.qradar_analytics_rules_module.rst)|Qradar Analytics Rules Management resource module
[ibm.qradar.qradar_log_sources_management](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.qradar_log_sources_management_module.rst)|Qradar Log Sources Management resource module
[ibm.qradar.rule](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.rule_module.rst)|Manage state of QRadar Rules, with filter options
[ibm.qradar.rule_info](https://github.com/ansible-collections/ibm.qradar/blob/main/docs/ibm.qradar.rule_info_module.rst)|Obtain information about one or many QRadar Rules, with filter options

<!--end collection content-->

## Installing this collection

You can install the IBM qradar collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install ibm.qradar

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: ibm.qradar
```

## Using the IBM QRadar Ansible Collection

An example for using this collection to manage a log source with [IBM QRadar](https://www.ibm.com/security/security-intelligence/qradar) is as follows.

`inventory.ini` (Note the password should be managed by a [Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) for a production environment.
```
[qradar]
qradar.example.com

[qradar:vars]
ansible_network_os=ibm.qradar.qradar
ansible_user=admin
ansible_httpapi_pass=SuperSekretPassword
ansible_httpapi_use_ssl=true
ansible_httpapi_validate_certs=true
ansible_connection=httpapi
```

**NOTE**: For Ansible 2.9, you may not see deprecation warnings when you run your playbooks with this collection. Use this documentation to track when a module is deprecated.

### Using the modules with Fully Qualified Collection Name (FQCN)

With [Ansible
Collections](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html)
there are various ways to utilize them either by calling specific Content from
the Collection, such as a module, by its Fully Qualified Collection Name (FQCN)
as we'll show in this example or by defining a Collection Search Path as the
examples below will display.

I should be noted that the FQCN method is the recommended method but the
shorthand options listed below exist for convenience.

`qradar_with_collections_example.yml`
```
---
- name: Testing URI manipulation of QRadar with FQCN
  hosts: qradar
  gather_facts: false
  tasks:
    - name: create log source
      ibm.qradar.log_source_management:
        name: "Ansible Collections Example Log Source"
        type_name: "Linux OS"
        state: present
        description: "Ansible Collections Example Log Source Description"
```

### Define your collection search path at the Play level

Below we specify our collection at the
[Play](https://docs.ansible.com/ansible/latest/user_guide/playbooks_intro.html)
level which allows us to use the `log_source_management` module without
the need for the FQCN for each task.

`qradar_with_collections_example.yml`
```
---
- name: Testing URI manipulation of QRadar
  hosts: qradar
  gather_facts: false
  collections:
    - ibm.qradar
  tasks:
    - name: create log source
      log_source_management:
        name: "Ansible Collections Example Log Source"
        type_name: "Linux OS"
        state: present
        description: "Ansible Collections Example Log Source Description"
```

### Define your collection search path at the Block level

Another option for Collection use is below. Here we use the
[`block`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_blocks.html)
level keyword instead of [Play](https://docs.ansible.com/ansible/latest/user_guide/playbooks_intro.html)
level as with the previous example. In this scenario we are able to use the
`log_source_management` module without the need for the FQCN for each
task but with an optionally more specific scope of Collection Search Path than
specifying at the Play level.

`qradar_with_collections_block_example.yml`
```
---
- name: Testing URI manipulation of QRadar
  hosts: qradar
  gather_facts: false
  tasks:
    - name: collection namespace block
      block:
        - name: create log source
          log_source_management:
            name: "Ansible Collections Example Log Source"
            type_name: "Linux OS"
            state: present
            description: "Ansible Collections Example Log Source Description"
      collections:
        - ibm.qradar
```

### Directory Structure

* `docs/`: local documentation for the collection
* `license.txt`: optional copy of license(s) for this collection
* `galaxy.yml`: source data for the MANIFEST.json that will be part of the collection package
* `playbooks/`: playbooks reside here
  * `tasks/`: this holds 'task list files' for `include_tasks`/`import_tasks` usage
* `plugins/`: all ansible plugins and modules go here, each in its own subdir
  * `modules/`: ansible modules
  * `lookups/`: lookup plugins
  * `filters/`: Jinja2 filter plugins
  * ... rest of plugins
* `README.md`: information file (this file)
* `roles/`: directory for ansible roles
* `tests/`: tests for the collection's content

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [IBM QRadar collection repository](https://github.com/ansible-collections/ibm.qradar). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

You can also join us on:

- IRC - the ``#ansible-community`` [irc.libera.chat](https://libera.chat/) channel

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Release notes

Release notes are available [here](https://github.com/ansible-collections/ibm.qradar/blob/main/changelogs/CHANGELOG.rst).

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
