# Splunk Enterprise Security Ansible Collection

[![CI](https://zuul-ci.org/gated.svg)](https://dashboard.zuul.ansible.com/t/ansible/project/github.com/ansible-collections/splunk.es)
[![Codecov](https://codecov.io/gh/ansible-collections/splunk.es/branch/main/graph/badge.svg)](https://codecov.io/gh/ansible-collections/splunk.es)
[![CI](https://github.com/ansible-collections/splunk.es/actions/workflows/tests.yml/badge.svg?branch=main&event=schedule)](https://github.com/ansible-collections/splunk.es/actions/workflows/tests.yml)

This is the [Ansible
Collection](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html)
provided by the [Ansible Security Automation
Team](https://github.com/ansible-security) for automating actions in
[Splunk Enterprise Security SIEM](https://www.splunk.com/en_us/software/enterprise-security.html)

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
[splunk.es.splunk](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.splunk_httpapi.rst)|HttpApi Plugin for Splunk

### Modules
Name | Description
--- | ---
[splunk.es.adaptive_response_notable_event](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.adaptive_response_notable_event_module.rst)|Manage Splunk Enterprise Security Notable Event Adaptive Responses
[splunk.es.correlation_search](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.correlation_search_module.rst)|Manage Splunk Enterprise Security Correlation Searches
[splunk.es.correlation_search_info](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.correlation_search_info_module.rst)|Manage Splunk Enterprise Security Correlation Searches
[splunk.es.data_input_monitor](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.data_input_monitor_module.rst)|Manage Splunk Data Inputs of type Monitor
[splunk.es.data_input_network](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.data_input_network_module.rst)|Manage Splunk Data Inputs of type TCP or UDP
[splunk.es.splunk_adaptive_response_notable_events](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.splunk_adaptive_response_notable_events_module.rst)|Manage Adaptive Responses notable events resource module
[splunk.es.splunk_correlation_searches](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.splunk_correlation_searches_module.rst)|Splunk Enterprise Security Correlation searches resource module
[splunk.es.splunk_data_inputs_monitor](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.splunk_data_inputs_monitor_module.rst)|Splunk Data Inputs of type Monitor resource module
[splunk.es.splunk_data_inputs_network](https://github.com/ansible-collections/splunk.es/blob/main/docs/splunk.es.splunk_data_inputs_network_module.rst)|Manage Splunk Data Inputs of type TCP or UDP resource module

<!--end collection content-->

### Supported connections

Use splunk modules with the [`httpapi` connection
plugin](https://docs.ansible.com/ansible/latest/plugins/connection/httpapi.html).
Set certain attributes in the inventory as follows:

Example `inventory.ini`:

**NOTE:** The passwords should be stored in a secure location or an [Ansible
Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html)

**NOTE:** the default port for Splunk's REST API is 8089

    [splunk]
    splunk.example.com

    [splunk:vars]
    ansible_network_os=splunk.es.splunk
    ansible_user=admin
    ansible_httpapi_pass=my_super_secret_admin_password
    ansible_httpapi_port=8089
    ansible_httpapi_use_ssl=yes
    ansible_httpapi_validate_certs=True
    ansible_connection=httpapi

## Installing this collection

You can install the splunk collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install splunk.es

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: splunk.es
```

## Using this collection

**NOTE**: For Ansible 2.9, you may not see deprecation warnings when you run your playbooks with this collection. Use this documentation to track when a module is deprecated.

An example of using this collection to manage a log source with [Splunk Enterprise Security SIEM](https://www.splunk.com/en_us/software/enterprise-security.html) is as follows.

`inventory.ini` (Note the password should be managed by a [Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) for a production environment.

```
[splunk]
splunk.example.com

[splunk:vars]
ansible_network_os=splunk.es.splunk
ansible_user=admin
ansible_httpapi_pass=my_super_secret_admin_password
ansible_httpapi_port=8089
ansible_httpapi_use_ssl=yes
ansible_httpapi_validate_certs=True
ansible_connection=httpapi
```

### Using the modules with Fully Qualified Collection Name (FQCN)

With [Ansible
Collections](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html)
there are various ways to utilize them either by calling specific Content from
the Collection, such as a module, by its Fully Qualified Collection Name (FQCN)
as we'll show in this example or by defining a Collection Search Path as the
examples below will display.

We recommend the FQCN method but the
shorthand options listed below exist for convenience.

`splunk_with_collections_fqcn_example.yml`

```
---
- name: demo splunk
  hosts: splunk
  gather_facts: false
  tasks:
    - name: test splunk_data_input_monitor
      splunk.es.data_input_monitor:
        name: "/var/log/demo.log"
        state: "present"
        recursive: true
    - name: test splunk_data_input_network
      splunk.es.data_input_network:
        name: "9001"
        protocol: "tcp"
        state: "absent"
    - name: test splunk_coorelation_search
      splunk.es.correlation_search:
        name: "Test Demo Coorelation Search From Playbook"
        description: "Test Demo Coorelation Search From Playbook, description."
        search: 'source="/var/log/snort.log"'
        state: "present"
    - name: test splunk_adaptive_response_notable_event
      splunk.es.adaptive_response_notable_event:
        name: "Demo notable event from playbook"
        correlation_search_name: "Test Demo Coorelation Search From Playbook"
        description: "Test Demo notable event from playbook, description."
        state: "present"
        next_steps:
          - ping
          - nslookup
        recommended_actions:
          - script
```

### Define your collection search path at the Play level

Below we specify our collection at the Play level which allows us to use the
splunk modules without specifying the need for the FQCN.

`splunk_with_collections_example.yml`

```
---
- name: demo splunk
  hosts: splunk
  gather_facts: false
  collections:
    - splunk.es
  tasks:
    - name: test splunk_data_input_monitor
      data_input_monitor:
        name: "/var/log/demo.log"
        state: "present"
        recursive: true
    - name: test splunk_data_input_network
      data_input_network:
        name: "9001"
        protocol: "tcp"
        state: "absent"
    - name: test splunk_coorelation_search
      correlation_search:
        name: "Test Demo Coorelation Search From Playbook"
        description: "Test Demo Coorelation Search From Playbook, description."
        search: 'source="/var/log/snort.log"'
        state: "present"
    - name: test splunk_adaptive_response_notable_event
      adaptive_response_notable_event:
        name: "Demo notable event from playbook"
        correlation_search_name: "Test Demo Coorelation Search From Playbook"
        description: "Test Demo notable event from playbook, description."
        state: "present"
        next_steps:
          - ping
          - nslookup
        recommended_actions:
          - script
```

### Define your collection search path at the Block level

Below we use the [`block`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_blocks.html)
level keyword, we are able to use the splunk modules without the need for the
FQCN.

`splunk_with_collections_block_example.yml`

```
---
- name: demo splunk
  hosts: splunk
  gather_facts: false
  tasks:
    - name: collection namespace block
      - name: test splunk_data_input_monitor
        data_input_monitor:
          name: "/var/log/demo.log"
          state: "present"
          recursive: true
      - name: test splunk_data_input_network
        data_input_network:
          name: "9001"
          protocol: "tcp"
          state: "absent"
      - name: test splunk_coorelation_search
        correlation_search:
          name: "Test Demo Coorelation Search From Playbook"
          description: "Test Demo Coorelation Search From Playbook, description."
          search: 'source="/var/log/snort.log"'
          state: "present"
      - name: test splunk_adaptive_response_notable_event
        adaptive_response_notable_event:
          name: "Demo notable event from playbook"
          correlation_search_name: "Test Demo Coorelation Search From Playbook"
          description: "Test Demo notable event from playbook, description."
          state: "present"
          next_steps:
            - ping
            - nslookup
          recommended_actions:
            - script
      collections:
        - splunk.es
```

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [Splunk collection repository](https://github.com/ansible-collections/splunk.es). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

You can also join us on:

- IRC - the `#ansible-security` [irc.libera.chat](https://libera.chat/) channel

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Code of Conduct

This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Release notes

Release notes are available [here](https://github.com/ansible-collections/splunk.es/blob/main/changelogs/CHANGELOG.rst).

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

- [Ansible network resources](https://docs.ansible.com/ansible/latest/network/getting_started/network_resources.html)
- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

## Author Information

[Ansible Security Automation Team](https://github.com/ansible-security)
