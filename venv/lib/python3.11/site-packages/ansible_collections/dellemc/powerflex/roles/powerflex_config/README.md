# powerflex_config

Role to configure the protection domain, fault set and storage pool.

## Table of contents

* [Requirements](#requirements)
* [Ansible collections](#ansible-collections)
* [Role Variables](#role-variables)
* [Examples](#examples)
* [Usage instructions](#usage-instructions)
* [Notes](#notes)
* [Author Information](#author-information)

## Requirements

```
ansible
python
```

## Ansible collections

Collections required to use the role.

```
dellemc.powerflex
```

## Role Variables

<table>
<thead>
  <tr>
    <th>Name</th>
    <th>Required</th>
    <th>Description</th>
    <th>Choices</th>
    <th>Type</th>
    <th>Default Value</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>hostname</td>
    <td>true</td>
    <td>IP or FQDN of the PowerFlex host.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>username</td>
    <td>true</td>
    <td>The username of the PowerFlex host.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>password</td>
    <td>true</td>
    <td>The password of the PowerFlex host.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>port</td>
    <td>false</td>
    <td>Port of the PowerFlex host.</td>
    <td></td>
    <td>int</td>
    <td>443</td>
  </tr>
  <tr>
    <td>validate_certs</td>
    <td>false</td>
    <td>If C(false), the SSL certificates will not be validated.<br>Configure C(false) only on personally controlled sites where self-signed certificates are used.</td>
    <td></td>
    <td>bool</td>
    <td>false</td>
  </tr>
  <tr>
    <td>powerflex_protection_domain_name</td>
    <td>false</td>
    <td>Name of the protection domain.<br></td>
    <td></td>
    <td>str</td>
    <td>config_protection_domain</td>
  </tr>
  <tr>
    <td>powerflex_fault_sets</td>
    <td>false</td>
    <td>List of fault sets.<br></td>
    <td></td>
    <td>list</td>
    <td>['fs1','fs2','fs3']</td>
  </tr>
  <tr>
    <td>powerflex_media_type</td>
    <td>false</td>
    <td>Media type of the storage pool.<br></td>
    <td>'SSD', 'HDD', 'TRANSITIONAL'</td>
    <td>str</td>
    <td>SSD</td>>
  </tr>
  <tr>
    <td>powerflex_storage_pool_name</td>
    <td>false</td>
    <td>Name of the storage pool.<br></td>
    <td></td>
    <td>str</td>
    <td>config_storage_pool</td>
  </tr>
</tbody>
</table>

## Examples
----
```
  - name: Configuration of protection domain, fault set and storage pool.
    ansible.builtin.import_role:
      name: "powerflex_config"
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_protection_domain_name: "protection_domain"
      powerflex_fault_sets:
        - 'fs1'
        - 'fs2'
        - 'fs3'
      powerflex_media_type: 'SSD'
      powerflex_storage_pool_name: "storage_pool"

```

## Usage instructions
----
### To configure the protection domain and storage pool:
- PowerFlex 3.6:
  ```
  ansible-playbook -i inventory site.yml
  ```
- PowerFlex 4.5:
  ```
  ansible-playbook -i inventory site_powerflex45.yml
  ```

Sample playbooks and inventory can be found in the playbooks directory.

## Notes
----

- As a pre-requisite, the Gateway must be installed.
- TRANSITIONAL media type is supported only during modification.

## Author Information
------------------

Dell Technologies </br>
Felix Stephen A (ansible.team@Dell.com)  2023
