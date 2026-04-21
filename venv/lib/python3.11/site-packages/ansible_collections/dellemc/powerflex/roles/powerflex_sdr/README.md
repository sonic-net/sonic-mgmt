# powerflex_sdr

Role to manage installation and uninstallation PowerFlex SDR.

## Table of contents

* [Requirements](#requirements)
* [Ansible collections](#ansible-collections)
* [Role Variables](#role-variables)
* [Examples](#examples)
* [Usage instructions](#usage-instructions)
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
    <td>powerflex_common_file_install_location</td>
    <td>false</td>
    <td>Location of required, compatible installation software package based on the operating system of the node.
    <br>The files can be downloaded from the Dell Product support page for PowerFlex software.</td>
    <td></td>
    <td>path</td>
    <td>/var/tmp</td>
  </tr>
  <tr>
    <td>powerflex_protection_domain_name</td>
    <td>false</td>
    <td>The name of the protection domain to which the SDR will be added.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_storage_pool_name</td>
    <td>false</td>
    <td>The name of the storage pool to which the device will be added.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sdr_repl_journal_capacity_max_ratio</td>
    <td>false</td>
    <td>Maximum capacity percentage to be allocated for journal capacity. Range is 0 to 100.</td>
    <td></td>
    <td>int</td>
    <td>10</td>
  </tr>
  <tr>
    <td>powerflex_mdm_password</td>
    <td>true</td>
    <td>Password for primary MDM node.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
<tr>
    <td>powerflex_sdr_state</td>
    <td>false</td>
    <td>State of the SDR.</td>
    <td>present, absent</td>
    <td>str</td>
    <td>present</td>
  </tr>
</tbody>
</table>

## Examples
----
```
  - name: Install powerflex SDR
    ansible.builtin.include_role:
      name: powerflex_sdr
    vars:
      powerflex_protection_domain_name: domain1
      powerflex_storage_pool_name: pool1
      powerflex_sdr_repl_journal_capacity_max_ratio: 10
      powerflex_sdr_state: present
      powerflex_mdm_password: Password111

  - name: Uninstall powerflex SDR
    ansible.builtin.include_role:
      name: powerflex_sdr
    vars:
      powerflex_mdm_password: Password111
      powerflex_sdr_state: absent

```

## Usage instructions
----
### To install all dependency packages, including SDR, on node:
- PowerFlex 3.6:
  ```
  ansible-playbook -i inventory site.yml
  ```
- PowerFlex 4.5:
  ```
  ansible-playbook -i inventory site_powerflex45.yml
  ```

### To uninstall SDR:
- PowerFlex 3.6:
  ```
  ansible-playbook -i inventory uninstall_powerflex.yml
  ```
- PowerFlex 4.5:
  ```
  ansible-playbook -i inventory uninstall_powerflex45.yml
  ```

Sample playbooks and inventory can be found in the playbooks directory.

## Author Information
------------------

Dell Technologies <br>
Abhishek Sinha (ansible.team@Dell.com) 2023