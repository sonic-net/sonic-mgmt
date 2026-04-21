# powerflex_sds

Role to manage the installation and uninstallation of Powerflex SDS.

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
    <td>hostname</td>
    <td>true</td>
    <td>IP or FQDN of the PowerFlex gateway.</td>
    <td></td>
    <td>str</td>
    <td>10.1.1.1</td>
  </tr>
  <tr>
    <td>username</td>
    <td>true</td>
    <td>The username of the PowerFlex gateway.</td>
    <td></td>
    <td>str</td>
    <td>admin</td>
  </tr>
  <tr>
    <td>password</td>
    <td>true</td>
    <td>The password of the PowerFlex gateway.</td>
    <td></td>
    <td>str</td>
    <td>password</td>
  </tr>
  <tr>
    <td>port</td>
    <td>false</td>
    <td>Port</td>
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
    <td>timeout</td>
    <td>false</td>
    <td>Timeout</td>
    <td></td>
    <td>int</td>
    <td>120</td>
  </tr>
    <tr>
    <td>powerflex_common_file_install_location</td>
    <td>true</td>
    <td>Location of installation and rpm gpg files to be installed.
    <br>The required, compatible installation software package based on the operating system of the node.
    <br>The files can be downloaded from the Dell Product support page for PowerFlex software.</td>
    <td></td>
    <td>str</td>
    <td>/var/tmp</td>
  </tr>
  <tr>
    <td>powerflex_sds_protection_domain</td>
    <td>true</td>
    <td>The name of the protection domain to which the SDS will be added.
    </td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sds_storage_pool</td>
    <td>true</td>
    <td>The name of the storage pool to which the device will be added.
    </td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sds_disks</td>
    <td>true</td>
    <td>Disks for adding the device.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sds_role</td>
    <td>true</td>
    <td>Role of the SDS.</td>
    <td>'sdsOnly', 'sdcOnly', 'all'</td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sds_device_media_type</td>
    <td>true</td>
    <td>Media type of the device.</td>
    <td>'HDD', 'SSD', 'NVDIMM'</td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sds_device_name</td>
    <td>true</td>
    <td>Name of the device added to the SDS.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sds_external_acceleration_type</td>
    <td>true</td>
    <td>External acceleration type of the device added.</td>
    <td>'Invalid', 'None', 'Read', 'Write', 'ReadAndWrite'</td>
    <td>str</td>
    <td></td>
    </tr>
  <tr>
    <td>powerflex_sds_fault_set</td>
    <td>false</td>
    <td>Fault set to which the SDS will be added.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
<tr>
    <td>powerflex_sds_state</td>
    <td>false</td>
    <td>State of the SDS.</td>
    <td>present, absent</td>
    <td>str</td>
    <td>present</td>
  </tr>
</tbody>
</table>

## Examples
----
```
  - name: "Install and configure powerflex SDS"
    ansible.builtin.import_role:
      name: "powerflex_sds"
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_sds_disks:
        ansible_available_disks:
        - '/dev/sdb'
      powerflex_sds_disks_type: HDD
      powerflex_sds_protection_domain: domain1
      powerflex_sds_storage_pool: pool1
      powerflex_sds_role: all
      powerflex_sds_device_media_type: HDD
      powerflex_sds_device_name: '/dev/sdb'
      powerflex_sds_external_acceleration_type: ReadAndWrite
      powerflex_sds_state: present

  - name: "Uninstall powerflex SDS"
    ansible.builtin.import_role:
      name: "powerflex_sds"
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_sds_state: 'absent'

```

## Usage instructions
----
### To install all dependency packages, including SDS, on node:
- PowerFlex 3.6:
  ```
  ansible-playbook -i inventory site.yml
  ```
- PowerFlex 4.5:
  ```
  ansible-playbook -i inventory site_powerflex45.yml
  ```

### To uninstall SDS:
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

Dell Technologies
Trisha Datta (ansible.team@Dell.com)  2023