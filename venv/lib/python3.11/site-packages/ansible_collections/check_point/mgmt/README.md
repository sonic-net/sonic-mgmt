# Check Point Ansible Mgmt Collection
This Ansible collection provides control over a Check Point Management server using
Check Point's web-services APIs.

The Ansible Check Point modules reference can be found here:
[Ansible Check Point modules reference](https://docs.ansible.com/ansible/latest/collections/check_point/mgmt/index.html)
<br>Note - look only at the `cp_mgmt_*` modules, because the `checkpoint_*` will be deprecated.

This is the repository of the mgmt collection which can be found here: [Galaxy: check_point.mgmt](https://galaxy.ansible.com/check_point/mgmt)

Installation instructions
-------------------------
Run `ansible-galaxy collection install check_point.mgmt`

Requirements
------------
* Ansible 2.9+ is required.
* The Check Point server should be using the versions detailed in this SK: [Check Point Support SK114661](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk114661)
* The Check Point server should be open for API communication from the Ansible server.
  Open SmartConsole and check "Manage & Settings > Blades > Management API > Advanced settings".

Usage
-----
1. Edit the `hosts` so that it will contain a section similar to this one:
```
[check_point]
%CHECK_POINT_MANAGEMENT_SERVER_IP%
[check_point:vars]
ansible_httpapi_use_ssl=True
ansible_httpapi_validate_certs=False
ansible_user=%CHECK_POINT_MANAGEMENT_SERVER_USER%
ansible_password=%CHECK_POINT_MANAGEMENT_SERVER_PASSWORD%
ansible_network_os=check_point.mgmt.checkpoint
```
Note - If you want to run against Ansible version 2.9 instead of the collection, just replace `ansible_network_os=check_point.mgmt.checkpoint` with `ansible_network_os=checkpoint`
<br><br>2. Run a playbook:
```sh
ansible-playbook your_ansible_playbook.yml
```
or

Run a playbook in "check mode":
```sh
ansible-playbook -C your_ansible_playbook.yml
```
Example playbook:
```
---
- name: playbook name
  hosts: check_point
  connection: httpapi
  tasks:
    - name: task to have network
      check_point.mgmt.cp_mgmt_network:
        name: "network name"
        subnet: "4.1.76.0"
        mask_length: 24
        auto_publish_session: true
        
      vars: 
        ansible_checkpoint_domain: "SMC User"
```
Note - If you want to run against Ansible version 2.9 instead of the collection, just replace `check_point.mgmt.cp_mgmt_network` with `cp_mgmt_network`

###  Notes:
  1. Because this Ansible module is controlling the management server remotely via the web API, 
     the Ansible server needs to have access to the Check Point API server.
     Open `SmartConsole`, navigate to "Manage & Settings > Blades > Management API > Advanced settings"
     and check the API server's accessibility set
  2. Ansible has a feature called "Check Mode" that enables you to test the
     changes without actually changing anything.
  3. The login and logout happens automatically.
  4. If you want to login to a specific domain, in the playbook above in the `vars`section change the domain name to 
     `ansible_checkpoint_domain`
  5. There are two ways to publish changes:
    a. Set the `auto_publish_session` to `true` as displayed in the example playbook above.
       This option will publish only the task which this parameter belongs to.
    b. Add the task to publish to the `cp_mgmt_publish` module.
       This option will publish all the tasks above this task.
  6. It is recommended by Check Point to use this collection over the modules of Ansible version 2.9
  7. If you still want to use Ansible version 2.9 instead of this collection (not recommended):
    a. In the `hosts` file replace `ansible_network_os=check_point.mgmt.checkpoint` with `ansible_network_os=checkpoint`
    b. In the task in the playbook replace the module `check_point.mgmt.cp_mgmt_*` with the module `cp_mgmt_*`
  8. Starting from version 1.0.6, when running a command which returns a task-id, and the user chooses to wait for that task to finish
     (the default is to wait), then the output of the command will be the output of the show-task command (instead of the task-id).

### Testing
This collection is tested with the most current Ansible releases. Ansible versions from 2.15.0 and above are supported.

### Support
As Red Hat Ansible Certified Content, this collection is entitled to support regarding issues or requests for enhancements
through the collection's GitHub repository using the **New issue** button in the top right corner: [GitHub Issues](https://github.com/CheckPointSW/CheckPointAnsibleMgmtCollection/issues)

### Release Notes
[Release Notes (CHANGELOG.rst)](https://github.com/CheckPointSW/CheckPointAnsibleMgmtCollection/blob/master/CHANGELOG.rst)

### Related Information
For further information please see - [Check Point Support SK114661](https://support.checkpoint.com/results/sk/sk114661)

### License Information
Apache-2.0 license