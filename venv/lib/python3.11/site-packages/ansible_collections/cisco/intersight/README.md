# cisco.intersight Ansible Collection

## Description

Ansible collection for managing and automating Cisco Intersight environments.  Modules and roles are provided for common Cisco Intersight tasks.  Detailed installation and usage examples are included in a lab guide in the misc directory of this collection in the [Intersight Ansible Lab Guide](https://github.com/CiscoDevNet/intersight-ansible/blob/master/misc/CL2020%20EMEAR%20DEVWKS-1542%20Intersight%20Ansible%20Lab%20Guide.pdf).

## Requirements

- ansible-core v2.15.0 or newer
- Python 3.7 or newer (Older Python versions are no longer supported with this collection)


## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:
```
ansible-galaxy collection install cisco.intersight
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:

```yaml
collections:
  - name: cisco.intersight
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install cisco.intersight --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 1.0.0:

```
ansible-galaxy collection install cisco.intersight:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Use Cases

Authentication with the Intersight API requires the use of API keys that should be generated within the Intersight UI.  See [Intersight help center](https://intersight.com/help) or the [Cisco Intersight API Overview](https://communities.cisco.com/docs/DOC-76947) for more information on generating and using API keys.
If you do not have an Intersight account, Cisco's dCloud provides an Intersight demo that you can use [this link](https://dcloud2-rtp.cisco.com/content/instantdemo/cisco-intersight-infrastructure-services).
Minimal setup is required in playbooks or variables to access the API.  By default modules use an api_uri for Intersight's US instance `https://intersight.com/api/v1`.  If you need to use Intersight's EU instance you'll need to set `api_uri: https://eu-central-1.intersight.com/api/v1`.  Here's an example playbook with other required API parameters:
```
---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
  - name: Configure Boot Policy
    cisco.intersight.intersight_rest_api:
      api_private_key: <path to your private key>
      api_key_id: <your public key id>
      resource_path: /boot/PrecisionPolicies
      api_body: {
```

localhost (the Ansible controller) can be used without the need to specify any hosts or inventory.  Hosts can be specified to perform parallel actions.  An example of Server Firmware Update on multiple servers is provided by the server_firmware.yml playbook.

If you're using playbooks in this repo, you will need to provide your own inventory file and cusomtize any variables used in playbooks with settings for your environment.  This repo includes an example_inventory file with host groups for HX Clusters (Intersight_HX) and Servers (Intersight_Servers) and API key variables shared for Intersight host groups:
```
[Intersight_HX]
sjc07-r13-501
sjc07-r13-503

[Intersight_Servers]

[Intersight:children]
Intersight_HX
Intersight_Servers

[Intersight:vars]
api_private_key=~/Downloads/SecretKey.txt
api_key_id=...
```
For demo purposes, you can copy the example_inventory file to a new file named inventory.  Then, edit the inventory file to provide your own api_private_key location and api_key_id for use in playbooks.  If you're are using the Intersight Virtual Appliance, your inventory file can also specify the appliance URI and use of local certificates:
```
api_uri=https://tme-appliance2.intersightdemo.cisco.com/api/v1
validate_certs=false
```

Once you've provided API key information, the inventory file can be automatically updated with data from your Intersight account using one of the following playbooks:
- update_all_inventory.yml (if you'd like all Servers in the inventory)
- update_standalone_inventory.yml (if you'd like only Standalone C-Series Servers that can be managed through Server Policies/Profiles)

Here are example command lines for creating your own inventory and running the update_standalone_inventory.yml playbook:
```
cp example_inventory inventory
edit inventory with your api_private_key and api_key_id
ansible-playbook -i inventory update_standalone_inventory.yml
```
With an inventory for your Intersight account, you can now run playbooks to configure profiles/policies, and perform other server actions in Intersight:
```
ansible-playbook -i inventory cos_server_policies_and_profiles.yml --list-tasks --list-hosts (will show the tasks and their tags along with the hosts that will be configured)
ansible-playbook -i inventory cos_server_policies_and_profiles.yml (will configure policies and profiles in Intersight)
ansible-playbook -i inventory deploy_server_profiles.yml (note: this will deploy settings, run with --check to see what would change 1st)
ansible-playbook -i inventory server_actions.yml (note: by default this will PowerOn all servers, view the playbook to see other options)
```

Here are example command lines for creating an inventory with all Servers:
```
cp example_inventory inventory
edit inventory with your api_private_key and api_key_id
ansible-playbook -i inventory update_all_inventory.yml
```

## Testing

This collection is tested using the examples in the playbooks directory.

## Contributing

To contribute to this collection, please see the [Development Guide](https://github.com/CiscoDevNet/intersight-ansible/blob/main/Development.md) for guidelines that describe the process.

## Support

As Red Hat Ansible Certified Content, this collection is entitled to support through Ansible Automation Platform (AAP).
Use the **Create issue** button on the top right corner of the [Automation Hub Collection page](https://console.redhat.com/ansible/automation-hub/repo/published/cisco/intersight/) for any defects, feature requests, or questions on usage.

If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, there may community help available on the [Ansible Forum](https://forum.ansible.com/).

## Release Notes

See the [Changelog](https://github.com/CiscoDevNet/intersight-ansible/blob/main/CHANGELOG.md) for information on what's changed in each release of this collection.

## Related Information

Cisco's DevNet includes a [Learning Lab on using this collection](https://developer.cisco.com/learning/labs/cisco-intersight-rest-api-ansible/).

## License Information

Licensed under the [MIT License](https://github.com/CiscoDevNet/intersight-ansible/blob/main/LICENSE.txt).
