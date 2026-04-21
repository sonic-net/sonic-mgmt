
# VyOS Collection

[![codecov](https://codecov.io/gh/vyos/vyos.vyos/graph/badge.svg?token=J217GFD69W)](https://codecov.io/gh/vyos/vyos.vyos)
[![CI](https://github.com/vyos/vyos.vyos/actions/workflows/tests.yml/badge.svg?branch=main&event=schedule)](https://github.com/vyos/vyos.vyos/actions/workflows/tests.yml)

The Ansible VyOS collection includes a variety of Ansible content to help automate the management of VyOS network appliances.

This collection has been tested against VyOS 1.3.8, 1.4.1 and the current rolling release for 1.5. Where possible,
compatibility with older versions of VyOS are maintained but not guaranteed.

## Communication

* Join the VyOS forum:
  * [FAQ](https://forum.vyos.io/faq): find answers to frequently asked questions.
  * [Guides and How To](https://forum.vyos.io/c/howto-guies/27): find guides and how-to articles.
  * [News & Announcements](https://forum.vyos.io/c/announcements/6): track project-wide announcements .


<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.15.0**.

For collections that support Ansible 2.9, please ensure you update your `network_os` to use the
fully qualified collection name (for example, `cisco.ios.ios`).
Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->


### Supported connections
The VyOS collection supports ``network_cli`` connections.

## Included content

<!--start collection content-->
### Cliconf plugins
Name | Description
--- | ---
[vyos.vyos.vyos](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_cliconf.rst)|Use vyos cliconf to run command on VyOS platform

### Modules
Name | Description
--- | ---
[vyos.vyos.vyos_banner](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_banner_module.rst)|Manage multiline banners on VyOS devices
[vyos.vyos.vyos_bgp_address_family](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_bgp_address_family_module.rst)|BGP Address Family resource module
[vyos.vyos.vyos_bgp_global](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_bgp_global_module.rst)|BGP global resource module
[vyos.vyos.vyos_command](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_command_module.rst)|Run one or more commands on VyOS devices
[vyos.vyos.vyos_config](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_config_module.rst)|Manage VyOS configuration on remote device
[vyos.vyos.vyos_facts](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_facts_module.rst)|Get facts about vyos devices.
[vyos.vyos.vyos_firewall_global](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_firewall_global_module.rst)|Firewall global resource module
[vyos.vyos.vyos_firewall_interfaces](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_firewall_interfaces_module.rst)|Firewall interfaces resource module
[vyos.vyos.vyos_firewall_rules](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_firewall_rules_module.rst)|Firewall rules resource module
[vyos.vyos.vyos_hostname](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_hostname_module.rst)|Manages hostname resource module
[vyos.vyos.vyos_interfaces](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_interfaces_module.rst)|Manages interface attributes of VyOS network devices.
[vyos.vyos.vyos_l3_interfaces](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_l3_interfaces_module.rst)|Layer 3 interfaces resource module.
[vyos.vyos.vyos_lag_interfaces](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_lag_interfaces_module.rst)|LAG interfaces resource module
[vyos.vyos.vyos_lldp_global](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_lldp_global_module.rst)|LLDP global resource module
[vyos.vyos.vyos_lldp_interfaces](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_lldp_interfaces_module.rst)|LLDP interfaces resource module
[vyos.vyos.vyos_logging_global](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_logging_global_module.rst)|Logging resource module
[vyos.vyos.vyos_ntp_global](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_ntp_global_module.rst)|NTP global resource module
[vyos.vyos.vyos_ospf_interfaces](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_ospf_interfaces_module.rst)|OSPF Interfaces Resource Module.
[vyos.vyos.vyos_ospfv2](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_ospfv2_module.rst)|OSPFv2 resource module
[vyos.vyos.vyos_ospfv3](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_ospfv3_module.rst)|OSPFv3 resource module
[vyos.vyos.vyos_ping](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_ping_module.rst)|Tests reachability using ping from VyOS network devices
[vyos.vyos.vyos_prefix_lists](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_prefix_lists_module.rst)|Prefix-Lists resource module for VyOS
[vyos.vyos.vyos_route_maps](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_route_maps_module.rst)|Route Map resource module
[vyos.vyos.vyos_snmp_server](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_snmp_server_module.rst)|Manages snmp_server resource module
[vyos.vyos.vyos_static_routes](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_static_routes_module.rst)|Static routes resource module
[vyos.vyos.vyos_system](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_system_module.rst)|Run `set system` commands on VyOS devices
[vyos.vyos.vyos_user](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_user_module.rst)|Manage the collection of local users on VyOS device
[vyos.vyos.vyos_vlan](https://github.com/vyos/vyos.vyos/blob/main/docs/vyos.vyos.vyos_vlan_module.rst)|Manage VLANs on VyOS network devices

<!--end collection content-->

Click the ``Content`` button to see the list of content included in this collection.

## Installing this collection

You can install the VyOS collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install vyos.vyos

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: vyos.vyos
```
## Using this collection


This collection includes [network resource modules](https://docs.ansible.com/ansible/latest/network/user_guide/network_resource_modules.html).

### Using modules from the VyOS collection in your playbooks

You can call modules by their Fully Qualified Collection Namespace (FQCN), such as `vyos.vyos.vyos_static_routes`.
The following example task replaces configuration changes in the existing configuration on a VyOS network device, using the FQCN:

```yaml
---
  - name: Replace device configurations of listed static routes with provided
      configurations
    register: result
    vyos.vyos.vyos_static_routes: &id001
      config:

        - address_families:

            - afi: ipv4
              routes:

                - dest: 192.0.2.32/28
                  blackhole_config:
                    distance: 2
                  next_hops:

                    - forward_router_address: 192.0.2.7

                    - forward_router_address: 192.0.2.8

                    - forward_router_address: 192.0.2.9
      state: replaced
```

**NOTE**: For Ansible 2.9, you may not see deprecation warnings when you run your playbooks with this collection. Use this documentation to track when a module is deprecated.



### See Also:

* [VyOS Platform Options](https://docs.ansible.com/ansible/latest/network/user_guide/platform_vyos.html)
* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [VyOS collection repository](https://github.com/vyos/vyos.vyos). See [Contributing to VyOS](https://vyos.net/contribute/) for complete details.

You can also join us on:

- Forum - https://forum.vyos.io

See the [Contributing to VyOS](https://vyos.net/contribute/) for details on contributing to Ansible.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

### Updating from resource module models

Some of our modules were templated using `resource_module_builder`, but some use
the newer [`cli_rm_builder`](https://github.com/ansible-network/cli_rm_builder)
which tempaltes baed on in-place device information, but also uses a new network
parsing engine designed to simplify and standardize the parsing of network
configuration.

#### Using older *resource_module_builder* modules

Last build was with a slightly-modified version of resource_module_builder.
This changes the calling parameters for the resources.

To update the collection from the resource module models, run the following command:

```bash
ansible-playbook -e rm_dest=`pwd` \
                 -e structure=collection \
                 -e collection_org=vyos \
                 -e collection_name=vyos \
                 -e model=../../../resource_module_models/models/vyos/firewall_rules/vyos_firewall_rules.yaml \
                 ../../../resource_module_builder/site.yml
```

#### Using *cli_rm_builder* modules

The newer `cli_rm_builder` works similarly to the older `resource_module_builder`, but
pulls the information directly from the `DOCUMENTATION`, `EXAMPLES` and `RETURN`
blocks in the module itself.

To update the collection from the `cli_rm_builder` models, run the following command:

```bash
ansible-playbook -e rm_dest=`pwd` \
                     -e collection_org=vyos \
                     -e collection_name=vyos \
                     -e resource=bgp_address_family \
                     ../../../cli_rm_builder/run.yml
```

Unlike the `resource_module_builder`, the `cli_rm_builder` does not require the `model` parameter. Instead, it uses the `resource` parameter to specify the resource to build.

### Testing playbooks

You can use `ANSIBLE_COLLECTIONS_PATH` to test the collection locally. For example:
```
ANSIBLE_COLLECTIONS_PATHS=~/my_dev_path ansible-playbook -i inventory.network test.yml
```

### Integration Tests

Integration tests are run using `ansible-test` and require that there be an inventory
defined (you can pass this in with `--inventory <filename>`) and that the system be
configured for access (recommended to use SSH keys).

Additionally:
- eth0 should be configured for `address dhcp` and should have an assigned address
  on the local network
- eth1 and eth2 should be defined and uncofirgured (they'll be overwritten by the tests)
- eth3 and beyond should not be present or interface-related tests will fail
- when using VMs for testing, ensure that the interfaces don't use `virtio`, as it will supress
  some interface configurations. `e1000e` is a good choice for testing.
- eth0 is also expected to show `duplex auto` and `speed auto` in the output of `show interfaces`,
  however others are not due to the fact that they are repeatedly deleted and recreated
  which causes the default values to be hidden.

## Changelogs

Change logs are available [here](https://github.com/vyos/vyos.vyos/blob/main/CHANGELOG.rst).

## Release notes

Release notes are available [here](https://github.com/vyos/vyos.vyos/blob/main/CHANGELOG.rst).

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

Major Version | Ansible Support | VyOS Support | Details
--- | --- | --- | ---
4.1.0 | 2.15 | 1.1.2 | Final release for the 4.x series
5.0.0 | 2.16 | 1.1.2 | First relase under VyOS control as a separate collection
6.0.0 | 2.18 | 1.3.8 | *Planned* release for supporting VyOS 1.3.8+
7.0.0 | x.xx | 1.4.x | *Prospective* release deprecating incompatible 1.3.x modules

Note:
- Unreleased versions are not guaranteed to be released as described.
- Some modules may support a wider variety of versions depending upon the compatibility
  with prior versions of VyOS.
- The roadmap is subject to change based on community feedback and contributions.


## More information

VyOS resources
- [Contributing to VyOS](https://vyos.net/contribute)
- [VyOS documentation](https://docs.vyos.io/en/latest/)
- [VyOS forum](https://forum.vyos.io)


Ansible Resources
- [Ansible network resources](https://docs.ansible.com/ansible/latest/network/getting_started/network_resources.html)
- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
