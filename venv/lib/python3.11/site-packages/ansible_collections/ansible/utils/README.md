# Ansible Utilities Collection
[![Codecov](https://codecov.io/gh/ansible-collections/ansible.utils/branch/main/graph/badge.svg)](https://codecov.io/gh/ansible-collections/ansible.utils)
[![CI](https://github.com/ansible-collections/ansible.utils/actions/workflows/tests.yml/badge.svg?branch=main&event=schedule)](https://github.com/ansible-collections/ansible.utils/actions/workflows/tests.yml)

The Ansible ``ansible.utils`` collection includes a variety of plugins that aid in the management, manipulation and visibility of data for the Ansible playbook developer.

## Support

As a Red Hat Ansible [Certified Content](https://catalog.redhat.com/software/search?target_platforms=Red%20Hat%20Ansible%20Automation%20Platform), this collection is entitled to [support](https://access.redhat.com/support/) through [Ansible Automation Platform](https://www.redhat.com/en/technologies/management/ansible) (AAP).

If a support case cannot be opened with Red Hat and the collection has been obtained either from [Galaxy](https://galaxy.ansible.com/ui/) or [GitHub](https://github.com/ansible-collections/ansible.utils), there is community support available at no charge.

You can join us on [#network:ansible.com](https://matrix.to/#/#network:ansible.com) room or the [Ansible Forum Network Working Group](https://forum.ansible.com/g/network-wg).

For more information you can check the communication section below.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'network'](https://forum.ansible.com/tag/network): subscribe to participate in collection-related conversations.```
  * [Ansible Network Automation Working Group](https://forum.ansible.com/g/network-wg/): by joining the team you will automatically get subscribed to the posts tagged with [network](https://forum.ansible.com/tags/network).
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.16.0**.

For collections that support Ansible 2.9, please ensure you update your `network_os` to use the
fully qualified collection name (for example, `cisco.ios.ios`).
Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

## Included content

<!--start collection content-->
### Filter plugins
Name | Description
--- | ---
[ansible.utils.cidr_merge](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.cidr_merge_filter.rst)|This filter can be used to merge subnets or individual addresses.
[ansible.utils.consolidate](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.consolidate_filter.rst)|Consolidate facts together on common attributes.
[ansible.utils.fact_diff](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.fact_diff_filter.rst)|Find the difference between currently set facts
[ansible.utils.from_xml](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.from_xml_filter.rst)|Convert given XML string to native python dictionary.
[ansible.utils.get_path](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.get_path_filter.rst)|Retrieve the value in a variable using a path
[ansible.utils.hwaddr](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.hwaddr_filter.rst)|HWaddr / MAC address filters
[ansible.utils.index_of](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.index_of_filter.rst)|Find the indices of items in a list matching some criteria
[ansible.utils.ip4_hex](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ip4_hex_filter.rst)|This filter is designed to convert IPv4 address to Hexadecimal notation with optional delimiter.
[ansible.utils.ipaddr](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipaddr_filter.rst)|This filter is designed to return the input value if a query is True, else False.
[ansible.utils.ipcut](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipcut_filter.rst)|This filter is designed to get 1st or last few bits of IP address.
[ansible.utils.ipmath](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipmath_filter.rst)|This filter is designed to do simple IP math/arithmetic.
[ansible.utils.ipsubnet](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipsubnet_filter.rst)|This filter can be used to manipulate network subnets in several ways.
[ansible.utils.ipv4](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv4_filter.rst)|To filter only Ipv4 addresses Ipv4 filter is used.
[ansible.utils.ipv6](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv6_filter.rst)|To filter only Ipv6 addresses Ipv6 filter is used.
[ansible.utils.ipv6form](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv6form_filter.rst)|This filter is designed to convert ipv6 address in different formats. For example expand, compressetc.
[ansible.utils.ipwrap](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipwrap_filter.rst)|This filter is designed to Wrap IPv6 addresses in [ ] brackets.
[ansible.utils.keep_keys](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.keep_keys_filter.rst)|Keep specific keys from a data recursively.
[ansible.utils.macaddr](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.macaddr_filter.rst)|macaddr / MAC address filters
[ansible.utils.network_in_network](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.network_in_network_filter.rst)|This filter returns whether an address or a network passed as argument is in a network.
[ansible.utils.network_in_usable](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.network_in_usable_filter.rst)|The network_in_usable filter returns whether an address passed as an argument is usable in a network.
[ansible.utils.next_nth_usable](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.next_nth_usable_filter.rst)|This filter returns the next nth usable ip within a network described by value.
[ansible.utils.nthhost](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.nthhost_filter.rst)|This filter returns the nth host within a network described by value.
[ansible.utils.param_list_compare](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.param_list_compare_filter.rst)|Generate the final param list combining/comparing base and provided parameters.
[ansible.utils.previous_nth_usable](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.previous_nth_usable_filter.rst)|This filter returns the previous nth usable ip within a network described by value.
[ansible.utils.reduce_on_network](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.reduce_on_network_filter.rst)|This filter reduces a list of addresses to only the addresses that match a given network.
[ansible.utils.remove_keys](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.remove_keys_filter.rst)|Remove specific keys from a data recursively.
[ansible.utils.replace_keys](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.replace_keys_filter.rst)|Replaces specific keys with their after value from a data recursively.
[ansible.utils.slaac](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.slaac_filter.rst)|This filter returns the SLAAC address within a network for a given HW/MAC address.
[ansible.utils.to_paths](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.to_paths_filter.rst)|Flatten a complex object into a dictionary of paths and values
[ansible.utils.to_xml](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.to_xml_filter.rst)|Convert given JSON string to XML
[ansible.utils.usable_range](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.usable_range_filter.rst)|Expand the usable IP addresses
[ansible.utils.validate](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.validate_filter.rst)|Validate data with provided criteria

### Lookup plugins
Name | Description
--- | ---
[ansible.utils.get_path](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.get_path_lookup.rst)|Retrieve the value in a variable using a path
[ansible.utils.index_of](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.index_of_lookup.rst)|Find the indices of items in a list matching some criteria
[ansible.utils.to_paths](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.to_paths_lookup.rst)|Flatten a complex object into a dictionary of paths and values
[ansible.utils.validate](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.validate_lookup.rst)|Validate data with provided criteria

### Modules
Name | Description
--- | ---
[ansible.utils.cli_parse](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.cli_parse_module.rst)|Parse cli output or text using a variety of parsers
[ansible.utils.fact_diff](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.fact_diff_module.rst)|Find the difference between currently set facts
[ansible.utils.update_fact](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.update_fact_module.rst)|Update currently set facts
[ansible.utils.validate](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.validate_module.rst)|Validate data with provided criteria

### Test plugins
Name | Description
--- | ---
[ansible.utils.in_any_network](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.in_any_network_test.rst)|Test if an IP or network falls in any network
[ansible.utils.in_network](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.in_network_test.rst)|Test if IP address falls in the network
[ansible.utils.in_one_network](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.in_one_network_test.rst)|Test if IP address belongs in any one of the networks in the list
[ansible.utils.ip](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ip_test.rst)|Test if something in an IP address or network
[ansible.utils.ip_address](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ip_address_test.rst)|Test if something in an IP address
[ansible.utils.ipv4](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv4_test.rst)|Test if something is an IPv4 address or network
[ansible.utils.ipv4_address](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv4_address_test.rst)|Test if something is an IPv4 address
[ansible.utils.ipv4_hostmask](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv4_hostmask_test.rst)|Test if an address is a valid hostmask
[ansible.utils.ipv4_netmask](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv4_netmask_test.rst)|Test if an address is a valid netmask
[ansible.utils.ipv6](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv6_test.rst)|Test if something is an IPv6 address or network
[ansible.utils.ipv6_address](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv6_address_test.rst)|Test if something is an IPv6 address
[ansible.utils.ipv6_ipv4_mapped](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv6_ipv4_mapped_test.rst)|Test if something appears to be a mapped IPv6 to IPv4 mapped address
[ansible.utils.ipv6_sixtofour](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv6_sixtofour_test.rst)|Test if something appears to be a 6to4 address
[ansible.utils.ipv6_teredo](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.ipv6_teredo_test.rst)|Test if something appears to be an IPv6 teredo address
[ansible.utils.loopback](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.loopback_test.rst)|Test if an IP address is a loopback
[ansible.utils.mac](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.mac_test.rst)|Test if something appears to be a valid MAC address
[ansible.utils.multicast](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.multicast_test.rst)|Test for a multicast IP address
[ansible.utils.private](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.private_test.rst)|Test if an IP address is private
[ansible.utils.public](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.public_test.rst)|Test if an IP address is public
[ansible.utils.reserved](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.reserved_test.rst)|Test for a reserved IP address
[ansible.utils.resolvable](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.resolvable_test.rst)|Test if an IP or name can be resolved via /etc/hosts or DNS
[ansible.utils.subnet_of](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.subnet_of_test.rst)|Test if a network is a subnet of another network
[ansible.utils.supernet_of](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.supernet_of_test.rst)|Test if a network is a supernet of another network
[ansible.utils.unspecified](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.unspecified_test.rst)|Test for an unspecified IP address
[ansible.utils.validate](https://github.com/ansible-collections/ansible.utils/blob/main/docs/ansible.utils.validate_test.rst)|Validate data with provided criteria

<!--end collection content-->

## Installing this collection

You can install the ``ansible.utils`` collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install ansible.utils

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: ansible.utils
```
## Using this collection

The most common use case for this collection is when you want to work with the complex data structures present in an Ansible playbook, inventory, or returned from modules. See each plugin documentation page for detailed examples for how these utilities can be used in tasks.


**NOTE**: For Ansible 2.9, you may not see deprecation warnings when you run your playbooks with this collection. Use this documentation to track when a module is deprecated.

### See Also:

* [Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) in the Ansible documentation for more details.

## Contributing to this collection

This collection is intended for plugins that are not platform or discipline specific. Simple plugin examples should be generic in nature. More complex examples can include real world platform modules to demonstrate the utility of the plugin in a playbook.

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [ansible.utils collection repository](https://github.com/ansible-collections/ansible.utils). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Developer notes

- 100% code coverage is the goal, although it's not always possible. Please include unit and integration tests with all PRs. PRs should not cause a decrease in code coverage.
- Filter plugins should be 1 per file, with an included DOCUMENTATION string, or reference a lookup plugin with the same name.
- Action, filter, and lookup plugins should use argspec validation. See [AnsibleArgSpecValidator](https://github.com/ansible-collections/ansible.utils/blob/main/plugins/module_utils/common/argspec_validate.py).
- This collection should not depend on other collections for imported code
- Use of the latest version of black is required for formatting (black -l79)
- The README contains a table of plugins. Use the [collection_prep](https://github.com/ansible-network/collection_prep) utilities to maintain this.


### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.


## Release notes
<!--Add a link to a changelog.md file or an external docsite to cover this information. -->
Release notes are available [here](CHANGELOG.rst)
For automated release announcements refer [here](https://twitter.com/AnsibleContent).


## Roadmap
For information on releasing, versioning and deprecation see the [stratergy document](https://access.redhat.com/articles/4993781).

In general, major versions can contain breaking changes, while minor versions only contain new features (like new plugin addition) and bugfixes.
The releases will be done on an as-needed basis when new features and/or bugfixes are done.

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
