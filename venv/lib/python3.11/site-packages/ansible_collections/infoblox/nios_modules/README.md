# Infoblox NIOS Modules for Ansible Collections

Infoblox NIOS Modules for Ansible Collections enable the management of your NIOS objects through APIs. 

## Description
Infoblox NIOS Modules for Ansible Collections facilitate the DNS and IPAM automation of 
VM workloads that are deployed across multiple platforms. The `nios_modules` collection consists of modules and plug-ins required to manage the networks,
IP addresses, and DNS records in NIOS. The collection is hosted on Ansible Galaxy under `infoblox.nios_modules`.

### Modules Overview

The `infoblox.nios_modules` collection has the following content:

##### Modules

- `nios_a_record` – Configure Infoblox NIOS A records
- `nios_aaaa_record` – Configure Infoblox NIOS AAAA records
- `nios_adminuser` – Configure Infoblox NIOS Adminuser
- `nios_cname_record` – Configure Infoblox NIOS CNAME records
- `nios_dns_view` – Configure Infoblox NIOS DNS views
- `nios_dtc_lbdn` – Configure Infoblox NIOS DTC LBDN records
- `nios_dtc_monitor_http` – Configure Infoblox NIOS DTC HTTP monitors
- `nios_dtc_monitor_icmp` – Configure Infoblox NIOS DTC ICMP monitors
- `nios_dtc_monitor_pdp` – Configure Infoblox NIOS DTC PDP monitors
- `nios_dtc_monitor_sip` – Configure Infoblox NIOS DTC SIP monitors
- `nios_dtc_monitor_snmp` – Configure Infoblox NIOS DTC SNMP monitors
- `nios_dtc_monitor_tcp` – Configure Infoblox NIOS DTC TCP monitors
- `nios_dtc_pool` – Configure Infoblox NIOS DTC pools
- `nios_dtc_server` – Configure Infoblox NIOS DTC server records
- `nios_dtc_topology` – Configure Infoblox NIOS DTC topologies
- `nios_extensible_attribute` - Configure Infoblox NIOS extensible attributes
- `nios_fixed_address` – Configure Infoblox NIOS DHCP Fixed Address
- `nios_host_record` – Configure Infoblox NIOS host records
- `nios_member` – Configure Infoblox NIOS members
- `nios_mx_record` – Configure Infoblox NIOS MX records
- `nios_naptr_record` – Configure Infoblox NIOS NAPTR records
- `nios_network` – Configure Infoblox NIOS network object
- `nios_network_view` – Configure Infoblox NIOS network views
- `nios_nsgroup` – Configure Infoblox DNS Authoritative Name server Groups
- `nios_nsgroup_delegation` – Configure Infoblox DNS Delegation Name server Groups
- `nios_nsgroup_forwardingmember` – Configure Infoblox DNS Forwarding Member Name server Groups
- `nios_nsgroup_forwardstubserver` – Configure Infoblox DNS Forward/Stub Server Name server Groups
- `nios_nsgroup_stubmember` – Configure Infoblox DNS Stub Member Name server Groups
- `nios_ptr_record` – Configure Infoblox NIOS PTR records
- `nios_range` - Configure Infoblox NIOS Network Range object
- `nios_restartservices` - Controlled restart of Infoblox NIOS services
- `nios_srv_record` – Configure Infoblox NIOS SRV records
- `nios_txt_record` – Configure Infoblox NIOS txt records
- `nios_vlan` – Configure Infoblox NIOS vlan
- `nios_zone` – Configure Infoblox NIOS DNS zones

#### Plugins

- `nios_inventory`: List all the hosts with records created in NIOS
- `nios_lookup`: Look up queries for NIOS database objects
- `nios_next_ip`: Return the next available IP address for a network
- `nios_next_network`: Return the next available network addresses
    for a given network CIDR
- `nios_next_vlan_id`: Return the next available VLAN IDs for a given VLAN View/Range.

## Requirements

- Python version 3.10 or later
- Ansible Core version 2.16 or later
- NIOS 8.6.x and 9.0.x
- Infoblox WAPI version 2.12.3 or later
- Python module infoblox-client version 0.6.2
 
 Install the infoblox-client WAPI package. To install, run the following command:
```shell
pip install infoblox-client==0.6.2
```

## Installation

To install nios module with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install infoblox.nios_modules
```

You can also include it in a requirements.yml file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
collections:
    - name: infoblox.nios_modules
```

Note that if you install any collection from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package. 
To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install infoblox.nios_modules --upgrade
```

You can also install a specific version of the collection. For example, due to an issue of the latest version,
if you need to downgrade the collection to a prior version, use the following command to install the specific version:

```
ansible-galaxy collection install infoblox.nios_modules:==<version>
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

### Installation from GitHub

- Install the collection directly from the [GitHub](https://github.com/infobloxopen/infoblox-ansible) repository using the latest commit on the master branch:
```shell
$ ansible-galaxy collection install git+https://github.com/infobloxopen/infoblox-ansible.git,master
```

- For offline installation on the Ansible control machine, follow the below steps to clone the git repository and install from the repository:

  1. **Clone the repo:**
      ```
      $ git clone https://github.com/infobloxopen/infoblox-ansible.git
      ```

  2. **Build the collection:**
      To build a collection, run the following command from inside the root directory of the collection:
      ```
      $ ansible-galaxy collection build
      ```
      This creates a tarball of the built collection in the current directory.

  3. **Install the collection:**
      ```
      $ ansible-galaxy collection install infoblox-nios_modules-<version>.tar.gz -p ./collections
      ```

Please refer to our Ansible [deployment guide](https://docs.infoblox.com/space/niosmodulesansible) for more details.

## Use Cases


### 1. Automated DNS Record Management

**Description:** Automatically create, update, and delete DNS records in Infoblox NIOS based on changes in your infrastructure.

**Example:**
```yaml
- name: Create a DNS A record
  infoblox.nios_modules.nios_a_record:
    name: "host.example.com"
    ipv4addr: "192.168.1.10"
    state: "present"
```

### 2. IP Address Allocation

**Description:** Dynamically allocate and manage IP addresses for virtual machines and other devices in your network.

**Example:**
```yaml
- name: Allocate an IP address
  infoblox.nios_modules.nios_fixed_address:
    ipv4addr: "192.168.1.20"
    mac: "00:50:56:00:00:01"
    state: "present"
```

### 3. Network Management

**Description:** Create and manage network segments and subnets within Infoblox NIOS.

**Example:**
```yaml
- name: Create a network
  infoblox.nios_modules.nios_network:
    network: "192.168.2.0/24"
    comment: "Development network"
    state: "present"
```

### 4. DHCP Scope Management

**Description:** Manage DHCP scopes to ensure efficient IP address distribution and avoid conflicts.

**Example:**
```yaml
- name: Create a DHCP range
  infoblox.nios_modules.nios_range:
    network: "192.168.3.0/24"
    start_addr: "192.168.3.10"
    end_addr: "192.168.3.100"
    state: "present"
```

### 5. DTC Object Management

**Description:** Manage DNS Traffic Control (DTC) objects to optimize traffic distribution and ensure high availability.

**Example:**
```yaml
- name: Create a DTC Pool
  infoblox.nios_modules.nios_dtc_pool:
    name: "example_pool"
    lb_method: "round_robin"
    state: "present"
```

### 6. Lookups

**Description:** Perform lookups to retrieve information about existing NIOS objects.

**Example:**
```yaml
- name: fetch the default dns view
  ansible.builtin.set_fact:
    dns_views: "{{ lookup('infoblox.nios_modules.nios_lookup', 'view', filter={'name': 'default'},
                  provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"
```

### 7. Next Available Functionality

**Description:** Retrieve the next available IP address or network in a specified range or network.

**Example:**
```yaml
- name: return next available IP address for network 192.168.10.0/24
  ansible.builtin.set_fact:
    ipaddr: "{{ lookup('infoblox.nios_modules.nios_next_ip', '192.168.10.0/24', provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"
```

For more detailed examples and playbooks, refer to the `playbooks` directory in the `infoblox-ansible` repository.


## Testing

The collection has been tested in the following environments:

- **Operating Systems:**
    - Ubuntu 20.04 LTS
    - Mac

- **Ansible Versions:**
    - Ansible Core 2.16
    - Ansible Core 2.17
    - Ansible Core 2.18

- **NIOS Versions:**
    - NIOS 8.6.x
    - NIOS 9.0.x

### Known Exceptions and Workarounds

- For detailed information on testing and performance, refer to the `tests` directory in the `infoblox-ansible` repository.
- The `use_dns_ea_inheritance` option for Host Records is compatible only with WAPI versions 2.12.3 or 2.13.4 and later. 

## Contributing

We welcome your contributions to Infoblox Nios Modules. See [CONTRIBUTING.md](https://github.com/infobloxopen/infoblox-ansible/blob/master/CONTRIBUTING.md) for more details.

## Support

### Supported Versions

Infoblox NIOS Modules for Ansible Collections supports the following versions:
- **NIOS Versions:** 8.6.x and 9.0.x
- **Ansible Core Versions:** 2.16 and later
- **Python Versions:** 3.10 and later

### How to Get Support

If you need assistance with the Infoblox NIOS Modules, you can get support through the following channels:

- **GitHub Issues:**
    - Submit your issues or requests for enhancements on the [GitHub Issues](https://github.com/infobloxopen/infoblox-ansible/issues) page.

- **Infoblox Support:**
    - For enterprise support, contact Infoblox Support through the [Infoblox Support Portal](https://support.infoblox.com).

For any other inquiries, please refer to the [Infoblox Contact Page](https://www.infoblox.com/company/contact-us/).

## Release Notes and Roadmap

For detailed information about the latest updates, new features, bug fixes, and improvements, please visit our [Changelog](https://github.com/infobloxopen/infoblox-ansible/blob/master/CHANGELOG.rst).

## Related Information

For more detailed documentation and examples, refer to the following resources:
- Infoblox [NIOS modules](https://docs.ansible.com/ansible/latest/collections/infoblox/nios_modules/index.html) on Ansible documentation
- Infoblox [workspace](https://galaxy.ansible.com/ui/repo/published/infoblox/nios_modules) in Ansible Galaxy
- Infoblox Ansible [deployment guide](https://docs.infoblox.com/space/niosmodulesansible)
- [CONTRIBUTING.md](https://github.com/infobloxopen/infoblox-ansible/blob/master/CONTRIBUTING.md) for contribution guidelines

## License Information

This code is published under `GPL v3.0` [COPYING](https://github.com/infobloxopen/infoblox-ansible/blob/master/COPYING)

## Issues or RFEs

You can open an issue or request for enhancement [here](https://github.com/infobloxopen/infoblox-ansible/issues)
