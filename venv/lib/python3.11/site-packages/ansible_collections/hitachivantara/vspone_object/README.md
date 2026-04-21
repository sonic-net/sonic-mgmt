# Hitachi Virtual Storage Platform One Object Storage Modules for Red Hat® Ansible® 1.1.1

The Hitachi Virtual Storage Platform One Object Storage Modules provide a comprehensive set of Ansible modules for managing VSP One Object series systems. These modules enable seamless integration with Red Hat Ansible, allowing users to automate storage provisioning, configuration, and management tasks.

## Hardware requirements

- VSP One Object 3.2

## Software requirements

- Red Hat Ansible Core - 2.16, 2.17, 2.18, 2.19
- Python - 3.7 or higher

## Supported operating systems

- Oracle Enterprise Linux 8.9 or higher
- Red Hat Enterprise Linux 8.9 or higher

## Recommended Host configuration

- CPU/vCPU - 2
- Memory - 4 GB
- HardDisk - 30 GB

## Idempotence

- Idempotence is supported for this release

## Changelog

View the [Changelog](https://github.com/hitachi-vantara/vspone-object-ansible/blob/main/CHANGELOG.rst).

## Available Modules

For a detailed list of available modules, please refer to the [Modules Documentation](https://github.com/hitachi-vantara/vspone-object-ansible/blob/main/docs/MODULES.md).

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install hitachivantara.vspone_object
```

```text
collections:
    - hitachivantara.vspone_object.oneobject_node
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the Ansible package.

To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install hitachivantara.vspone_object --upgrade
```

If you need to install a specific version of the collection (for example, to downgrade due to issues in the latest version), you can use the following syntax to install version 1.0.0:

```bash
ansible-galaxy collection install hitachivantara.vspone_object:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Troubleshooting

For troubleshooting tips and common issues, please refer to the [Troubleshooting Guide](https://github.com/hitachi-vantara/vspone-object-ansible/blob/main/docs/TROUBLESHOOTING.md).

## Testing

This collection has been tested using the following methods:

### Sanity Tests

```bash
ansible-test sanity
```

## Use Cases

Below is an example of how this collection can be used to manage a VSP One Object storage system:

### Add certificate to VSP One Object

This example shows how to add a certificate to VSP One Object

```yaml
- name: Add 
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Add a certificate to VSP One Object
      hitachivantara.vspone_object.oneobject_node.hv_certificates::
        connection_info: "{{ connection_info }}"
        state: "present"
        spec:
          cert_file_path: "/path/to/certificate.crt"
      register: result

    - name: Debug the result variable
      ansible.builtin.debug:
        var: result
```

## Support

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the **Create issue** button on the top right corner.

If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, there may be community help available on the [Ansible Forum](https://forum.ansible.com/).

For additional support, please use one of the following channels:

- [GitHub Issues](https://github.com/hitachi-vantara/vspone-object-ansible/issues) – for bug reports, feature requests, and technical assistance
- [Hitachi Vantara Support Portal](https://support.hitachivantara.com/) – for enterprise-grade support (requires valid Hitachi Vantara support contract)

## Release Notes and Roadmap

### Release Notes

Version **1.1.1** highlights:

- Minor documentation updates and clarifications.

### Roadmap

- Feature enhancements and new module development
- Ongoing bug fixes and maintenance

## License

[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Author

*This collection was created by the Hitachi Vantara® Ansible Team in 2025.*
