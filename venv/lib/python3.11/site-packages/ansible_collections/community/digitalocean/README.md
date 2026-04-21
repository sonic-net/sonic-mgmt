# DigitalOcean Community Collection

[![coverage](https://img.shields.io/codecov/c/github/ansible-collections/community.digitalocean)](https://codecov.io/gh/ansible-collections/community.digitalocean)
[![black](https://github.com/ansible-collections/community.digitalocean/actions/workflows/black.yml/badge.svg)](https://github.com/ansible-collections/community.digitalocean/actions/workflows/black.yml)
[![integration](https://github.com/ansible-collections/community.digitalocean/actions/workflows/ansible-test-integration.yml/badge.svg)](https://github.com/ansible-collections/community.digitalocean/actions/workflows/ansible-test-integration.yml)
[![sanity](https://github.com/ansible-collections/community.digitalocean/actions/workflows/ansible-test-sanity.yml/badge.svg)](https://github.com/ansible-collections/community.digitalocean/actions/workflows/ansible-test-sanity.yml)
[![unit](https://github.com/ansible-collections/community.digitalocean/actions/workflows/ansible-test-unit.yml/badge.svg)](https://github.com/ansible-collections/community.digitalocean/actions/workflows/ansible-test-unit.yml)

This collection contains modules and plugins to assist in automating [DigitalOcean](https://www.digitalocean.com) infrastructure and API interactions with Ansible.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'digitalocean'](https://forum.ansible.com/tag/digitalocean): subscribe to participate in collection-related conversations.
  * [Refer to your forum group here if exists](https://forum.ansible.com/g/): by joining the team you will automatically get subscribed to the posts tagged with [your group forum tag here](https://forum.ansible.com/tags).
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Included content

- [digital_ocean](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_module.html) – Create/delete a droplet/SSH_key in DigitalOcean
- [digital_ocean_account_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_account_facts_module.html) – Gather information about DigitalOcean User account
- [digital_ocean_account_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_account_info_module.html) – Gather information about DigitalOcean User account
- [digital_ocean_balance_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_balance_info_module.html) – Display DigitalOcean customer balance
- [digital_ocean_block_storage](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_block_storage_module.html) – Create/destroy or attach/detach Block Storage volumes in DigitalOcean
- [digital_ocean_cdn_endpoints_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_cdn_endpoints_info_module.html) – Gather information about DigitalOcean CDN Endpoints
- [digital_ocean_cdn_endpoints](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_cdn_endpoints_module.html) – Create and delete DigitalOcean CDN Endpoints
- [digital_ocean_certificate](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_certificate_module.html) – Manage certificates in DigitalOcean.
- [digital_ocean_certificate_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_certificate_facts_module.html) – Gather information about DigitalOcean certificates
- [digital_ocean_certificate_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_certificate_info_module.html) – Gather information about DigitalOcean certificates
- [digital_ocean_database_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_database_info_module.html) – Gather information about DigitalOcean databases
- [digital_ocean_database](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_database_module.html) – Create and delete DigitalOcean databases
- [digital_ocean_domain](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_domain_module.html) – Create/delete a DNS domain in DigitalOcean
- [digital_ocean_domain_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_domain_facts_module.html) – Gather information about DigitalOcean Domains
- [digital_ocean_domain_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_domain_info_module.html) – Gather information about DigitalOcean Domains
- [digital_ocean_domain_record_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_domain_record_info_module.html) – Gather information about DigitalOcean domain records
- [digital_ocean_domain_record](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_domain_record_module.html) – Create and delete DigitalOcean Domain Records
- [digital_ocean_droplet](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_droplet_module.html) – Create and delete a DigitalOcean droplet
- [digital_ocean_droplet_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_droplet_info_module.html) - Gather information about DigitalOcean Droplets
- [digital_ocean_firewall](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_firewall_module.html) – Create and delete DigitalOcean firewalls
- [digital_ocean_firewall_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_firewall_facts_module.html) – Gather information about DigitalOcean firewalls
- [digital_ocean_firewall_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_firewall_info_module.html) – Gather information about DigitalOcean firewalls
- [digital_ocean_floating_ip](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_floating_ip_module.html) – Manage DigitalOcean Floating IPs
- [digital_ocean_floating_ip_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_floating_ip_facts_module.html) – DigitalOcean Floating IPs information
- [digital_ocean_floating_ip_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_floating_ip_info_module.html) – DigitalOcean Floating IPs information
- [digital_ocean_image_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_image_facts_module.html) – Gather information about DigitalOcean images
- [digital_ocean_image_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_image_info_module.html) – Gather information about DigitalOcean images
- [digital_ocean_kubernetes_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_kubernetes_info_module.html) – Gather information about DigitalOcean Kubernetes clusters
- [digital_ocean_kubernetes](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_kubernetes_module.html) – Create and delete DigitalOcean Kubernetes clusters
- [digital_ocean_load_balancer](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_load_balancer_module.html) – Create and delete DigitalOcean load balancers
- [digital_ocean_load_balancer_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_load_balancer_facts_module.html) – Gather information about DigitalOcean load balancers
- [digital_ocean_load_balancer_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_load_balancer_info_module.html) – Gather information about DigitalOcean load balancers
- [digital_ocean_monitoring_alerts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_monitoring_alerts_module.html) – Create and delete DigitalOcean Monitoring alerts
- [digital_ocean_monitoring_alerts_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_monitoring_alerts_info_module.html) – Gather information about DigitalOcean Monitoring alerts
- [digital_ocean_project_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_load_project_info_module.html) – Gather information about DigitalOcean projects
- [digital_ocean_project](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_load_project_module.html) – Manage DigitalOcean projects
- [digital_ocean_region_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_region_facts_module.html) – Gather information about DigitalOcean regions
- [digital_ocean_region_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_region_info_module.html) – Gather information about DigitalOcean regions
- [digital_ocean_size_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_size_facts_module.html) – Gather information about DigitalOcean Droplet sizes
- [digital_ocean_size_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_size_info_module.html) – Gather information about DigitalOcean Droplet sizes
- [digital_ocean_snapshot_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_snapshot_facts_module.html) – Gather information about DigitalOcean Snapshot
- [digital_ocean_snapshot_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_snapshot_info_module.html) – Gather information about DigitalOcean Snapshot
- [digital_ocean_snapshot](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_snapshot_module.html) – Manage DigitalOcean Snapshots
- [digital_ocean_spaces_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_spaces_info_module.html) – Gather information about DigitalOcean Spaces
- [digital_ocean_spaces](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_spaces_module.html) – Manage DigitalOcean Spaces
- [digital_ocean_sshkey](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_sshkey_module.html) – Manage DigitalOcean SSH keys
- [digital_ocean_sshkey_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_sshkey_facts_module.html) – DigitalOcean SSH keys facts
- [digital_ocean_sshkey_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_sshkey_info_module.html) – Gather information about DigitalOcean SSH keys
- [digital_ocean_tag](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_tag_module.html) – Create and remove tag(s) to DigitalOcean resource.
- [digital_ocean_tag_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_tag_facts_module.html) – Gather information about DigitalOcean tags
- [digital_ocean_tag_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_tag_info_module.html) – Gather information about DigitalOcean tags
- [digital_ocean_volume_facts](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_volume_facts_module.html) – Gather information about DigitalOcean volumes
- [digital_ocean_volume_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_volume_info_module.html) – Gather information about DigitalOcean volumes
- [digital_ocean_vpc](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_vpc_module.html) – Create and delete DigitalOcean VPCs
- [digital_ocean_vpc_info](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digital_ocean_vpc_info_module.html) – Gather information about DigitalOcean VPCs
- [digitalocean](https://docs.ansible.com/ansible/latest/collections/community/digitalocean/digitalocean_inventory.html) – DigitalOcean Inventory Plugin

## Installation and Usage

### Requirements

The collection is tested and supported with:

- ansible-core >= 2.14 (including `devel`)
- python >= 3.9

### Installing the Collection from Ansible Galaxy

Before using the DigitalOcean collection, you need to install it with the Ansible Galaxy CLI:

    ansible-galaxy collection install community.digitalocean

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.digitalocean
```

### Using modules from the DigitalOcean Collection in your playbooks

It's preferable to use content in this collection using their Fully Qualified Collection Namespace (FQCN), for example `community.digitalocean.digital_ocean_droplet`:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  vars:
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"

  # You can also default the value of a variable for every DO module using module_defaults
  # module_defaults:
  #   group/community.digitalocean.all:
  #     oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"

  tasks:
    - name: Create SSH key
      community.digitalocean.digital_ocean_sshkey:
        oauth_token: "{{ oauth_token }}"
        name: mykey
        ssh_pub_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQDDHr/jh2Jy4yALcK4JyWbVkPRaWmhck3IgCoeOO3z1e2dBowLh64QAM+Qb72pxekALga2oi4GvT+TlWNhzPH4V example"
        state: present
      register: my_ssh_key

    - name: Create a new Droplet
      community.digitalocean.digital_ocean_droplet:
        oauth_token: "{{ oauth_token }}"
        state: present
        name: mydroplet
        unique_name: true
        size: s-1vcpu-1gb
        region: sfo3
        image: ubuntu-20-04-x64
        wait_timeout: 500
        ssh_keys:
          - "{{ my_ssh_key.data.ssh_key.id }}"
      register: my_droplet

    - name: Show Droplet info
      ansible.builtin.debug:
        msg: |
          Droplet ID is {{ my_droplet.data.droplet.id }}
          First Public IPv4 is {{ (my_droplet.data.droplet.networks.v4 | selectattr('type', 'equalto', 'public')).0.ip_address | default('<none>', true) }}
          First Private IPv4 is {{ (my_droplet.data.droplet.networks.v4 | selectattr('type', 'equalto', 'private')).0.ip_address | default('<none>', true) }}

    - name: Tag a resource; creating the tag if it does not exist
      community.digitalocean.digital_ocean_tag:
        oauth_token: "{{ oauth_token }}"
        name: "{{ item }}"
        resource_id: "{{ my_droplet.data.droplet.id }}"
        state: present
      loop:
        - staging
        - dbserver
```

If upgrading older playbooks which were built prior to Ansible 2.10 and this collection's existence, you can also define `collections` in your play and refer to this collection's modules as you did in Ansible 2.9 and below, as in this example:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  collections:
    - community.digitalocean

  tasks:
    - name: Create ssh key
      digital_ocean_sshkey:
        oauth_token: "{{ oauth_token }}"
        ...
```

## Testing and Development

If you want to develop new content for this collection or improve what's already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

Alternatively, to develop completely out of `~/src/ansible-dev`, one could:

    mkdir -p ~/src/ansible-dev
    cd ~/src/ansible-dev
    python3 -m venv venv
    source venv/bin/activate
    git clone https://github.com/ansible/ansible.git
    pip install --requirement ansible/requirements.txt
    pip install kubernetes
    source ansible/hacking/env-setup
    export ANSIBLE_COLLECTIONS_PATHS="~/src/ansible-dev/ansible_collections"
    ansible-galaxy collection install community.digitalocean community.general

This gives us a self-contained environment in `~/src/ansible-dev` consisting of Python, Ansible, and this collection (located in `~/src/ansible-dev/ansible_collections/community/digitalocean`).
This collection requires functionality from `community.general`, and as such, we install it as well.

If you would like to contribute any changes which you have made to the collection, you will have to push them to your fork.
If you do not have a fork yet, you can create one [here](https://github.com/ansible-collections/community.digitalocean/fork).
Once you have a fork:

    cd ~/src/ansible-dev/ansible_collections/community/digitalocean
    git remote add origin git@github.com:{your fork organization}/community.digitalocean.git
    git checkout -b my-awesome-fixes
    git commit -am "My awesome fixes"
    git push -u origin my-awesome-fixes

Now, you should be ready to create a [Pull Request](https://github.com/ansible-collections/community.digitalocean/pulls).

### Testing with `ansible-test`

The `tests` directory inside the collection root contains configuration for
running unit, sanity, and integration tests using [`ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html).

You can run the collection's test suites with the commands:

    ansible-test units --venv --python 3.9
    ansible-test sanity --venv --python 3.9
    ansible-test integration --venv --python 3.9

Replace `--venv` with `--docker` if you'd like to use Docker for the testing runtime environment.

Note: To run integration tests, you must add an [`tests/integration/integration_config.yml`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html#integration-config-yml) file with a valid DigitalOcean API Key (variable `do_api_key`),
AWS Access ID and Secret Key (variables `aws_access_key_id` and `aws_secret_access_key`, respectively). The AWS
variables are used for the DigitalOcean Spaces and CDN Endpoints integration tests.

## Release notes

See the [changelog](https://github.com/ansible-collections/community.digitalocean/blob/main/CHANGELOG.rst).

### Release process

Releases are automatically built and pushed to Ansible Galaxy for any new tag. Before tagging a release, make sure to do the following:

  1. Update `galaxy.yml` and this README's `requirements.yml` example with the new `version` for the collection. Make sure all new modules have references above.
  1. Update the CHANGELOG:
      1. Make sure you have [`antsibull-changelog`](https://pypi.org/project/antsibull-changelog/) installed.
      1. Make sure there are fragments for all known changes in `changelogs/fragments`.
      1. Run `antsibull-changelog release`.
      1. Don't forget to add new folks to `galaxy.yml`.
  1. Commit the changes and create a PR with the changes. Wait for tests to pass, then merge it once they have.
  1. Tag the version in Git and push to GitHub.
      1. Determine the next version (collections follow [semver](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions) semantics) by listing tags or looking at the [releases](https://github.com/ansible-collections/community.digitalocean/releases).
      1. List tags with `git tag --list`
      1. Create a new tag with `git tag 1.2.3`
      1. Push tags upstream with `git push upstream --tags`

After the version is published, verify it exists on the [DigitalOcean Collection Galaxy page](https://galaxy.ansible.com/community/digitalocean).

## More information

  - [DigitalOcean Working Group](https://github.com/ansible/community/wiki/Digital-Ocean)
  - [Ansible Collection overview](https://github.com/ansible-collections/overview)
  - [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
  - [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
  - [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [COPYING](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
