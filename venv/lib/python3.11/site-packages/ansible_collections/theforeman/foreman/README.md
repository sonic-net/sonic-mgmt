# Foreman Ansible Modules ![Build Status](https://github.com/theforeman/foreman-ansible-modules/workflows/CI/badge.svg)

Ansible modules for interacting with the Foreman API and various plugin APIs such as Katello.

## Documentation

A list of all modules and their documentation can be found at [theforeman.org/plugins/foreman-ansible-modules](https://theforeman.org/plugins/foreman-ansible-modules/).

## Support

### Supported Foreman and plugins versions

Modules should support any currently stable Foreman release and the matching set of plugins.
Some modules have additional features/arguments that are only applied when the corresponding plugin is installed.

We actively test the modules against the latest stable Foreman release and the matching set of plugins.

### Supported Ansible Versions

The supported Ansible versions are aligned with currently maintained Ansible versions that support Collections (2.10+).
You can find the list of maintained Ansible versions [here](https://docs.ansible.com/ansible/devel/reference_appendices/release_and_maintenance.html).

### Supported Python Versions

The supported Python versions are aligned with the currently supported Python versions by maintained Ansible releases.
You can find the list of maintained Ansible releases and their supported Python versions versions [here](https://docs.ansible.com/ansible/devel/reference_appendices/release_and_maintenance.html).

### Known issues

* Some modules, e.g. `repository_sync` and `content_view_version`, trigger long running tasks on the server side. It might be beneficial to your playbook to wait for their completion in an asynchronous manner.
  As Ansible has facilities to do so, the modules will wait unconditionally. See the [Ansible documentation](https://docs.ansible.com/ansible/latest/user_guide/playbooks_async.html) for putting tasks in the background.
  Please make sure to set a high enough `async` value, as otherwise Ansible might abort the execution of the module while there is still a task running on the server, making status reporting fail.

* According to [Ansible documentation](https://docs.ansible.com/ansible/latest/user_guide/playbooks_loops.html), using loop over Ansible resources can leak sensitive data. This applies to all modules, but especially those which require more secrets than the API credentials (`auth_source_ldap`, `compute_resource`, `host`, `hostgroup`, `http_proxy`, `image`, `repository`, `scc_account`, `user`). You can prevent this by using `no_log: true` on the task.
  
  eg:

   ```yaml
   - name: Create compute resources
     theforeman.foreman.compute_resource:
       server_url: https://foreman.example.com
       username: admin
       password: changeme
       validate_certs: true
       name: "{{ item.name }}"
       organizations: "{{ item.organizations | default(omit) }}"
       locations: "{{ item.locations | default(omit) }}"
       description: "{{ item.description | default(omit) }}"
       provider: "{{ item.provider }}"
       provider_params: "{{ item.provider_params | default(omit) }}"
       state: "{{ item.state | default('present') }}"
     loop: "{{ compute_resources }}"
     no_log: true
   ```
* Modules require write access to `~/.cache` (or wherever `$XDG_CACHE_HOME` points at). Otherwise the API documentation cannot be downloaded and you get errors like `[Errno 13] Permission denied: '/home/runner/.cache/apypie`. If on your system `~/.cache` is not writeable, please set the `$XDG_CACHE_HOME` environment variable to a directory Ansible can write to.

## Installation

There are currently two ways to use the modules in your setup: install directly from Ansible Galaxy or via packages.

### Installation from Ansible Galaxy

You can install the collection from [Ansible Galaxy](https://galaxy.ansible.com/theforeman/foreman) by running `ansible-galaxy collection install theforeman.foreman`.

After the installation, the modules are available as `theforeman.foreman.<module_name>`. Please see the [Using Ansible collections documentation](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for further details.

### Installation via packages

The collection is also available as `ansible-collection-theforeman-foreman` from the `plugins` repository on `yum.theforeman.org` for Enterprise Linux systems and from the `plugins` repository on `deb.theforeman.org` for Debian and Ubuntu systems.

After installing the package, you can use the modules in the same way as when they are installed directly from Ansible Galaxy.

## Installation From Source

For development or testing purposes, you can install the collection from source git repository. For production usage, see the instructions above on installing the latest stable release.

### Installation from Github Repository

With Ansible >= 2.10, you can install from a Github repository (such as this one or your fork):

```console
$ ansible-galaxy collection install git+https://github.com/theforeman/foreman-ansible-modules.git
```

If you have configured GitHub to use SSH instead of HTTPS, you can do:

```console
$ ansible-galaxy collection install git@github.com/theforeman/foreman-ansible-modules.git
```

You can also specify a branch to use such as `devel` (below) or a feature branch that you are working with:

```console
$ ansible-galaxy collection install git+https://github.com/theforeman/foreman-ansible-modules.git,devel
```

To install from a `requirements.yml` file (useful when installing multiple collections) add a snippet to your `requirements.yml` like

```yaml
---
collections:
  - name: https://github.com/theforeman/foreman-ansible-modules.git
    type: git
    version: develop
```

And install all specified requirements with `ansible-galaxy install -r requirements.yml`

### Building and Installing the Collection Locally

For all currently supported versions of Ansible, you can build the collection locally:

```console
$ make dist
```

And install it with:

```console
$ ansible-galaxy collection install ./theforeman-foreman-*.tar.gz
```

## Dependencies

These dependencies are required for the Ansible controller, not the Foreman server.

* [`PyYAML`](https://pypi.org/project/PyYAML/)
* [`requests`](https://pypi.org/project/requests/)
* `rpm` for the RPM support in the `content_upload` module
* `debian` for the DEB support in the `content_upload` module

## Module defaults groups

With ansible-core >= 2.12 and version >= 3.4.0 of the collection it is possible to specify defaults parameters for all modules in this collection using [Module defaults groups](https://docs.ansible.com/ansible/latest/user_guide/playbooks_module_defaults.html#module-defaults-groups). Use it like this:

```yaml
---
- name: Configure Foreman
  hosts: foreman.example.com

  module_defaults:
    group/theforeman.foreman.foreman:
      server_url: "https://foreman.example.com"
      username: "admin"
      password: "changeme"

  tasks:
    - name: Setup architecture
      theforeman.foreman.architecture:
        name: "x86_64"
    - name: Setup sync plan
      theforeman.foreman.sync_plan:
        organization: "Default Organization"
        name: "Daily"
        interval: "daily"
        enabled: true
        sync_date: "2025-07-10 00:00:00 +0000"
```

# Foreman Ansible Roles

Roles using the Foreman Ansible Modules to configure Foreman and its plugins.

## Documentation

For individual role documentation, check the README defined at `roles/rolename/README.md`.

### Common Role Variables

- `foreman_server_url`: URL of the Foreman server. If the variable is not specified, the value of environment variable `FOREMAN_SERVER_URL` will be used instead.
- `foreman_username`: Username accessing the Foreman server. If the variable is not specified, the value of environment variable `FOREMAN_USERNAME` will be used instead.
- `foreman_password`: Password of the user accessing the Foreman server. If the variable is not specified, the value of environment variable `FOREMAN_PASSWORD` will be used instead.
- `foreman_validate_certs`: Whether or not to verify the TLS certificates of the Foreman server. If the variable is not specified, the value of environment variable `FOREMAN_VALIDATE_CERTS` will be used instead.
- `foreman_organization`: Organization where configuration will be applied.
