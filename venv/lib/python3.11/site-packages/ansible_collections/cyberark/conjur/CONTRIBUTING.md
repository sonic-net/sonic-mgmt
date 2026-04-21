# Contributing to the Ansible Secrets Manager Collection

Thanks for your interest in Secrets Manager. Before contributing, please take a moment to
read and sign our <a href="https://github.com/cyberark/community/blob/master/documents/CyberArk_Open_Source_Contributor_Agreement.pdf" download="conjur_contributor_agreement">Contributor Agreement</a>.
This provides patent protection for all Secrets Manager users and allows CyberArk to enforce
its license terms. Please email a signed copy to <a href="oss@cyberark.com">oss@cyberark.com</a>.
For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

- [Contributing to the Ansible Secrets Manager Collection](#contributing-to-the-ansible-secrets-manager-collection)
  * [Prerequisites](#prerequisites)
  * [Set up a development environment](#set-up-a-development-environment)
    + [Verification](#verification)
    + [Useful links](#useful-links)
  * [Testing](#testing)
    + [Unit tests](#unit-tests)
    + [Integration tests](#integration-tests)
  * [Releasing](#releasing)
- [Ansible Secrets Manager Collection Quick Start](#ansible-secrets-manager-collection-quick-start)
  * [Setup a conjur OSS Environment](#setup-a-conjur-oss-environment)
  * [Load policy to set up Secrets Manager Ansible integration](#load-policy-to-set-up-secrets-manager-ansible-integration)
  * [Create Ansible managed nodes](#create-ansible-managed-nodes)
  * [Use Secrets Manager Ansible Role to set up identity on managed nodes](#use-secrets-manager-ansible-role-to-set-up-identity-on-managed-nodes)
  * [Use Secrets Manager Lookup Plugin to provide secrets to Ansible Playbooks](#use-secrets-manager-lookup-plugin-to-provide-secrets-to-ansible-playbooks)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

## Prerequisites

Before getting started, the following tools need to be installed:

1. [Git][get-git] to manage source code
2. [Docker][get-docker] to manage dependencies and runtime environments
3. [Docker Compose][get-docker-compose] to orchestrate Docker environments

[get-docker]: https://docs.docker.com/engine/installation
[get-docker-compose]: https://docs.docker.com/compose/install
[get-git]: https://git-scm.com/downloads

## Set up a development environment

The `dev` directory contains a `docker-compose.yml` file which creates a development
environment :
-  A Conjur Open Source instance
-  An Ansible control node
-  Managed nodes to push tasks to

To use it:

1. Install dependencies (as above)
2. Clone the [Collection repository](https://github.com/cyberark/ansible-conjur-collection):
```sh-session
$ git clone https://github.com/cyberark/ansible-conjur-collection.git
```
3. Create a VERSION file in the project root containing the last version from CHANGELOG.md (example: 1.3.7)
```sh-session
$ cd ansible-conjur-collection
$ echo <major>.<minor>.<patch> > VERSION
```
4. Run the setup script:

```sh-session
$ cd dev
$ ./start.sh
```

### Verification

When the Secrets Manager and Ansible containers have been successfully setup, the
terminal prints the following:

```sh-session
  ...
  PLAY RECAP *********************************************************************
  ansibleplugingtestingconjurhostidentity-test_app_centos-1 : ok=17 ...
  ansibleplugingtestingconjurhostidentity-test_app_centos-2 : ok=17 ...
  ansibleplugingtestingconjurhostidentity-test_app_ubuntu-1 : ok=16 ...
  ansibleplugingtestingconjurhostidentity-test_app_ubuntu-2 : ok=16 ...
  ```

Your Secrets Manager instance will be configured with the following:
* Account: `cucumber`
* User: `admin`
* Password: Run `conjurctl role retrieve-key cucumber:user:admin` inside the
  Secrets Manager container shell to retrieve the admin user API key

### Useful links

- [Official documentation for Secrets Manager's Ansible integration](https://docs.conjur.org/Latest/en/Content/Integrations/ansible.html)
- [Secrets Manager Collection on Ansible Galaxy](https://galaxy.ansible.com/cyberark/conjur)
- [Ansible documentation for the Secrets Manager collection](https://docs.ansible.com/ansible/latest/collections/cyberark/conjur/index.html)

## Testing

### Unit tests

Unit tests are only available for the Secrets Manager Variable Lookup plugin. To run
these tests:
```
./dev/test_unit.sh
```

### Integration tests

The collection has integration tests for both the Variable Lookup plugin and the
Host Identity role that will validate each against live Secrets Manager and Ansible
containers.

To run all tests:
```
./ci/test.sh -a
```

To run the tests for a particular module:
```
./ci/test.sh -d <role or plugin name>
```

Integration tests can be run against Secrets Manager, Self-Hosted by adding the `-e` flag:
```
./ci/test.sh -e -a
```

## Releasing

Releases should be created by maintainers only. To create a tag and release,
follow the instructions in this section.

### Update the changelog and notices (if necessary)
1. Update the `CHANGELOG.md` file with the new version and the changes that are included in the release.
1. Update the version number in [`galaxy.yml`](galaxy.yml)

### Pre-requisites

1. Review the git log and ensure the [changelog](CHANGELOG.md) contains all
   relevant recent changes with references to GitHub issues or PRs, if possible.
   Also ensure the latest unreleased version is accurate - our pipeline generates 
   a VERSION file based on the changelog, which is then used to assign the version
   of the release and any release artifacts.
1. Ensure that all documentation that needs to be written has been 
   written by TW, approved by PO/Engineer, and pushed to the forward-facing documentation.
1. Scan the project for vulnerabilities

### Release and Promote

1. Merging into main/master branches will automatically trigger a release. If successful, this release can be promoted at a later time.
1. Jenkins build parameters can be utilized to promote a successful release or manually trigger aditional releases as needed.
1. Reference the [internal automated release doc](https://github.com/conjurinc/docs/blob/master/reference/infrastructure/automated_releases.md#release-and-promotion-process) for releasing and promoting.
1. A `PROMOTE` build will kick off an automated script which publish the release to
      [Ansible Galaxy](https://galaxy.ansible.com/cyberark/conjur)

# Ansible Secrets Manager Collection Quick Start

## Setup a conjur OSS Environment

Generate the master key, which will be used to encrypt Conjur's database. Store
this value as an environment variable.

```sh-session
docker compose run --no-deps --rm conjur data-key generate > data_key
export CONJUR_DATA_KEY="$(< data_key)"
```

Start the Conjur OSS environment. An account, named `cucumber`, will be
automatically created.

```sh-session
docker compose up -d conjur
```

Retrieve the admin user's API key, and store the value in an environment variable.

```sh-session
export CLI_CONJUR_AUTHN_API_KEY="$(docker compose exec conjur conjurctl role retrieve-key cucumber:user:admin)"
```

Start the Secrets Manager CLI container. The CLI will be automatically authenticated as
the user `cucumber:user:admin`.

```sh-session
docker compose up -d conjur_cli
```

## Load policy to set up Secrets Manager Ansible integration

Policy defines Secrets Manager entities and the relationships between them. An entity can
be a policy, a host, a user, a layer, a group, or a variable.

Check out the policy file, and load it into Secrets Manager:

```sh-session
docker compose exec conjur_cli cat /policy/root.yml
docker compose exec conjur_cli conjur policy load root /policy/root.yml
```

Also, load a dummy secret value into the `ansible/target-password` variable.
This is a variable required by remote nodes in order to complete their workloads.

```sh-session
docker compose exec conjur_cli conjur variable values add ansible/target-password S3cretV@lue
```

## Create Ansible managed nodes

The Ansible environment will include a control node and a number of managed
nodes. First, retrieve the API key for the Secrets Manager host representing the control
node, then create it:

```sh-session
export ANSIBLE_CONJUR_AUTHN_API_KEY="$(docker compose exec conjur conjurctl role retrieve-key cucumber:host:ansible/ansible-master)"
docker compose up -d ansible
```

Next, create two instances of each managed node:

```sh-session
docker compose up -d --scale test_app_ubuntu=2 test_app_ubuntu
docker compose up -d --scale test_app_centos=2 test_app_centos
```

## Use Secrets Manager Ansible Role to set up identity on managed nodes

To grant your Ansible host a Secrets Manager identity, first install the Secrets Manager
Collection on your Ansible control node:

```sh-session
docker compose exec ansible ansible-galaxy collection install cyberark.conjur
```

Set up the host factory token in the HFTOKEN env var

```sh-session
export HFTOKEN="$(docker compose exec conjur_cli conjur hostfactory tokens create ansible/ansible-factory | jq -r '.[0].token')"
```

Once you've done this, you can configure each Ansible node with a Secrets Manager
identity by including a section like the example below in your Ansible playbook:

```yaml
---
- hosts: testapp
  roles:
    - role: cyberark.conjur.conjur_host_identity
      conjur_appliance_url: 'https://conjur.myorg.com',
      conjur_account: 'cucumber',
      conjur_host_factory_token: "{{lookup('env', 'HFTOKEN')}}",
      conjur_host_name: "{{inventory_hostname}}"
```

First we register the host with Secrets Manager, adding it into the layer specific to the
provided host factory token, and then install Summon with the Summon Secrets Manager
provider for secret retrieval from Secrets Manager.

## Use Secrets Manager Lookup Plugin to provide secrets to Ansible Playbooks

The Secrets Manager lookup plugin can inject secret data directly into an Ansible
playbook, like it the following example:

```yaml
---
- hosts: testapp
  tasks:
  - name: Provide secret with Lookup plugin
    debug:
      msg: "{{ lookup('cyberark.conjur.conjur_variable', '/ansible/target-password') }}"
```
