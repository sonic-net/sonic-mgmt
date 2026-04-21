# CyberArk Ansible Secrets Manager Collection

This collection contains components to be used with CyberArk Conjur OSS & Secrets Manager
hosted in [Ansible Galaxy](https://galaxy.ansible.com/cyberark/conjur).

## Table of Contents

* [Certification Level](#certification-level)
* [Requirements](#requirements)
* [Installation](#installation)
* [Secrets Manager Ansible Role](#secrets-manager-ansible-role)
  + [Usage](#usage)
  + [Role Variables](#role-variables)
  + [Example Playbook](#example-playbook)
  + [Summon & Service Managers](#summon---service-managers)
  + [Recommendations](#recommendations)
* [Secrets Manager Ansible Lookup Plugin](#secrets-manager-ansible-lookup-plugin)
  + [Environment variables](#environment-variables)
  + [Role Variables](#role-variables-1)
  + [Examples](#examples)
    - [Retrieve a secret in a Playbook](#retrieve-a-secret-in-a-playbook)
    - [Retrieve a private key in an Inventory file](#retrieve-a-private-key-in-an-inventory-file)
* [Contributing](#contributing)
* [License](#license)

<!-- Table of contents generated with markdown-toc
http://ecotrust-canada.github.io/markdown-toc/ -->

## Certification Level

![](https://img.shields.io/badge/Certification%20Level-Certified-6C757D?link=https://github.com/cyberark/community/blob/main/Conjur/conventions/certification-levels.md)

This repo is a **Certified** level project. It's been reviewed by CyberArk to
verify that it will securely work with CyberArk Enterprise as documented. In
addition, CyberArk offers Enterprise-level support for these features. For more
detailed information on our certification levels, see
[our community guidelines](https://github.com/cyberark/community/blob/main/Conjur/conventions/certification-levels.md#community).

## Requirements

- An instance of [CyberArk Conjur Open Source](https://www.conjur.org) v1.x+ or [CyberArk
  Secrets Manager, Self-Hosted](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Resources/_TopNav/cc_Home.htm)
  (formerly Conjur Enterprise) v10.x+ accessible from the target node
- Ansible >= 2.17

## Using ansible-conjur-collection with Conjur Open Source

Are you using this project with [Conjur Open Source](https://github.com/cyberark/conjur)? Then we
**strongly** recommend choosing the version of this project to use from the latest [Conjur OSS
suite release](https://docs.conjur.org/Latest/en/Content/Overview/Conjur-OSS-Suite-Overview.html).
Secrets Manager maintainers perform additional testing on the suite release versions to ensure
compatibility. When possible, upgrade your Secrets Manager version to match the
[latest suite release](https://docs.conjur.org/Latest/en/Content/ReleaseNotes/ConjurOSS-suite-RN.htm);
when using integrations, choose the latest suite release that matches your Conjur version. For any
questions, please contact us on [Discourse](https://discuss.cyberarkcommons.org/c/conjur/5).

## Installation 

From terminal, run the following command:
```sh
ansible-galaxy collection install cyberark.conjur
```

## Secrets Manager Ansible Role

This Ansible role provides the ability to grant Secrets Manager machine identity to a host. Based on that
identity, secrets can then be retrieved securely using the [Secrets Manager Lookup
Plugin](#secrets-manager-ansible-lookup-plugin) or using the [Summon](https://github.com/cyberark/summon)
tool (installed on hosts with identities created by this role).

### Usage

The Secrets Manager role provides a method to establish the Secrets Manager identity of a remote node with Ansible.
The node can then be granted least-privilege access to retrieve the secrets it needs in a secure
manner.

### Role Variables

* `conjur_appliance_url` _(Required)_: URL of the running Secrets Manager service
* `conjur_account` _(Required)_: Secrets Manager account name
* `conjur_host_factory_token` _(Required)_: [Host
  Factory](https://developer.conjur.net/reference/services/host_factory/) token for layer
  enrollment. This should be specified in the environment on the Ansible controlling host.
* `conjur_host_name` _(Required)_: Name of the host to be created.
* `conjur_ssl_certificate`: Public SSL certificate of the Secrets Manager endpoint
* `conjur_validate_certs`: Boolean value to indicate if the Secrets Manager endpoint should validate
  certificates
* `state`: Specifies whether to install or uninstall the Role on the specified nodes
* `summon.version`: version of Summon to install. Default is `0.8.2`.
* `summon_conjur.version`: version of summon-conjur provider to install. Default is `0.5.3`.

The variables not marked _`(Required)`_ are required for running with an HTTPS Secrets Manager endpoint.

### Example Playbook

Configure a remote node with a Secrets Manager identity and Summon:
```yml
- hosts: servers
  roles:
    - role: cyberark.conjur.conjur_host_identity
      conjur_appliance_url: 'https://conjur.myorg.com'
      conjur_account: 'myorg'
      conjur_host_factory_token: "{{ lookup('env', 'HFTOKEN') }}"
      conjur_host_name: "{{ inventory_hostname }}"
      conjur_ssl_certificate: "{{ lookup('file', '/path/to/conjur.pem') }}"
      conjur_validate_certs: true
```

This example:
- Registers the host `{{ inventory_hostname }}` with Secrets Manager, adding it into the Secrets Manager policy layer
  defined for the provided host factory token.
- Installs Summon with the summon-conjur provider for secret retrieval from Secrets Manager.

### Role Cleanup

Executing the following playbook will clean up configuration and identity files
written to the specified remote nodes, as well as uninstalling Summon and the
summon-conjur provider:
```yml
- hosts: servers
  roles:
    - role: cyberark.conjur.conjur_host_identity
      state: absent
```

### Summon & Service Managers

With Summon installed, using Secrets Manager with a Service Manager (like systemd) becomes a snap. Here's a
simple example of a `systemd` file connecting to Secrets Manager:

```ini
[Unit]
Description=DemoApp
After=network-online.target

[Service]
User=DemoUser
#Environment=CONJUR_MAJOR_VERSION=4
ExecStart=/usr/local/bin/summon --yaml 'DB_PASSWORD: !var staging/demoapp/database/password' /usr/local/bin/myapp
```

`CONJUR_MAJOR_VERSION` set to `4`. You can provide it by uncommenting the relevant line above.

The above example uses Summon to retrieve the password stored in `staging/myapp/database/password`,
set it to an environment variable `DB_PASSWORD`, and provide it to the demo application process.
Using Summon, the secret is kept off disk. If the service is restarted, Summon retrieves the
password as the application is started.

### Recommendations

- Add `no_log: true` to each play that uses sensitive data, otherwise that data can be printed to
  the logs.

- Set the Ansible files to minimum permissions. Ansible uses the permissions of the user that runs
  it.

## Secrets Manager Ansible Lookup Plugin

The Conjur Ansible Lookup Plugin allows you to securely fetch credentials from CyberArk Conjur using various authentication methods. The plugin supports the following types of authentication:

- API Key Authentication

- AWS IAM Authentication (via IMDS token)

- Azure Authentication (via Managed Identity)

- GCP Authentication (via IMDS token)

Each authentication method retrieves secrets from Conjur dynamically, ensuring secure and seamless integration with cloud environments and Conjur.

### Authentication Parameters

Credentials can be fetched from CyberArk Conjur using the controlling host's Conjur identity, environment variables, or extra-vars.

The controlling host running Ansible must have a Conjur identity, provided for example by the
[Secrets Manager role](#secrets-manager-ansible-role).

### Authentication Methods

#### 1. API Key Authentication

This is the default method for authenticating with Secrets Manager using an API key.

#### Required Extra-vars/Environment Variables:

- `conjur_appliance_url / CONJUR_APPLIANCE_URL`: URL of the running Secrets Manager service (e.g., https://conjur.example.com).

- `conjur_authn_login / CONJUR_AUTHN_LOGIN`: The identity of the Secrets Manager host (e.g., host/my-host).

- `conjur_authn_api_key / CONJUR_AUTHN_API_KEY`: The API key corresponding to the Secrets Manager host username.

#### Optional Extra-vars/Environment Variables:
- `conjur_account / CONJUR_ACCOUNT`: The Secrets Manager account name (default: conjur).

- `conjur_cert_content / CONJUR_CERT_CONTENT`: Content of the Secrets Manager certificate (PEM format).

- `conjur_cert_file / CONJUR_CERT_FILE`: Path to the Secrets Manager certificate file.

- `conjur_authn_token_file / CONJUR_AUTHN_TOKEN_FILE`: Path to a file containing a valid Secrets Manager auth token.

#### API Key Authentication

The lookup plugin authenticates the workload using the API key and retrieves the secrets.


#### 2. AWS IAM Authentication
This method uses AWS IAM roles and Instance Metadata Service (IMDS) tokens for authentication.

#### Required Extra-vars/Environment Variables:
- `conjur_authn_type / CONJUR_AUTHN_TYPE` : Authentication type ("aws").

- `conjur_appliance_url / CONJUR_APPLIANCE_URL`: URL of the running Secrets Manager service (e.g., https://conjur.example.com).

- `conjur_authn_login / CONJUR_AUTHN_LOGIN`: The identity of the Secrets Manager host (e.g., host/my-host).

- `conjur_authn_service_id / CONJUR_AUTHN_SERVICE_ID`: The service ID used for the AWS Authenticator web service.

#### Optional Extra-vars/Environment Variables:
- `conjur_account / CONJUR_ACCOUNT`: The Secrets Manager account name (default: conjur).

- `conjur_cert_content / CONJUR_CERT_CONTENT`: Content of the Secrets Manager certificate (PEM format).

- `conjur_cert_file / CONJUR_CERT_FILE`: Path to the Secrets Manager certificate file.

#### How AWS Authentication Works

For AWS IAM Authentication, the plugin uses AWS Instance Metadata Service (IMDS) to obtain a token for the current instance. This token is then used to authenticate the instance against Secrets Manager and obtain secrets securely. This eliminates the need for static API keys and enhances security by utilizing temporary credentials provided by the IMDS.

#### 3. Azure Authentication

This method uses Azure Managed Identity to authenticate with Secrets Manager.

#### Required Extra-vars/Environment Variables:

- `conjur_authn_type / CONJUR_AUTHN_TYPE` : Authentication type ("azure").

- `conjur_appliance_url / CONJUR_APPLIANCE_URL`: URL of the running Secrets Manager service (e.g., https://conjur.example.com).

- `conjur_authn_login / CONJUR_AUTHN_LOGIN`: The identity of the Secrets Manager host (e.g., host/my-host).

- `conjur_authn_service_id / CONJUR_AUTHN_SERVICE_ID`: The service ID used for the Azure Authenticator web service.

#### Optional Extra-vars/Environment Variables:

- `conjur_account / CONJUR_ACCOUNT`: The Secrets Manager account name (default: conjur).

- `conjur_cert_content / CONJUR_CERT_CONTENT`: Content of the Secrets Manager certificate (PEM format).

- `conjur_cert_file / CONJUR_CERT_FILE`: Path to the Secrets Manager certificate file.

- `azure_client_id / AZURE_CLIENT_ID`: The Azure client ID for User Assigned Managed Identity (optional).

#### How Azure Authentication Works

For Azure Authentication, the plugin uses Azure Instance Metadata Service (IMDS) to retrieve authentication tokens for Azure Managed Identity. This allows the plugin to authenticate workloads running in Azure dynamically, fetching the necessary secrets from Secrets Manager without needing static credentials.

#### 4. GCP Authentication

This method allows you to authenticate using a Google Cloud Platform (GCP) Service Account.

#### Required Extra-vars/Environment Variables:

- `conjur_authn_type / CONJUR_AUTHN_TYPE` : Authentication type ("gcp").

- `conjur_appliance_url / CONJUR_APPLIANCE_URL`: URL of the running Secrets Manager service (e.g., https://conjur.example.com).

- `conjur_authn_login / CONJUR_AUTHN_LOGIN`: The identity of the Secrets Manager host (e.g., host/my-host).


#### Optional Extra-vars/Environment Variables:

- `conjur_account / CONJUR_ACCOUNT`: The Secrets Manager account name (default: conjur).

- `conjur_cert_content / CONJUR_CERT_CONTENT`: Content of the Secrets Manager certificate (PEM format).

- `conjur_cert_file / CONJUR_CERT_FILE`: Path to the Secrets Manager certificate file.

#### How GCP Authentication Works

For GCP Authentication, the plugin uses Google Cloud Instance Metadata Service (IMDS) to authenticate the workload by retrieving a JWT token. The token is used to authenticate against Secrets Manager, allowing the plugin to fetch the requested secrets securely.

### Example Playbooks and Ansible Commands

Below are example playbooks and the corresponding Ansible commands to run them for each authentication method.

#### 1. API Key Authentication

##### Playbook Example:

```yaml
---
- hosts: localhost
  collections:
    - cyberark.conjur
  tasks:
    - name: Lookup variable in Secrets Manager
      debug:
        msg: "{{ lookup('cyberark.conjur.conjur_variable', 'data/ansible/target-secret') }}"
```

##### Using with Extra-vars:

```sh
ansible-playbook -v \
--extra-vars "conjur_appliance_url=https://conjur.example.com" \
--extra-vars "conjur_authn_login=host/my-host" \
--extra-vars "conjur_authn_api_key=<your_conjur_api_key>" \
--extra-vars "conjur_cert_file=<path>/certificate.pem" retrieve-secrets.yaml
```

Alternatively, to provide the certificate content in PEM format as a string:

```sh
ansible-playbook -v \
--extra-vars "conjur_appliance_url=https://conjur.example.com" \
--extra-vars "conjur_authn_login=host/my-host" \
--extra-vars "conjur_authn_api_key=<your_conjur_api_key>" \
--extra-vars "conjur_cert_content='-----BEGIN CERTIFICATE-----\n<your certificate content>\n-----END CERTIFICATE-----\n'" retrieve-secrets.yaml
```
#### Using with Environment variables:

```sh
export CONJUR_APPLIANCE_URL="https://conjur.example.com"
export CONJUR_ACCOUNT="myaccount"
export CONJUR_AUTHN_LOGIN="host/testapp"
export CONJUR_AUTHN_API_KEY="<your_conjur_api_key>"
export CONJUR_CERT_FILE="<path>/certificate.pem"
```

```sh
ansible-playbook -v retrieve-secrets.yaml
```

#### 2. AWS IAM Authentication

##### Playbook Example:

```yaml
---
- hosts: localhost
  collections:
    - cyberark.conjur
  tasks:
    - name: Lookup variable in Secrets Manager
      debug:
        msg: "{{ lookup('cyberark.conjur.conjur_variable', 'data/ansible/target-secret') }}"
```
##### Using with Extra-vars:

```sh
ansible-playbook -v \
--extra-vars "conjur_authn_type=aws" \
--extra-vars "conjur_appliance_url=https://conjur.example.com" \
--extra-vars "conjur_authn_login=host/my-host" \
--extra-vars "conjur_authn_service_id=<your_conjur_service_id>" \
--extra-vars "conjur_cert_file=<path>/certificate.pem" retrieve-secrets.yaml
```

Alternatively, to provide the certificate content in PEM format as a string:

```sh
ansible-playbook -v \
--extra-vars "conjur_authn_type=aws" \
--extra-vars "conjur_appliance_url=https://conjur.example.com" \
--extra-vars "conjur_authn_login=host/my-host" \
--extra-vars "conjur_authn_service_id=<your_conjur_service_id>" \ 
--extra-vars "conjur_cert_content='-----BEGIN CERTIFICATE-----\n<your certificate content>\n-----END CERTIFICATE-----\n'" retrieve-secrets.yaml
```
#### Using with Environment variables:

```sh
export CONJUR_AUTHN_TYPE="aws"
export CONJUR_APPLIANCE_URL="https://conjur.example.com"
export CONJUR_ACCOUNT="myaccount"
export CONJUR_AUTHN_LOGIN="host/testapp"
export CONJUR_AUTHN_SERVICE_ID="<your_conjur_service_id>"
export CONJUR_CERT_FILE="<path>/certificate.pem"
```

```sh
ansible-playbook -v retrieve-secrets.yaml
```

#### 3. Azure Authentication

##### Playbook Example:

```yaml
---
- hosts: localhost
  collections:
    - cyberark.conjur
  tasks:
    - name: Lookup variable in Secrets Manager
      debug:
        msg: "{{ lookup('cyberark.conjur.conjur_variable', 'data/ansible/target-secret') }}"
```
##### Using with Extra-vars:

```sh
ansible-playbook -v \
--extra-vars "conjur_authn_type=azure" \
--extra-vars "conjur_appliance_url=https://conjur.example.com" \
--extra-vars "conjur_authn_login=host/my-host" \
--extra-vars "conjur_authn_service_id=<your_conjur_service_id>" \
--extra-vars "azure_client_id=<your_azure_client_id>" \
--extra-vars "conjur_cert_file=<path>/certificate.pem" retrieve-secrets.yaml
```

Alternatively, to provide the certificate content in PEM format as a string:

```sh
ansible-playbook -v \
--extra-vars "conjur_authn_type=azure" \
--extra-vars "conjur_appliance_url=https://conjur.example.com" \
--extra-vars "conjur_authn_login=host/my-host" \
--extra-vars "conjur_authn_service_id=<your_conjur_service_id>" \
--extra-vars "azure_client_id=<your_azure_client_id>" \
--extra-vars "conjur_cert_content='-----BEGIN CERTIFICATE-----\n<your certificate content>\n-----END CERTIFICATE-----\n'" retrieve-secrets.yaml
```
#### Using with Environment variables:

```sh
export CONJUR_AUTHN_TYPE="azure"
export CONJUR_APPLIANCE_URL="https://conjur.example.com"
export CONJUR_ACCOUNT="myaccount"
export CONJUR_AUTHN_LOGIN="host/testapp"
export CONJUR_AUTHN_SERVICE_ID="<your_conjur_service_id>"
export AZURE_CLIENT_ID="<your_azure_client_id>"
export CONJUR_CERT_FILE="<path>/certificate.pem"
```

```sh
ansible-playbook -v retrieve-secrets.yaml
```
#### 4. GCP Authentication

##### Playbook Example:

```yaml
---
- hosts: localhost
  collections:
    - cyberark.conjur
  tasks:
    - name: Lookup variable in Secrets Manager
      debug:
        msg: "{{ lookup('cyberark.conjur.conjur_variable', 'data/ansible/target-secret') }}"
```
##### Using with Extra-vars:

```sh
ansible-playbook -v \
--extra-vars "conjur_authn_type=gcp" \
--extra-vars "conjur_appliance_url=https://conjur.example.com" \
--extra-vars "conjur_authn_login=host/my-host" \
--extra-vars "conjur_cert_file=<path>/certificate.pem" retrieve-secrets.yaml
```

Alternatively, to provide the certificate content in PEM format as a string:

```sh
ansible-playbook -v \
--extra-vars "conjur_authn_type=gcp" \
--extra-vars "conjur_appliance_url=https://conjur.example.com" \
--extra-vars "conjur_authn_login=host/my-host" \
--extra-vars "conjur_cert_content='-----BEGIN CERTIFICATE-----\n<your certificate content>\n-----END CERTIFICATE-----\n'" retrieve-secrets.yaml
```
#### Using with Environment variables:

```sh
export CONJUR_AUTHN_TYPE="gcp"
export CONJUR_APPLIANCE_URL="https://conjur.example.com"
export CONJUR_ACCOUNT="myaccount"
export CONJUR_AUTHN_LOGIN="host/testapp"
export CONJUR_CERT_FILE="<path>/certificate.pem"
```

```sh
ansible-playbook -v retrieve-secrets.yaml
```

### Certificate Content Format

In addition to specifying a certificate file (using CONJUR_CERT_FILE environment variable or conjur_cert_file extra-vars), you can now provide the certificate content directly via the CONJUR_CERT_CONTENT environment variable or conjur_cert_content extra-vars. This is useful when you prefer to include the certificate as a string (PEM format) instead of referencing a file on disk.

### How it works

The lookup plugin will first attempt to use the CONJUR_CERT_CONTENT or conjur_cert_content variable (either from the environment or extra-vars). If it is invalid or missing, the plugin will fall back to using the certificate file specified in the CONJUR_CERT_FILE or conjur_cert_file.

### Example

1. CONJUR_CERT_CONTENT or conjur_cert_content as PEM format

You can provide the certificate directly as a string in PEM format inside the CONJUR_CERT_CONTENT environment variable or conjur_cert_content extra-vars. Ensure that the content includes the full certificate block starting with -----BEGIN CERTIFICATE----- and ending with -----END CERTIFICATE-----.

Using Environment Variable:

```sh
export CONJUR_CERT_CONTENT="-----BEGIN CERTIFICATE-----
<your certificate content>
-----END CERTIFICATE-----"
```

Using extra-vars:

```sh
ansible-playbook -v \
--extra-vars "conjur_cert_content='-----BEGIN CERTIFICATE-----
<your certificate content>
-----END CERTIFICATE-----'" retrieve-secrets.yaml
```

Once set, the plugin will look for this variable and use the certificate content as needed.

2. CONJUR_CERT_FILE or conjur_cert_file as File

If CONJUR_CERT_CONTENT environment variable or conjur_cert_content extra-vars is not set or is invalid, the plugin will attempt to use the certificate file specified in the CONJUR_CERT_FILE environment variable or conjur_cert_file extra-vars.

Using Environment Variable:

```sh
export CONJUR_CERT_FILE="<path>/certificate.pem"
```
Using extra-vars:

```sh
ansible-playbook -v \
--extra-vars "conjur_cert_file=<path>/certificate.pem" retrieve-secrets.yaml
```

3. If both CONJUR_CERT_CONTENT or conjur_cert_content and CONJUR_CERT_FILE or conjur_cert_file are missing or invalid, the plugin will return an error. This allows you to quickly diagnose the issue and ensure that the required certificate is provided.

### Role Variables

None.

### Examples

#### Retrieve a secret in a Playbook
 
```yaml
---
- hosts: localhost
  tasks:
  - name: Lookup variable in Secrets Manager
    debug:
      msg: "{{ lookup('cyberark.conjur.conjur_variable', '/path/to/secret') }}"
```

#### Retrieve a private key in an Inventory file

```yaml
---
ansible_host: <host>
ansible_ssh_private_key_file: "{{ lookup('cyberark.conjur.conjur_variable', 'path/to/secret-id', as_file=true) }}"
```

**Note:** Using the `as_file=true` condition, the private key is stored in a temporary file and its path is written 
in `ansible_ssh_private_key_file`.

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and
descriptions of our development workflows, please see our [contributing guide][contrib].

[contrib]: https://github.com/cyberark/ansible-conjur-collection/blob/main/CONTRIBUTING.md

## License

Copyright (c) 2025 CyberArk Software Ltd. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.

For the full license text see [`LICENSE`](LICENSE).
