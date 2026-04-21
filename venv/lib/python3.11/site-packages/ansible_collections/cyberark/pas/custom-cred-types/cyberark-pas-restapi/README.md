# CyberArk PAS REST API

Custom Credential Type for Ansible Tower

## Installation

1. Login to Ansible Tower as a Tower Administrator.
2. Under Administration, click on Credential Type.
3. Click the green [ + ] in the top right-hand corner to create a new Custom Credential Type.
4. Set the name of your Credential Type. e.g. `CyberArk PAS REST API`
5. Under `Input Configuration` select `YAML`.
6. Copy and paste the [input.yml](input.yml) into the text field for `Input Configuration`.
7. Under `Injector Configuration` select `YAML`.
8. Copy and paste the [injector.yml](injector.yml) into the text field for `Injector Configuration`.
9. Click `Save` at the bottom to save the Custom Credential Type.

## Usage

Reference the following environment variables within your Ansible Playbook when using this Credential Type:

* `CYBERARK_API_URL` \
This is the Base URI of your CyberArk Password Vault Web Access (PVWA). _e.g. `https://pvwa.cyberark.com`_

* `CYBERARK_API_USERNAME` \
This is the username to use when logging into the CyberArk PAS Web Services SDK (REST API).

* `CYBERARK_API_PASSWORD` \
This is the password associated with the username provided for login.

## Maintainer

Joe Garcia, CISSP - DevOps Security Engineer, CyberArk - [@infamousjoeg](https://github.com/infamousjoeg)
