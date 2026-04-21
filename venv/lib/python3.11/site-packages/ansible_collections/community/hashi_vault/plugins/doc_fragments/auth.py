# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
    options:
      auth_method:
        description:
          - Authentication method to be used.
          - C(none) auth method was added in collection version C(1.2.0).
          - C(cert) auth method was added in collection version C(1.4.0).
          - C(aws_iam_login) was renamed C(aws_iam) in collection version C(2.1.0) and was removed in C(3.0.0).
          - C(azure) auth method was added in collection version C(3.2.0).
          - C(gcp) auth method was added in collection version C(7.1.0).
        choices:
          - token
          - userpass
          - ldap
          - approle
          - aws_iam
          - azure
          - jwt
          - cert
          - gcp
          - none
        default: token
        type: str
      mount_point:
        description:
          - Vault mount point.
          - If not specified, the default mount point for a given auth method is used.
          - Does not apply to token authentication.
        type: str
      token:
        description:
          - Vault token. Token may be specified explicitly, through the listed [env] vars, and also through the C(VAULT_TOKEN) env var.
          - If no token is supplied, explicitly or through env, then the plugin will check for a token file, as determined by I(token_path) and I(token_file).
          - The order of token loading (first found wins) is C(token param -> ansible var -> ANSIBLE_HASHI_VAULT_TOKEN -> VAULT_TOKEN -> token file).
        type: str
      token_path:
        description: If no token is specified, will try to read the I(token_file) from this path.
        type: str
      token_file:
        description: If no token is specified, will try to read the token from this file in I(token_path).
        default: '.vault-token'
        type: str
      token_validate:
        description:
          - For token auth, will perform a C(lookup-self) operation to determine the token's validity before using it.
          - Disable if your token does not have the C(lookup-self) capability.
        type: bool
        default: false
        version_added: 0.2.0
      username:
        description: Authentication user name.
        type: str
      password:
        description: Authentication password.
        type: str
      role_id:
        description:
          - Vault Role ID or name. Used in C(approle), C(aws_iam), C(azure) and C(cert) auth methods.
          - For C(cert) auth, if no I(role_id) is supplied, the default behavior is to try all certificate roles and return any one that matches.
          - For C(azure) auth, I(role_id) is required.
        type: str
      secret_id:
        description: Secret ID to be used for Vault AppRole authentication.
        type: str
      jwt:
        description: The JSON Web Token (JWT) to use for JWT authentication to Vault.
        type: str
      aws_profile:
        description: The AWS profile
        type: str
        aliases: [ boto_profile ]
      aws_access_key:
        description: The AWS access key to use.
        type: str
        aliases: [ aws_access_key_id ]
      aws_secret_key:
        description: The AWS secret key that corresponds to the access key.
        type: str
        aliases: [ aws_secret_access_key ]
      aws_security_token:
        description: The AWS security token if using temporary access and secret keys.
        type: str
      region:
        description: The AWS region for which to create the connection.
        type: str
      aws_iam_server_id:
        description: If specified, sets the value to use for the C(X-Vault-AWS-IAM-Server-ID) header as part of C(GetCallerIdentity) request.
        required: False
        type: str
        version_added: '0.2.0'
      azure_tenant_id:
        description:
          - The Azure Active Directory Tenant ID (also known as the Directory ID) of the service principal. Should be a UUID.
          - >-
            Required when using a service principal to authenticate to Vault,
            e.g. required when both I(azure_client_id) and I(azure_client_secret) are specified.
          - Optional when using managed identity to authenticate to Vault.
        required: False
        type: str
        version_added: '3.2.0'
      azure_client_id:
        description:
          - The client ID (also known as application ID) of the Azure AD service principal or managed identity. Should be a UUID.
          - If not specified, will use the system assigned managed identity.
        required: False
        type: str
        version_added: '3.2.0'
      azure_client_secret:
        description: The client secret of the Azure AD service principal.
        required: False
        type: str
        version_added: '3.2.0'
      azure_resource:
        description: The resource URL for the application registered in Azure Active Directory. Usually should not be changed from the default.
        required: False
        type: str
        default: https://management.azure.com/
        version_added: '3.2.0'
      cert_auth_public_key:
        description: For C(cert) auth, path to the certificate file to authenticate with, in PEM format.
        type: path
        version_added: 1.4.0
      cert_auth_private_key:
        description: For C(cert) auth, path to the private key file to authenticate with, in PEM format.
        type: path
        version_added: 1.4.0
    '''

    PLUGINS = r'''
    options:
      auth_method:
        env:
          - name: ANSIBLE_HASHI_VAULT_AUTH_METHOD
            version_added: 0.2.0
        ini:
          - section: hashi_vault_collection
            key: auth_method
            version_added: 1.4.0
        vars:
          - name: ansible_hashi_vault_auth_method
            version_added: 1.2.0
      mount_point:
        env:
          - name: ANSIBLE_HASHI_VAULT_MOUNT_POINT
            version_added: 1.5.0
        ini:
          - section: hashi_vault_collection
            key: mount_point
            version_added: 1.5.0
        vars:
          - name: ansible_hashi_vault_mount_point
            version_added: 1.5.0
      token:
        env:
          - name: ANSIBLE_HASHI_VAULT_TOKEN
            version_added: 0.2.0
        vars:
          - name: ansible_hashi_vault_token
            version_added: 1.2.0
      token_path:
        env:
          - name: ANSIBLE_HASHI_VAULT_TOKEN_PATH
            version_added: 0.2.0
        ini:
          - section: hashi_vault_collection
            key: token_path
            version_added: 1.4.0
        vars:
          - name: ansible_hashi_vault_token_path
            version_added: 1.2.0
      token_file:
        env:
          - name: ANSIBLE_HASHI_VAULT_TOKEN_FILE
            version_added: 0.2.0
        ini:
          - section: hashi_vault_collection
            key: token_file
            version_added: 1.4.0
        vars:
          - name: ansible_hashi_vault_token_file
            version_added: 1.2.0
      token_validate:
        env:
          - name: ANSIBLE_HASHI_VAULT_TOKEN_VALIDATE
        ini:
          - section: hashi_vault_collection
            key: token_validate
            version_added: 1.4.0
        vars:
          - name: ansible_hashi_vault_token_validate
            version_added: 1.2.0
      username:
        env:
          - name: ANSIBLE_HASHI_VAULT_USERNAME
            version_added: '1.2.0'
        vars:
          - name: ansible_hashi_vault_username
            version_added: '1.2.0'
      password:
        env:
          - name: ANSIBLE_HASHI_VAULT_PASSWORD
            version_added: '1.2.0'
        vars:
          - name: ansible_hashi_vault_password
            version_added: '1.2.0'
      role_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_ROLE_ID
            version_added: 0.2.0
        ini:
          - section: hashi_vault_collection
            key: role_id
            version_added: 1.4.0
        vars:
          - name: ansible_hashi_vault_role_id
            version_added: 1.2.0
      secret_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_SECRET_ID
            version_added: 0.2.0
        vars:
          - name: ansible_hashi_vault_secret_id
            version_added: 1.2.0
      jwt:
        env:
          - name: ANSIBLE_HASHI_VAULT_JWT
      aws_profile:
        env:
          - name: AWS_DEFAULT_PROFILE
          - name: AWS_PROFILE
      aws_access_key:
        env:
          - name: EC2_ACCESS_KEY
          - name: AWS_ACCESS_KEY
          - name: AWS_ACCESS_KEY_ID
      aws_secret_key:
        env:
          - name: EC2_SECRET_KEY
          - name: AWS_SECRET_KEY
          - name: AWS_SECRET_ACCESS_KEY
      aws_security_token:
        env:
          - name: EC2_SECURITY_TOKEN
          - name: AWS_SESSION_TOKEN
          - name: AWS_SECURITY_TOKEN
      region:
        env:
          - name: EC2_REGION
          - name: AWS_REGION
      aws_iam_server_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_AWS_IAM_SERVER_ID
        ini:
          - section: hashi_vault_collection
            key: aws_iam_server_id
            version_added: 1.4.0
      azure_tenant_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_AZURE_TENANT_ID
        ini:
          - section: hashi_vault_collection
            key: azure_tenant_id
        vars:
          - name: ansible_hashi_vault_azure_tenant_id
      azure_client_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_AZURE_CLIENT_ID
        ini:
          - section: hashi_vault_collection
            key: azure_client_id
        vars:
          - name: ansible_hashi_vault_azure_client_id
      azure_client_secret:
        env:
          - name: ANSIBLE_HASHI_VAULT_AZURE_CLIENT_SECRET
        vars:
          - name: ansible_hashi_vault_azure_client_secret
      azure_resource:
        env:
          - name: ANSIBLE_HASHI_VAULT_AZURE_RESOURCE
        ini:
          - section: hashi_vault_collection
            key: azure_resource
        vars:
          - name: ansible_hashi_vault_azure_resource
      cert_auth_public_key:
        env:
          - name: ANSIBLE_HASHI_VAULT_CERT_AUTH_PUBLIC_KEY
        vars:
          - name: ansible_hashi_vault_cert_auth_public_key
            version_added: 6.2.0
        ini:
          - section: hashi_vault_collection
            key: cert_auth_public_key
      cert_auth_private_key:
        env:
          - name: ANSIBLE_HASHI_VAULT_CERT_AUTH_PRIVATE_KEY
        vars:
          - name: ansible_hashi_vault_cert_auth_private_key
            version_added: 6.2.0
        ini:
          - section: hashi_vault_collection
            key: cert_auth_private_key
    '''
