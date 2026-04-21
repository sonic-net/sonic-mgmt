# -*- coding: utf-8 -*-

# Copyright: (c) 2018-2022, Sumit Kumar <sumit4@netapp.com>, chris Archibald <carchi@netapp.com>
# Copyright (c) 2018-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  - See respective platform section for more details
requirements:
  - See respective platform section for more details
notes:
  - Ansible modules are available for the following NetApp Storage Platforms: E-Series, ONTAP, SolidFire
'''
    # Documentation fragment for ONTAP (na_ontap) that contains REST
    NA_ONTAP = r'''
options:
  hostname:
      description:
        - The hostname or IP address of the ONTAP instance.
      type: str
      required: true
  username:
      description:
        - This can be a Cluster-scoped or SVM-scoped account, depending on whether a Cluster-level or SVM-level API is required.
        - For more information, please read the documentation U(https://docs.netapp.com/us-en/ontap/authentication/create-svm-user-accounts-task.html).
        - Two authentication methods are supported
        - 1. Basic authentication, using username and password.
        - 2. SSL certificate authentication, using a ssl client cert file, and optionally a private key file.
        - To use a certificate, the certificate must have been installed in the ONTAP cluster, and cert authentication must have been enabled.
      type: str
      aliases: [ user ]
  password:
      description:
        - Password for the specified user.
      type: str
      aliases: [ pass ]
  cert_filepath:
      description:
        - path to SSL client cert file (.pem).
        - not supported with python 2.6.
      type: str
      version_added: 20.6.0
  key_filepath:
      description:
        - path to SSL client key file.
      type: str
      version_added: 20.6.0
  https:
      description:
        - Enable and disable https.
        - Ignored when using REST as only https is supported.
        - Ignored when using SSL certificate authentication as it requires SSL.
      type: bool
      default: no
  validate_certs:
      description:
        - If set to C(no), the SSL certificates will not be validated.
        - This should only set to C(False) used on personally controlled sites using self-signed certificates.
      type: bool
      default: yes
  http_port:
      description:
      - Override the default port (80 or 443) with this port
      type: int
  ontapi:
      description:
      - The ontap api version to use
      type: int
  use_rest:
      description:
        - Whether to use REST or ZAPI.
        - always -- will always use the REST API if the module supports REST.
          A warning is issued if the module does not support REST.
          An error is issued if a module option is not supported in REST.
        - never -- will always use ZAPI if the module supports ZAPI.  An error may be issued if a REST option is not supported in ZAPI.
        - auto -- will try to use the REST API if the module supports REST and modules options are supported.  Reverts to ZAPI otherwise.
      default: always
      type: str
  feature_flags:
      description:
        - Enable or disable a new feature.
        - This can be used to enable an experimental feature or disable a new feature that breaks backward compatibility.
        - Supported keys and values are subject to change without notice.  Unknown keys are ignored.
      type: dict
      version_added: "20.5.0"
  force_ontap_version:
      description:
        - Override the cluster ONTAP version when using REST.
        - The behavior is undefined if the version does not match the target cluster.
        - This is provided as a work-around when the cluster version cannot be read because of permission issues.
          See https://github.com/ansible-collections/netapp.ontap/wiki/Known-issues.
        - This should be in the form 9.10 or 9.10.1 with each element being an integer number.
        - When C(use_rest) is set to auto, this may force a switch to ZAPI based on the version and platform capabilities.
        - Ignored with ZAPI.
      type: str
      version_added: "21.23.0"
  use_lambda:
      description:
        - Specifies if AWS Lambda proxy functionality should be used to connect to the ONTAP system.
        - Supported only with REST.
      type: bool
      default: false
      version_added: "23.2.0"
requirements:
  - Ansible 2.9 or later - 2.12 or later is recommended.
  - Python3 - 3.9 or later is recommended.
  - netapp-lib only when using ZAPI (install using 'pip install netapp-lib'),
    Please note that netapp-lib is deprecated and no longer maintained. Proceed at your own risk.
  - A physical or virtual clustered Data ONTAP system, the modules support Data ONTAP 9.1 and onward,
    REST support requires ONTAP 9.6 or later.

notes:
  - The modules prefixed with na_ontap are built to support the ONTAP storage platform.
  - https is enabled by default and recommended.
    To enable http on the cluster you must run the following commands 'set -privilege advanced;' 'system services web modify -http-enabled true;'
    '''

    # Documentation fragment for ONTAP (na_ontap) that are ZAPI ONLY
    NA_ONTAP_ZAPI = r'''
options:
  hostname:
      description:
        - The hostname or IP address of the ONTAP instance.
      type: str
      required: true
  username:
      description:
        - This can be a Cluster-scoped or SVM-scoped account, depending on whether a Cluster-level or SVM-level API is required.
        - For more information, please read the documentation U(https://docs.netapp.com/us-en/ontap/authentication/create-svm-user-accounts-task.html).
        - Two authentication methods are supported
        - 1. Basic authentication, using username and password.
        - 2. SSL certificate authentication, using a ssl client cert file, and optionally a private key file.
        - To use a certificate, the certificate must have been installed in the ONTAP cluster, and cert authentication must have been enabled.
      type: str
      aliases: [ user ]
  password:
      description:
        - Password for the specified user.
      type: str
      aliases: [ pass ]
  cert_filepath:
      description:
        - path to SSL client cert file (.pem).
        - not supported with python 2.6.
      type: str
      version_added: 20.6.0
  key_filepath:
      description:
        - path to SSL client key file.
      type: str
      version_added: 20.6.0
  https:
      description:
        - Enable and disable https.
        - Ignored when using REST as only https is supported.
        - Ignored when using SSL certificate authentication as it requires SSL.
      type: bool
      default: no
  validate_certs:
      description:
        - If set to C(no), the SSL certificates will not be validated.
        - This should only set to C(False) used on personally controlled sites using self-signed certificates.
      type: bool
      default: yes
  http_port:
      description:
      - Override the default port (80 or 443) with this port
      type: int
  ontapi:
      description:
      - The ontap api version to use
      type: int
  use_rest:
      description:
        - This module only supports ZAPI and can not be swtiched to REST.
        - never -- will always use ZAPI if the module supports ZAPI.  An error may be issued if a REST option is not supported in ZAPI.
        - auto -- will always use ZAPI.
      default: never
      type: str
  feature_flags:
      description:
        - Enable or disable a new feature.
        - This can be used to enable an experimental feature or disable a new feature that breaks backward compatibility.
        - Supported keys and values are subject to change without notice.  Unknown keys are ignored.
      type: dict
      version_added: "20.5.0"
requirements:
  - Ansible 2.9 or later - 2.12 or later is recommended.
  - Python3 - 3.9 or later is recommended.
  - netapp-lib only when using ZAPI (install using 'pip install netapp-lib'),
    Please note that netapp-lib is deprecated and no longer maintained. Proceed at your own risk.
  - A physical or virtual clustered Data ONTAP system, the modules support Data ONTAP 9.1 and onward,
    REST support requires ONTAP 9.6 or later.

notes:
  - The modules prefixed with na_ontap are built to support the ONTAP storage platform.
  - https is enabled by default and recommended.
    To enable http on the cluster you must run the following commands 'set -privilege advanced;' 'system services web modify -http-enabled true;'
    '''

# Documentation fragment for ONTAP (na_ontap) that are REST ONLY
    NA_ONTAP_REST = r'''
options:
  hostname:
      description:
        - The hostname or IP address of the ONTAP instance.
      type: str
      required: true
  username:
      description:
        - This can be a Cluster-scoped or SVM-scoped account, depending on whether a Cluster-level or SVM-level API is required.
        - For more information, please read the documentation U(https://docs.netapp.com/us-en/ontap/authentication/create-svm-user-accounts-task.html).
        - Two authentication methods are supported
        - 1. Basic authentication, using username and password.
        - 2. SSL certificate authentication, using a ssl client cert file, and optionally a private key file.
        - To use a certificate, the certificate must have been installed in the ONTAP cluster, and cert authentication must have been enabled.
      type: str
      aliases: [ user ]
  password:
      description:
        - Password for the specified user.
      type: str
      aliases: [ pass ]
  cert_filepath:
      description:
        - path to SSL client cert file (.pem).
        - not supported with python 2.6.
      type: str
      version_added: 20.6.0
  key_filepath:
      description:
        - path to SSL client key file.
      type: str
      version_added: 20.6.0
  https:
      description:
        - Enable and disable https.
        - Ignored when using REST as only https is supported.
        - Ignored when using SSL certificate authentication as it requires SSL.
      type: bool
      default: no
  validate_certs:
      description:
        - If set to C(no), the SSL certificates will not be validated.
        - This should only set to C(False) used on personally controlled sites using self-signed certificates.
      type: bool
      default: yes
  http_port:
      description:
      - Override the default port (80 or 443) with this port
      type: int
  use_rest:
      description:
        - This module only supports REST.
        - always -- will always use the REST API.
          A warning is issued if the module does not support REST.
      default: always
      type: str
  feature_flags:
      description:
        - Enable or disable a new feature.
        - This can be used to enable an experimental feature or disable a new feature that breaks backward compatibility.
        - Supported keys and values are subject to change without notice.  Unknown keys are ignored.
      type: dict
      version_added: "20.5.0"
  force_ontap_version:
      description:
        - Override the cluster ONTAP version when using REST.
        - The behavior is undefined if the version does not match the target cluster.
        - This is provided as a work-around when the cluster version cannot be read because of permission issues.
          See https://github.com/ansible-collections/netapp.ontap/wiki/Known-issues.
        - This should be in the form 9.10 or 9.10.1 with each element being an integer number.
      type: str
      version_added: "21.23.0"
requirements:
  - Ansible 2.9 or later - 2.12 or later is recommended.
  - Python3 - 3.9 or later is recommended.
  - netapp-lib only when using ZAPI (install using 'pip install netapp-lib'),
    Please note that netapp-lib is deprecated and no longer maintained. Proceed at your own risk.
  - A physical or virtual clustered Data ONTAP system, the modules support Data ONTAP 9.1 and onward,
    REST support requires ONTAP 9.6 or later.

notes:
  - The modules prefixed with na_ontap are built to support the ONTAP storage platform.
  - https is enabled by default and recommended.
    To enable http on the cluster you must run the following commands 'set -privilege advanced;' 'system services web modify -http-enabled true;'
    '''

    # Documentation fragment for ONTAP (na_ontap) peer options
    NA_ONTAP_PEER = r'''
options:
  peer_options:
    version_added: 21.8.0
    description:
      - IP address and connection options for the peer system.
      - If any if these options is not specified, the corresponding source option is used.
    type: dict
    suboptions:
      hostname:
        description:
          - The hostname or IP address of the ONTAP instance.
        type: str
        required: true
      username:
        description:
          - Username when using basic authentication.
        type: str
        aliases: [ user ]
      password:
        description:
          - Password for the specified user.
        type: str
        aliases: [ pass ]
      cert_filepath:
        description:
          - path to SSL client cert file (.pem).
        type: str
      key_filepath:
        description:
          - path to SSL client key file.
        type: str
      https:
        description:
          - Enable and disable https.
        type: bool
      validate_certs:
        description:
          - If set to C(no), the SSL certificates will not be validated.
          - This should only set to C(False) used on personally controlled sites using self-signed certificates.
        type: bool
      http_port:
        description:
          - Override the default port (80 or 443) with this port
        type: int
      ontapi:
        description:
          - The ontap api version to use
        type: int
      use_rest:
        description:
          - REST API if supported by the target system for all the resources and attributes the module requires. Otherwise will revert to ZAPI.
          - always -- will always use the REST API
          - never -- will always use the ZAPI
          - auto -- will try to use the REST Api
        type: str
      force_ontap_version:
          description:
            - Override the cluster ONTAP version when using REST.
            - The behavior is undefined if the version does not match the target cluster.
            - This is provided as a work-around when the cluster version cannot be read because of permission issues.
              See https://github.com/ansible-collections/netapp.ontap/wiki/Known-issues.
            - This should be in the form 9.10 or 9.10.1 with each element being an integer number.
            - When C(use_rest) is set to auto, this may force a switch to ZAPI based on the version and platform capabilities.
            - Ignored with ZAPI.
          type: str
          version_added: "21.23.0"
'''
