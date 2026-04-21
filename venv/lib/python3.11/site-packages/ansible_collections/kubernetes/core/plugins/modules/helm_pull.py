#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: helm_pull
short_description: download a chart from a repository and (optionally) unpack it in local directory.
version_added: 2.4.0
author:
  - Aubin Bikouo (@abikouo)
description:
  - Retrieve a package from a package repository, and download it locally.
  - It can also be used to perform cryptographic verification of a chart without installing the chart.
  - There are options for unpacking the chart after download.

requirements:
  - "helm >= 3.0 (https://github.com/helm/helm/releases)"

options:
  chart_ref:
    description:
      - chart name on chart repository.
      - absolute URL.
    required: true
    type: str
  chart_version:
    description:
      - Specify a version constraint for the chart version to use.
      - This constraint can be a specific tag (e.g. 1.1.1) or it may reference a valid range (e.g. ^2.0.0).
      - Mutually exclusive with C(chart_devel).
    type: str
  verify_chart:
    description:
      - Verify the package before using it.
    default: False
    type: bool
  verify_chart_keyring:
    description:
      - location of public keys used for verification.
    type: path
  provenance:
    description:
      - Fetch the provenance file, but don't perform verification.
    type: bool
    default: False
  repo_url:
    description:
      - chart repository url where to locate the requested chart.
    type: str
    aliases: [ url, chart_repo_url ]
  repo_username:
    description:
      - Chart repository username where to locate the requested chart.
      - Required if C(repo_password) is specified.
    type: str
    aliases: [ username, chart_repo_username ]
  repo_password:
    description:
      - Chart repository password where to locate the requested chart.
      - Required if C(repo_username) is specified.
    type: str
    aliases: [ password, chart_repo_password ]
  pass_credentials:
    description:
      - Pass credentials to all domains.
    default: False
    type: bool
  skip_tls_certs_check:
    description:
    - Whether or not to check tls certificate for the chart download.
    - Requires helm >= 3.3.0. Alias C(insecure_skip_tls_verify) added in 5.3.0.
    type: bool
    default: False
    aliases: [ insecure_skip_tls_verify ]
  chart_devel:
    description:
    - Use development versions, too. Equivalent to version '>0.0.0-0'.
    - Mutually exclusive with C(chart_version).
    type: bool
  untar_chart:
    description:
    - if set to true, will untar the chart after downloading it.
    type: bool
    default: False
  destination:
    description:
    - location to write the chart.
    type: path
    required: True
  chart_ca_cert:
    description:
    - Verify certificates of HTTPS-enabled servers using this CA bundle.
    - Requires helm >= 3.1.0.
    type: path
  chart_ssl_cert_file:
    description:
    - Identify HTTPS client using this SSL certificate file.
    - Requires helm >= 3.1.0.
    type: path
  chart_ssl_key_file:
    description:
    - Identify HTTPS client using this SSL key file
    - Requires helm >= 3.1.0.
    type: path
  binary_path:
    description:
      - The path of a helm binary to use.
    required: false
    type: path
  plain_http:
    description:
      - Use HTTP instead of HTTPS when working with OCI registries
      - Requires Helm >= 3.13.0
    type: bool
    default: False
    version_added: 6.1.0
"""

EXAMPLES = r"""
- name: Download chart using chart url
  kubernetes.core.helm_pull:
    chart_ref: https://github.com/grafana/helm-charts/releases/download/grafana-5.6.0/grafana-5.6.0.tgz
    destination: /path/to/chart

- name: Download Chart using chart_name and repo_url
  kubernetes.core.helm_pull:
    chart_ref: redis
    repo_url: https://charts.bitnami.com/bitnami
    untar_chart: yes
    destination: /path/to/chart

- name: Download Chart (skip tls certificate check)
  kubernetes.core.helm_pull:
    chart_ref: redis
    repo_url: https://charts.bitnami.com/bitnami
    untar_chart: yes
    destination: /path/to/chart
    skip_tls_certs_check: yes

- name: Download Chart using chart registry credentials
  kubernetes.core.helm_pull:
    chart_ref: redis
    repo_url: https://charts.bitnami.com/bitnami
    untar_chart: yes
    destination: /path/to/chart
    username: myuser
    password: mypassword123
"""

RETURN = r"""
stdout:
  type: str
  description: Full `helm pull` command stdout, in case you want to display it or examine the event log
  returned: always
  sample: ''
stderr:
  type: str
  description: Full `helm pull` command stderr, in case you want to display it or examine the event log
  returned: always
  sample: ''
command:
  type: str
  description: Full `helm pull` command built by this module, in case you want to re-run the command outside the module or debug a problem.
  returned: always
  sample: helm pull --repo test ...
rc:
  type: int
  description: Helm pull command return code
  returned: always
  sample: 1
"""

from ansible_collections.kubernetes.core.plugins.module_utils.helm import (
    AnsibleHelmModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.version import (
    LooseVersion,
)


def main():
    argspec = dict(
        chart_ref=dict(type="str", required=True),
        chart_version=dict(type="str"),
        verify_chart=dict(type="bool", default=False),
        verify_chart_keyring=dict(type="path"),
        provenance=dict(type="bool", default=False),
        repo_url=dict(type="str", aliases=["url", "chart_repo_url"]),
        repo_username=dict(type="str", aliases=["username", "chart_repo_username"]),
        repo_password=dict(
            type="str", no_log=True, aliases=["password", "chart_repo_password"]
        ),
        pass_credentials=dict(type="bool", default=False, no_log=False),
        skip_tls_certs_check=dict(
            type="bool", default=False, aliases=["insecure_skip_tls_verify"]
        ),
        chart_devel=dict(type="bool"),
        untar_chart=dict(type="bool", default=False),
        destination=dict(type="path", required=True),
        chart_ca_cert=dict(type="path"),
        chart_ssl_cert_file=dict(type="path"),
        chart_ssl_key_file=dict(type="path"),
        binary_path=dict(type="path"),
        plain_http=dict(type="bool", default=False),
    )
    module = AnsibleHelmModule(
        argument_spec=argspec,
        supports_check_mode=True,
        required_by=dict(
            repo_username=("repo_password"),
            repo_password=("repo_username"),
        ),
        mutually_exclusive=[("chart_version", "chart_devel")],
    )

    helm_version = module.get_helm_version()
    if LooseVersion(helm_version) < LooseVersion("3.0.0"):
        module.fail_json(
            msg="This module requires helm >= 3.0.0, current version is {0}".format(
                helm_version
            )
        )

    helm_pull_opt_versionning = dict(
        skip_tls_certs_check="3.3.0",
        chart_ca_cert="3.1.0",
        chart_ssl_cert_file="3.1.0",
        chart_ssl_key_file="3.1.0",
        plain_http="3.13.0",
    )

    def test_version_requirement(opt):
        req_version = helm_pull_opt_versionning.get(opt)
        if req_version and LooseVersion(helm_version) < LooseVersion(req_version):
            module.fail_json(
                msg="Parameter {0} requires helm >= {1}, current version is {2}".format(
                    opt, req_version, helm_version
                )
            )

    # Set `helm pull` arguments requiring values
    helm_pull_opts = []

    helm_value_args = dict(
        chart_version="version",
        verify_chart_keyring="keyring",
        repo_url="repo",
        repo_username="username",
        repo_password="password",
        destination="destination",
        chart_ca_cert="ca-file",
        chart_ssl_cert_file="cert-file",
        chart_ssl_key_file="key-file",
    )

    for opt, cmdkey in helm_value_args.items():
        if module.params.get(opt):
            test_version_requirement(opt)
            helm_pull_opts.append("--{0} {1}".format(cmdkey, module.params.get(opt)))

    # Set `helm pull` arguments flags
    helm_flag_args = dict(
        verify_chart=dict(key="verify"),
        provenance=dict(key="prov"),
        pass_credentials=dict(key="pass-credentials"),
        skip_tls_certs_check=dict(key="insecure-skip-tls-verify"),
        chart_devel=dict(key="devel"),
        untar_chart=dict(key="untar"),
        plain_http=dict(key="plain-http"),
    )

    for k, v in helm_flag_args.items():
        if module.params.get(k):
            test_version_requirement(k)
            helm_pull_opts.append("--{0}".format(v["key"]))

    helm_cmd_common = "{0} pull {1} {2}".format(
        module.get_helm_binary(),
        module.params.get("chart_ref"),
        " ".join(helm_pull_opts),
    )
    if not module.check_mode:
        rc, out, err = module.run_helm_command(helm_cmd_common, fails_on_error=False)
    else:
        rc, out, err = (0, "", "")

    if rc == 0:
        module.exit_json(
            failed=False,
            changed=True,
            command=helm_cmd_common,
            stdout=out,
            stderr=err,
            rc=rc,
        )
    else:
        module.fail_json(
            msg="Failure when executing Helm command.",
            command=helm_cmd_common,
            changed=False,
            stdout=out,
            stderr=err,
            rc=rc,
        )


if __name__ == "__main__":
    main()
