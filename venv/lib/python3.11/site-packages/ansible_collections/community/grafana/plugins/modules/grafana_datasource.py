#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Thierry Sallé (@seuf)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: grafana_datasource
author:
- Thierry Sallé (@seuf)
- Martin Wang (@martinwangjian)
- Rémi REY (@rrey)
short_description: Manage Grafana datasources
description:
- Create/update/delete Grafana datasources via API.
options:
  name:
    description:
    - The name of the datasource.
    required: true
    type: str
  uid:
    description:
    - The uid of the datasource.
    required: false
    type: str
  ds_type:
    description:
    - The type of the datasource.
    - Required when C(state=present).
    choices:
    - graphite
    - prometheus
    - elasticsearch
    - influxdb
    - opentsdb
    - mysql
    - postgres
    - cloudwatch
    - alexanderzobnin-zabbix-datasource
    - grafana-azure-monitor-datasource
    - sni-thruk-datasource
    - camptocamp-prometheus-alertmanager-datasource
    - loki
    - redis-datasource
    - tempo
    - quickwit-quickwit-datasource
    - alertmanager
    type: str
  ds_url:
    description:
    - The URL of the datasource.
    - Required when C(state=present).
    type: str
  access:
    description:
    - The access mode for this datasource.
    choices:
    - direct
    - proxy
    default: proxy
    type: str
  database:
    description:
    - Name of the database for the datasource.
    - This options is required when the C(ds_type) is C(influxdb), C(elasticsearch)
      (index name), C(mysql) or C(postgres).
    required: false
    type: str
    default: ''
  user:
    description:
    - The datasource login user for influxdb datasources.
    type: str
    default: ''
  password:
    description:
    - The datasource password.
    - Stored as secure data, see C(enforce_secure_data) and notes!
    type: str
    default: ''
  basic_auth_user:
    description:
    - The datasource basic auth user.
    - Setting this option with basic_auth_password will enable basic auth.
    type: str
  basic_auth_password:
    description:
    - The datasource basic auth password, when C(basic auth) is C(true).
    - Stored as secure data, see C(enforce_secure_data) and notes!
    type: str
  with_credentials:
    description:
    - Whether credentials such as cookies or auth headers should be sent with cross-site
      requests.
    type: bool
    default: false
  tls_servername:
    description:
    - A Servername is used to verify the hostname on the returned certificate
    type: str
  tls_client_cert:
    description:
    - The client TLS certificate.
    - If C(tls_client_cert) and C(tls_client_key) are set, this will enable TLS authentication.
    - Starts with ----- BEGIN CERTIFICATE -----
    - Stored as secure data, see C(enforce_secure_data) and notes!
    type: str
  tls_client_key:
    description:
    - The client TLS private key
    - Starts with ----- BEGIN RSA PRIVATE KEY -----
    - Stored as secure data, see C(enforce_secure_data) and notes!
    type: str
  tls_ca_cert:
    description:
    - The TLS CA certificate for self signed certificates.
    - Only used when C(tls_client_cert) and C(tls_client_key) are set.
    - Stored as secure data, see C(enforce_secure_data) and notes!
    type: str
  tls_skip_verify:
    description:
    - Skip the TLS datasource certificate verification.
    type: bool
    default: false
  is_default:
    description:
    - Make this datasource the default one.
    type: bool
    default: false
  org_id:
    description:
    - Grafana organization ID in which the datasource should be created.
    - Not used when C(grafana_api_key) is set, because the C(grafana_api_key) only
      belongs to one organization.
    - Mutually exclusive with C(org_name).
    default: 1
    type: int
  org_name:
    description:
    - Grafana organization name in which the datasource should be created.
    - Not used when C(grafana_api_key) is set, because the C(grafana_api_key) only
      belongs to one organization.
    - Mutually exclusive with C(org_id).
    type: str
  state:
    description:
    - Status of the datasource
    choices:
    - absent
    - present
    default: present
    type: str
  es_version:
    description:
    - Elasticsearch version (for C(ds_type = elasticsearch) only)
    - Version 56 is for elasticsearch 5.6+ where you can specify the C(max_concurrent_shard_requests)
      option.
    choices:
    - "2"
    - "5"
    - "56"
    - "60"
    - "70"
    - "7.7+"
    - "7.10+"
    - "8.0+"
    default: "7.10+"
    type: str
  max_concurrent_shard_requests:
    description:
    - Starting with elasticsearch 5.6, you can specify the max concurrent shard per
      requests.
    default: 256
    type: int
  time_field:
    description:
    - Name of the time field in elasticsearch ds.
    - For example C(@timestamp).
    type: str
    default: '@timestamp'
  time_interval:
    description:
    - Minimum group by interval for C(influxdb), C(elasticsearch) or C(prometheus) datasources.
    - for example C(>10s).
    type: str
  interval:
    description:
    - For elasticsearch C(ds_type), this is the index pattern used.
    choices:
    - ''
    - Hourly
    - Daily
    - Weekly
    - Monthly
    - Yearly
    type: str
    default: ''
  tsdb_version:
    description:
    - The opentsdb version.
    - Use C(1) for <=2.1, C(2) for ==2.2, C(3) for ==2.3.
    choices:
    - 1
    - 2
    - 3
    default: 1
    type: int
  tsdb_resolution:
    description:
    - The opentsdb time resolution.
    choices:
    - millisecond
    - second
    default: second
    type: str
  sslmode:
    description:
    - SSL mode for C(postgres) datasource type.
    choices:
    - disable
    - require
    - verify-ca
    - verify-full
    type: str
    default: disable
  trends:
    required: false
    description:
    - Use trends or not for zabbix datasource type.
    type: bool
    default: false
  alertmanager_implementation:
    description:
    - The implementation to set for the alertmanager datasource type.
    choices:
    - mimir
    - cortex
    - prometheus
    type: str
  alertmanager_handle_grafana_alerts:
    description:
    - Whether Grafana should send alerts to this alertmanager.
    type: bool
    default: false
  aws_auth_type:
    description:
    - Type for AWS authentication for CloudWatch datasource type (authType of grafana
      api)
    default: keys
    choices:
    - keys
    - credentials
    - arn
    - default
    type: str
  aws_default_region:
    description:
    - AWS default region for CloudWatch datasource type
    default: us-east-1
    type: str
    choices:
    - ap-northeast-1
    - ap-northeast-2
    - ap-southeast-1
    - ap-southeast-2
    - ap-south-1
    - ca-central-1
    - cn-north-1
    - cn-northwest-1
    - eu-central-1
    - eu-west-1
    - eu-west-2
    - eu-west-3
    - sa-east-1
    - us-east-1
    - us-east-2
    - us-gov-west-1
    - us-west-1
    - us-west-2
  aws_credentials_profile:
    description:
    - Profile for AWS credentials for CloudWatch datasource type when C(aws_auth_type)
      is C(credentials)
    default: ''
    required: false
    type: str
  aws_access_key:
    description:
    - AWS access key for CloudWatch datasource type when C(aws_auth_type) is C(keys)
    - Stored as secure data, see C(enforce_secure_data) and notes!
    default: ''
    required: false
    type: str
  aws_secret_key:
    description:
    - AWS secret key for CloudWatch datasource type when C(aws_auth_type) is C(keys)
    - Stored as secure data, see C(enforce_secure_data) and notes!
    default: ''
    required: false
    type: str
  aws_assume_role_arn:
    description:
    - AWS IAM role arn to assume for CloudWatch datasource type when C(aws_auth_type)
      is C(arn)
    default: ''
    required: false
    type: str
  aws_custom_metrics_namespaces:
    description:
    - Namespaces of Custom Metrics for CloudWatch datasource type
    required: false
    type: str
  azure_cloud:
    description:
    - The national cloud for your Azure account
    default: 'azuremonitor'
    required: false
    type: str
    choices:
    - azuremonitor
    - chinaazuremonitor
    - govazuremonitor
    - germanyazuremonitor
  azure_tenant:
    description:
    - The directory/tenant ID for the Azure AD app registration to use for authentication
    required: false
    type: str
  azure_client:
    description:
    - The application/client ID for the Azure AD app registration to use for authentication.
    required: false
    type: str
  azure_secret:
    description:
    - The application client secret for the Azure AD app registration to use for auth
    required: false
    type: str
  zabbix_user:
    description:
    - User for Zabbix API
    required: false
    type: str
  zabbix_password:
    description:
    - Password for Zabbix API
    required: false
    type: str
  additional_json_data:
    description:
    - Defined data is used for datasource jsonData
    - Data may be overridden by specifically defined parameters (like zabbix_user)
    required: false
    type: dict
    default: {}
  additional_secure_json_data:
    description:
    - Defined data is used for datasource secureJsonData
    - Data may be overridden by specifically defined parameters (like tls_client_cert)
    - Stored as secure data, see C(enforce_secure_data) and notes!
    required: false
    type: dict
    default: {}
  enforce_secure_data:
    description:
    - Secure data is not updated per default (see notes!)
    - To update secure data you have to enable this option!
    - Enabling this, the task will always report changed=True
    required: false
    type: bool
    default: false
extends_documentation_fragment:
- community.grafana.basic_auth
- community.grafana.api_key
notes:
- Secure data will get encrypted by the Grafana API, thus it can not be compared on subsequent runs. To workaround this, secure
  data will not be updated after initial creation! To force the secure data update you have to set I(enforce_secure_data=True).
- Hint, with the C(enforce_secure_data) always reporting changed=True, you might just do one Task updating the datasource without
  any secure data and make a separate playbook/task also changing the secure data. This way it will not break any workflow.
"""

EXAMPLES = """
---
- name: Create elasticsearch datasource
  community.grafana.grafana_datasource:
    name: "datasource-elastic"
    grafana_url: "https://grafana.company.com"
    grafana_user: "admin"
    grafana_password: "xxxxxx"
    org_id: "1"
    ds_type: "elasticsearch"
    ds_url: "https://elastic.company.com:9200"
    database: "[logstash_]YYYY.MM.DD"
    basic_auth_user: "grafana"
    basic_auth_password: "******"
    time_field: "@timestamp"
    time_interval: "1m"
    interval: "Daily"
    es_version: 56
    max_concurrent_shard_requests: 42
    tls_ca_cert: "/etc/ssl/certs/ca.pem"

- name: Create influxdb datasource
  community.grafana.grafana_datasource:
    name: "datasource-influxdb"
    grafana_url: "https://grafana.company.com"
    grafana_user: "admin"
    grafana_password: "xxxxxx"
    org_id: "1"
    ds_type: "influxdb"
    ds_url: "https://influx.company.com:8086"
    database: "telegraf"
    time_interval: ">10s"
    tls_ca_cert: "/etc/ssl/certs/ca.pem"

- name: Create influxdbv2 datasource using fluxql
  community.grafana.grafana_datasource:
    name: "datasource-influxdb-flux"
    grafana_url: "https://grafana.company.com"
    grafana_user: "admin"
    grafana_password: "xxxxxx"
    org_id: "1"
    ds_type: "influxdb"
    ds_url: "https://influx.company.com:8086"
    additional_json_data:
      version: "Flux"
      organization: "organization"
      defaultBucket: "bucket"
      tlsSkipVerify: false
    additional_secure_json_data:
      token: "token"

- name: Create postgres datasource
  community.grafana.grafana_datasource:
    name: "datasource-postgres"
    grafana_url: "https://grafana.company.com"
    grafana_user: "admin"
    grafana_password: "xxxxxx"
    org_id: "1"
    ds_type: "postgres"
    ds_url: "postgres.company.com:5432"
    database: "db"
    user: "postgres"
    sslmode: "verify-full"
    additional_json_data:
      postgresVersion: 12
      timescaledb: false
    additional_secure_json_data:
      password: "iampgroot"

- name: Create cloudwatch datasource
  community.grafana.grafana_datasource:
    name: "datasource-cloudwatch"
    grafana_url: "https://grafana.company.com"
    grafana_user: "admin"
    grafana_password: "xxxxxx"
    org_id: "1"
    ds_type: "cloudwatch"
    ds_url: "http://monitoring.us-west-1.amazonaws.com"
    aws_auth_type: "keys"
    aws_default_region: "us-west-1"
    aws_access_key: "speakFriendAndEnter"
    aws_secret_key: "mel10n"
    aws_custom_metrics_namespaces: "n1,n2"

- name: grafana - add thruk datasource
  community.grafana.grafana_datasource:
    name: "datasource-thruk"
    grafana_url: "https://grafana.company.com"
    grafana_user: "admin"
    grafana_password: "xxxxxx"
    org_id: "1"
    ds_type: "sni-thruk-datasource"
    ds_url: "https://thruk.company.com/sitename/thruk"
    basic_auth_user: "thruk-user"
    basic_auth_password: "******"

# handle secure data - workflow example
# this will create/update the datasource but dont update the secure data on updates
# so you can assert if all tasks are changed=False
- name: create prometheus datasource
  community.grafana.grafana_datasource:
    name: openshift_prometheus
    ds_type: prometheus
    ds_url: https://openshift-monitoring.company.com
    access: proxy
    tls_skip_verify: true
    additional_json_data:
      httpHeaderName1: "Authorization"
    additional_secure_json_data:
      httpHeaderValue1: "Bearer ihavenogroot"

# in a separate task or even play you then can force to update
# and assert if each datasource is reporting changed=True
- name: update prometheus datasource
  community.grafana.grafana_datasource:
    name: openshift_prometheus
    ds_type: prometheus
    ds_url: https://openshift-monitoring.company.com
    access: proxy
    tls_skip_verify: true
    additional_json_data:
      httpHeaderName1: "Authorization"
    additional_secure_json_data:
      httpHeaderValue1: "Bearer ihavenogroot"
    enforce_secure_data: true
"""

RETURN = """
---
datasource:
  description: datasource created/updated by module
  returned: changed
  type: dict
  sample: { "access": "proxy",
        "basicAuth": false,
        "database": "test_*",
        "id": 1035,
        "isDefault": false,
        "jsonData": {
            "esVersion": 5,
            "timeField": "@timestamp",
            "timeInterval": "10s",
        },
        "secureJsonFields": {
            "JustASecureTest": true,
        },
        "name": "grafana_datasource_test",
        "orgId": 1,
        "type": "elasticsearch",
        "url": "http://elastic.company.com:9200",
        "user": "",
        "password": "",
        "withCredentials": false }
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.urls import fetch_url, basic_auth_header
from ansible_collections.community.grafana.plugins.module_utils import base


ES_VERSION_MAPPING = {
    "7.7+": "7.7.0",
    "7.10+": "7.10.0",
    "8.0+": "8.0.0",
}


def compare_datasources(new, current, compareSecureData=True):
    if new.get("uid") is None:
        new.pop("uid", None)
        current.pop("uid", None)

    for field in [
        "apiVersion",
        "basicAuthPassword",
        "id",
        "password",
        "readOnly",
        "typeLogoUrl",
        "version",
    ]:
        current.pop(field, None)

    if not current.get("basicAuth", True):
        current.pop("basicAuthUser", None)

    if (
        current.get("type") == "grafana-postgresql-datasource"
        and new.get("type") == "postgres"
    ):
        new.pop("type", None)
        current.pop("type", None)

    # check if secureJsonData should be compared
    if not compareSecureData:
        # if we should ignore it just drop alltogether
        new.pop("secureJsonData", None)
        new.pop("secureJsonFields", None)
        current.pop("secureJsonData", None)
        current.pop("secureJsonFields", None)
    else:
        # handle secureJsonData/secureJsonFields, some current facts:
        # - secureJsonFields is reporting each field set as true
        # - secureJsonFields once set cant be removed (DS has to be deleted)
        if not new.get("secureJsonData"):
            # secureJsonData is not provided so just remove both for comparision
            new.pop("secureJsonData", None)
            current.pop("secureJsonFields", None)
        else:
            # we have some secure data so just "rename" secureJsonFields for comparison as it will change anyhow everytime
            current["secureJsonData"] = current.pop("secureJsonFields")

    return dict(before=current, after=new)


def get_datasource_payload(data, org_id=None):
    payload = {
        "orgId": data["org_id"] if org_id is None else org_id,
        "name": data["name"],
        "uid": data["uid"],
        "type": data["ds_type"],
        "access": data["access"],
        "url": data["ds_url"],
        "database": data["database"],
        "withCredentials": data["with_credentials"],
        "isDefault": data["is_default"],
        "user": data["user"],
        "jsonData": data["additional_json_data"],
        "secureJsonData": data["additional_secure_json_data"],
    }

    json_data = payload["jsonData"]
    secure_json_data = payload["secureJsonData"]

    # define password
    if data.get("password"):
        secure_json_data["password"] = data["password"]

    # define basic auth
    if (
        "basic_auth_user" in data
        and data["basic_auth_user"]
        and "basic_auth_password" in data
        and data["basic_auth_password"]
    ):
        payload["basicAuth"] = True
        payload["basicAuthUser"] = data["basic_auth_user"]
        secure_json_data["basicAuthPassword"] = data["basic_auth_password"]
    else:
        payload["basicAuth"] = False

    # define tls auth
    if data.get("tls_client_cert") and data.get("tls_client_key"):
        json_data["tlsAuth"] = True
        if data.get("tls_ca_cert"):
            secure_json_data["tlsCACert"] = data["tls_ca_cert"]
            json_data["tlsAuthWithCACert"] = True
        json_data["serverName"] = data["tls_servername"]
        secure_json_data["tlsClientCert"] = data["tls_client_cert"]
        secure_json_data["tlsClientKey"] = data["tls_client_key"]
    else:
        json_data["tlsAuth"] = False
        json_data["tlsAuthWithCACert"] = False
        if data.get("tls_ca_cert"):
            json_data["tlsAuthWithCACert"] = True
            secure_json_data["tlsCACert"] = data["tls_ca_cert"]

    if data.get("tls_skip_verify"):
        json_data["tlsSkipVerify"] = True

    # datasource type related parameters
    if data["ds_type"] == "alertmanager":
        json_data["implementation"] = data["alertmanager_implementation"]
        json_data["handleGrafanaManagedAlerts"] = data[
            "alertmanager_handle_grafana_alerts"
        ]

    if data["ds_type"] == "elasticsearch":
        json_data["maxConcurrentShardRequests"] = data["max_concurrent_shard_requests"]
        json_data["timeField"] = data["time_field"]
        if data.get("interval"):
            json_data["interval"] = data["interval"]

        # Handle changes in es_version format in Grafana < 8.x which used to
        # be integers and is now semver format
        try:
            es_version = int(data["es_version"])
            if es_version < 56:
                json_data.pop("maxConcurrentShardRequests")
        except ValueError:
            # Retrieve the Semver format expected by API
            es_version = ES_VERSION_MAPPING.get(data["es_version"])
        json_data["esVersion"] = es_version

    if data["ds_type"] in ["elasticsearch", "influxdb", "prometheus"]:
        if data.get("time_interval"):
            json_data["timeInterval"] = data["time_interval"]

    if data["ds_type"] == "opentsdb":
        json_data["tsdbVersion"] = data["tsdb_version"]
        if data["tsdb_resolution"] == "second":
            json_data["tsdbResolution"] = 1
        else:
            json_data["tsdbResolution"] = 2

    if data["ds_type"] == "postgres":
        json_data["sslmode"] = data["sslmode"]

    if data["ds_type"] == "alexanderzobnin-zabbix-datasource":
        if data.get("trends"):
            json_data["trends"] = True
        json_data["username"] = data["zabbix_user"]
        json_data["password"] = data["zabbix_password"]

    if data["ds_type"] == "grafana-azure-monitor-datasource":
        json_data["tenantId"] = data["azure_tenant"]
        json_data["clientId"] = data["azure_client"]
        json_data["cloudName"] = data["azure_cloud"]
        json_data["clientsecret"] = "clientsecret"
        if data.get("azure_secret"):
            secure_json_data["clientSecret"] = data["azure_secret"]

    if data["ds_type"] == "cloudwatch":
        if data.get("aws_credentials_profile"):
            payload["database"] = data.get("aws_credentials_profile")

        json_data["authType"] = data["aws_auth_type"]
        json_data["defaultRegion"] = data["aws_default_region"]

        if data.get("aws_custom_metrics_namespaces"):
            json_data["customMetricsNamespaces"] = data.get(
                "aws_custom_metrics_namespaces"
            )
        if data.get("aws_assume_role_arn"):
            json_data["assumeRoleArn"] = data.get("aws_assume_role_arn")
        if data.get("aws_access_key") and data.get("aws_secret_key"):
            secure_json_data["accessKey"] = data.get("aws_access_key")
            secure_json_data["secretKey"] = data.get("aws_secret_key")

    payload["jsonData"] = json_data
    payload["secureJsonData"] = secure_json_data
    return payload


class GrafanaInterface(object):
    def __init__(self, module):
        self._module = module
        self.grafana_url = base.clean_url(module.params.get("url"))
        self.org_id = None
        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        if module.params.get("grafana_api_key", None):
            self.headers["Authorization"] = (
                "Bearer %s" % module.params["grafana_api_key"]
            )
        else:
            self.headers["Authorization"] = basic_auth_header(
                module.params["url_username"], module.params["url_password"]
            )
            self.org_id = (
                self.organization_by_name(module.params["org_name"])
                if module.params["org_name"]
                else module.params["org_id"]
            )
            self.switch_organization(self.org_id)
        # }}}

    def _send_request(self, url, data=None, headers=None, method="GET"):
        if data is not None:
            data = json.dumps(data, sort_keys=True)
        if not headers:
            headers = []

        full_url = "{grafana_url}{path}".format(grafana_url=self.grafana_url, path=url)
        resp, info = fetch_url(
            self._module, full_url, data=data, headers=headers, method=method
        )
        status_code = info["status"]
        if status_code == 404:
            return None
        elif status_code == 401:
            self._module.fail_json(
                failed=True,
                msg="Unauthorized to perform action '%s' on '%s'" % (method, full_url),
            )
        elif status_code == 403:
            self._module.fail_json(failed=True, msg="Permission Denied")
        elif status_code == 200:
            return self._module.from_json(resp.read())
        self._module.fail_json(
            failed=True,
            msg="Grafana API answered with HTTP %d for url %s and data %s"
            % (status_code, url, data),
        )

    def switch_organization(self, org_id):
        url = "/api/user/using/%d" % org_id
        self._send_request(url, headers=self.headers, method="POST")

    def organization_by_name(self, org_name):
        url = "/api/user/orgs"
        organizations = self._send_request(url, headers=self.headers, method="GET")
        orga = next((org for org in organizations if org["name"] == org_name))
        if orga:
            return orga["orgId"]

        return self._module.fail_json(
            failed=True, msg="Current user isn't member of organization: %s" % org_name
        )

    def datasource_by_name(self, name):
        url = "/api/datasources/name/%s" % quote(name, safe="")
        return self._send_request(url, headers=self.headers, method="GET")

    def delete_datasource(self, name):
        url = "/api/datasources/name/%s" % quote(name, safe="")
        self._send_request(url, headers=self.headers, method="DELETE")

    def update_datasource(self, ds_id, data):
        url = "/api/datasources/%d" % ds_id
        self._send_request(url, data=data, headers=self.headers, method="PUT")

    def create_datasource(self, data):
        url = "/api/datasources"
        self._send_request(url, data=data, headers=self.headers, method="POST")


def setup_module_object():
    argument_spec = base.grafana_argument_spec()

    argument_spec.update(
        name=dict(required=True, type="str"),
        uid=dict(type="str"),
        ds_type=dict(
            choices=[
                "graphite",
                "prometheus",
                "elasticsearch",
                "influxdb",
                "opentsdb",
                "mysql",
                "postgres",
                "cloudwatch",
                "alexanderzobnin-zabbix-datasource",
                "grafana-azure-monitor-datasource",
                "camptocamp-prometheus-alertmanager-datasource",
                "sni-thruk-datasource",
                "redis-datasource",
                "loki",
                "tempo",
                "quickwit-quickwit-datasource",
                "alertmanager",
            ]
        ),
        ds_url=dict(type="str"),
        access=dict(default="proxy", choices=["proxy", "direct"]),
        database=dict(type="str", default=""),
        user=dict(default="", type="str"),
        password=dict(default="", no_log=True, type="str"),
        basic_auth_user=dict(type="str"),
        basic_auth_password=dict(type="str", no_log=True),
        with_credentials=dict(default=False, type="bool"),
        tls_servername=dict(type="str"),
        tls_client_cert=dict(type="str", no_log=True),
        tls_client_key=dict(type="str", no_log=True),
        tls_ca_cert=dict(type="str", no_log=True),
        tls_skip_verify=dict(type="bool", default=False),
        is_default=dict(default=False, type="bool"),
        org_id=dict(default=1, type="int"),
        org_name=dict(type="str"),
        es_version=dict(
            type="str",
            default="7.10+",
            choices=["2", "5", "56", "60", "70", "7.7+", "7.10+", "8.0+"],
        ),
        max_concurrent_shard_requests=dict(type="int", default=256),
        time_field=dict(default="@timestamp", type="str"),
        time_interval=dict(type="str"),
        interval=dict(
            type="str",
            choices=["", "Hourly", "Daily", "Weekly", "Monthly", "Yearly"],
            default="",
        ),
        tsdb_version=dict(type="int", default=1, choices=[1, 2, 3]),
        tsdb_resolution=dict(
            type="str", default="second", choices=["second", "millisecond"]
        ),
        sslmode=dict(
            default="disable",
            choices=["disable", "require", "verify-ca", "verify-full"],
        ),
        trends=dict(default=False, type="bool"),
        alertmanager_implementation=dict(choices=["mimir", "cortex", "prometheus"]),
        alertmanager_handle_grafana_alerts=dict(default=False, type="bool"),
        aws_auth_type=dict(
            default="keys", choices=["keys", "credentials", "arn", "default"]
        ),
        aws_default_region=dict(
            default="us-east-1",
            choices=[
                "ap-northeast-1",
                "ap-northeast-2",
                "ap-southeast-1",
                "ap-southeast-2",
                "ap-south-1",
                "ca-central-1",
                "cn-north-1",
                "cn-northwest-1",
                "eu-central-1",
                "eu-west-1",
                "eu-west-2",
                "eu-west-3",
                "sa-east-1",
                "us-east-1",
                "us-east-2",
                "us-gov-west-1",
                "us-west-1",
                "us-west-2",
            ],
        ),
        aws_access_key=dict(default="", no_log=True, type="str"),
        aws_secret_key=dict(default="", no_log=True, type="str"),
        aws_credentials_profile=dict(default="", type="str"),
        aws_assume_role_arn=dict(default="", type="str"),
        aws_custom_metrics_namespaces=dict(type="str"),
        azure_cloud=dict(
            type="str",
            default="azuremonitor",
            choices=[
                "azuremonitor",
                "chinaazuremonitor",
                "govazuremonitor",
                "germanyazuremonitor",
            ],
        ),
        azure_tenant=dict(type="str"),
        azure_client=dict(type="str"),
        azure_secret=dict(type="str", no_log=True),
        zabbix_user=dict(type="str"),
        zabbix_password=dict(type="str", no_log=True),
        additional_json_data=dict(type="dict", default={}, required=False),
        additional_secure_json_data=dict(type="dict", default={}, required=False),
        enforce_secure_data=dict(type="bool", default=False, required=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[
            ["url_username", "url_password", "org_id"],
            ["tls_client_cert", "tls_client_key"],
        ],
        mutually_exclusive=[
            ["url_username", "grafana_api_key"],
            ["tls_ca_cert", "tls_skip_verify"],
            ["org_id", "org_name"],
        ],
        required_if=[
            ["state", "present", ["ds_type", "ds_url"]],
            ["ds_type", "opentsdb", ["tsdb_version", "tsdb_resolution"]],
            ["ds_type", "influxdb", ["database"]],
            [
                "ds_type",
                "elasticsearch",
                ["database", "es_version", "time_field", "interval"],
            ],
            ["ds_type", "mysql", ["database"]],
            ["ds_type", "postgres", ["database", "sslmode"]],
            ["ds_type", "cloudwatch", ["aws_auth_type", "aws_default_region"]],
            ["es_version", "56", ["max_concurrent_shard_requests"]],
            ["es_version", "60", ["max_concurrent_shard_requests"]],
            ["es_version", "70", ["max_concurrent_shard_requests"]],
        ],
    )
    return module


def main():
    module = setup_module_object()

    state = module.params["state"]
    name = module.params["name"]
    enforce_secure_data = module.params["enforce_secure_data"]

    grafana_iface = GrafanaInterface(module)
    ds = grafana_iface.datasource_by_name(name)

    if state == "present":
        payload = get_datasource_payload(module.params, grafana_iface.org_id)
        if ds is None:
            grafana_iface.create_datasource(payload)
            ds = grafana_iface.datasource_by_name(name)
            if ds.get("isDefault") != module.params["is_default"]:
                grafana_iface.update_datasource(ds.get("id"), payload)
                ds = grafana_iface.datasource_by_name(name)
            module.exit_json(
                changed=True, datasource=ds, msg="Datasource %s created" % name
            )
        else:
            diff = compare_datasources(payload.copy(), ds.copy(), enforce_secure_data)
            if diff.get("before") == diff.get("after"):
                module.exit_json(
                    changed=False, datasource=ds, msg="Datasource %s unchanged" % name
                )
            grafana_iface.update_datasource(ds.get("id"), payload)
            ds = grafana_iface.datasource_by_name(name)
            if diff.get("before") == diff.get("after"):
                module.exit_json(
                    changed=False, datasource=ds, msg="Datasource %s unchanged" % name
                )

            module.exit_json(
                changed=True,
                diff=diff,
                datasource=ds,
                msg="Datasource %s updated" % name,
            )
    else:
        if ds is None:
            module.exit_json(
                changed=False,
                datasource=None,
                msg="Datasource %s does not exist." % name,
            )
        grafana_iface.delete_datasource(name)
        module.exit_json(
            changed=True, datasource=None, msg="Datasource %s deleted." % name
        )


if __name__ == "__main__":
    main()
