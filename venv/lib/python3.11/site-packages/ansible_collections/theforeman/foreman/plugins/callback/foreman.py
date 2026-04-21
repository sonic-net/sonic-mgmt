# -*- coding: utf-8 -*-
# (c) 2015, 2016 Daniel Lobato <elobatocs@gmail.com>
# (c) 2016 Guido Günther <agx@sigxcpu.org>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# pylint: disable=super-with-arguments

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    name: foreman
    type: notification
    short_description: Sends events to Foreman
    description:
      - This callback will report facts and task events to Foreman
    requirements:
      - whitelisting in configuration
      - requests (python library)
    options:
      report_type:
        description:
          - "endpoint type for reports: foreman or proxy"
        env:
          - name: FOREMAN_REPORT_TYPE
        default: foreman
        ini:
          - section: callback_foreman
            key: report_type
      url:
        description:
          - URL of the Foreman server.
        env:
          - name: FOREMAN_URL
          - name: FOREMAN_SERVER_URL
          - name: FOREMAN_SERVER
        required: true
        ini:
          - section: callback_foreman
            key: url
      proxy_url:
        description:
          - URL of the Foreman Smart Proxy server.
        env:
          - name: FOREMAN_PROXY_URL
        ini:
          - section: callback_foreman
            key: proxy_url
      client_cert:
        description:
          - X509 certificate to authenticate to Foreman if https is used
        env:
            - name: FOREMAN_SSL_CERT
        default: /etc/foreman/client_cert.pem
        ini:
          - section: callback_foreman
            key: ssl_cert
          - section: callback_foreman
            key: client_cert
        aliases: [ ssl_cert ]
      client_key:
        description:
          - the corresponding private key
        env:
          - name: FOREMAN_SSL_KEY
        default: /etc/foreman/client_key.pem
        ini:
          - section: callback_foreman
            key: ssl_key
          - section: callback_foreman
            key: client_key
        aliases: [ ssl_key ]
      verify_certs:
        description:
          - Toggle to decide whether to verify the Foreman certificate.
          - It can be set to '1' to verify SSL certificates using the installed CAs or to a path pointing to a CA bundle.
          - Set to '0' to disable certificate checking.
        env:
          - name: FOREMAN_SSL_VERIFY
        default: 1
        ini:
          - section: callback_foreman
            key: verify_certs
      dir_store:
        description:
          - When set, callback does not perform HTTP calls but stores results in a given directory.
          - For each report, new file in the form of SEQ_NO-hostname.json is created.
          - For each facts, new file in the form of SEQ_NO-hostname.json is created.
          - The value must be a valid directory.
          - This is meant for debugging and testing purposes.
          - When set to blank (default) this functionality is turned off.
        env:
          - name: FOREMAN_DIR_STORE
        default: ''
        ini:
          - section: callback_foreman
            key: dir_store
      disable_callback:
        description:
          - Toggle to make the callback plugin disable itself even if it is loaded.
          - It can be set to '1' to prevent the plugin from being used even if it gets loaded.
        env:
          - name: FOREMAN_CALLBACK_DISABLE
        default: 0
'''

import os
from datetime import datetime
from collections import defaultdict
import json
import time

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from ansible.module_utils.common.json import AnsibleJSONEncoder
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.parsing.convert_bool import boolean as to_bool
from ansible.plugins.callback import CallbackBase


def build_log_foreman(data_list):
    """
    Transform the internal log structure to one accepted by Foreman's
    config_report API.
    """
    for data in data_list:
        result = data.pop('result')
        task = data.pop('task')
        result['failed'] = data.get('failed')
        result['module'] = task.get('action')
        if data.get('failed'):
            level = 'err'
        elif result.get('changed'):
            level = 'notice'
        else:
            level = 'info'

        yield {
            "log": {
                'sources': {
                    'source': task.get('name'),
                },
                'messages': {
                    'message': json.dumps(result, sort_keys=True, cls=AnsibleNoVaultJSONEncoder),
                },
                'level': level,
            }
        }


def get_time():
    """
    Return the time for measuring duration. Prefers monotonic time but
    falls back to the regular time on older Python versions.
    """
    try:
        return time.monotonic()
    except AttributeError:
        return time.time()


def get_now():
    """
    Return the current timestamp as a string to be sent over the network.
    The time is always in UTC *with* timezone information, so that Ruby
    DateTime can easily parse it.
    """
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S+00:00")


class AnsibleNoVaultJSONEncoder(AnsibleJSONEncoder):
    def default(self, o):
        if getattr(o, '__ENCRYPTED__', False):
            value = 'ENCRYPTED_VAULT_VALUE_NOT_REPORTED'
        else:
            value = super(AnsibleNoVaultJSONEncoder, self).default(o)
        return value


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    CALLBACK_NAME = 'theforeman.foreman.foreman'
    CALLBACK_NEEDS_WHITELIST = True

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.items = defaultdict(list)
        self.facts = defaultdict(dict)
        self.start_time = get_time()

    def set_options(self, task_keys=None, var_options=None, direct=None):

        super(CallbackModule, self).set_options(task_keys=task_keys, var_options=var_options, direct=direct)

        if self.get_option('disable_callback'):
            self._disable_plugin('Callback disabled by environment.')

        self.report_type = self.get_option('report_type')
        self.foreman_url = self.get_option('url')
        self.proxy_url = self.get_option('proxy_url')
        ssl_cert = self.get_option('client_cert')
        ssl_key = self.get_option('client_key')
        self.dir_store = self.get_option('dir_store')

        if not HAS_REQUESTS:
            self._disable_plugin(u'The `requests` python module is not installed')

        self.session = requests.Session()
        if self.foreman_url.startswith('https://'):
            if not os.path.exists(ssl_cert):
                self._disable_plugin(u'FOREMAN_SSL_CERT %s not found.' % ssl_cert)

            if not os.path.exists(ssl_key):
                self._disable_plugin(u'FOREMAN_SSL_KEY %s not found.' % ssl_key)

            self.session.verify = self._ssl_verify(str(self.get_option('verify_certs')))
            self.session.cert = (ssl_cert, ssl_key)

    def _disable_plugin(self, msg):
        self.disabled = True
        if msg:
            self._display.warning(msg + u' Disabling the Foreman callback plugin.')
        else:
            self._display.warning(u'Disabling the Foreman callback plugin.')

    def _ssl_verify(self, option):
        try:
            verify = to_bool(option)
        except TypeError:
            verify = option

        if verify is False:  # is only set to bool if try block succeeds
            requests.packages.urllib3.disable_warnings()
            self._display.warning(
                u"SSL verification of %s disabled" % self.foreman_url,
            )

        return verify

    def _send_data(self, data_type, report_type, host, data):
        if data_type == 'facts':
            url = self.foreman_url + '/api/v2/hosts/facts'
        elif data_type == 'report' and report_type == 'foreman':
            url = self.foreman_url + '/api/v2/config_reports'
        elif data_type == 'report' and report_type == 'proxy':
            url = self.proxy_url + '/reports/ansible'
        else:
            self._display.warning(u'Unknown report_type: {rt}'.format(rt=report_type))

        json_data = json.dumps(data, indent=2, sort_keys=True, cls=AnsibleNoVaultJSONEncoder)

        if len(self.dir_store) > 0:
            filename = u'{host}-{dt}.json'.format(host=to_text(host), dt=data_type)
            filename = os.path.join(self.dir_store, filename)
            with open(filename, 'w') as f:
                f.write(json_data)
        else:
            try:
                headers = {'content-type': 'application/json'}
                response = self.session.post(url=url, data=json_data, headers=headers)
                response.raise_for_status()
            except requests.exceptions.RequestException as err:
                self._display.warning(u'Sending data to Foreman at {url} failed for {host}: {err}'.format(
                    host=to_text(host), err=to_text(err), url=to_text(self.foreman_url)))

    def send_facts(self):
        """
        Sends facts to Foreman, to be parsed by foreman_ansible fact
        parser.  The default fact importer should import these facts
        properly.
        """
        # proxy parses facts from report directly
        if self.report_type == "proxy":
            return

        for host, facts in self.facts.items():
            facts = {
                "name": host,
                "facts": {
                    "ansible_facts": facts,
                    "_type": "ansible",
                    "_timestamp": get_now(),
                },
            }

            self._send_data('facts', 'foreman', host, facts)

    def send_reports_proxy_host_report(self, stats):
        """
        Send reports to Foreman Smart Proxy running Host Reports
        plugin. The format is native Ansible report without any
        changes.
        """
        for host in stats.processed.keys():
            report = {
                "host": host,
                "reported_at": get_now(),
                "metrics": {
                    "time": {
                        "total": int(get_time() - self.start_time)
                    }
                },
                "summary": stats.summarize(host),
                "results": self.items[host],
                "check_mode": self.check_mode,
            }

            self._send_data('report', 'proxy', host, report)
            self.items[host] = []

    def send_reports_foreman(self, stats):
        """
        Send reports to Foreman to be parsed by its config report
        importer. The data is in a format that Foreman can handle
        without writing another report importer.
        """
        for host in stats.processed.keys():
            total = stats.summarize(host)
            report = {
                "config_report": {
                    "host": host,
                    "reported_at": get_now(),
                    "metrics": {
                        "time": {
                            "total": int(get_time() - self.start_time)
                        }
                    },
                    "status": {
                        "applied": total['changed'],
                        "failed": total['failures'] + total['unreachable'],
                        "skipped": total['skipped'],
                    },
                    "logs": list(build_log_foreman(self.items[host])),
                    "reporter": "ansible",
                    "check_mode": self.check_mode,
                }
            }
            if self.check_mode:
                report['config_report']['status']['pending'] = total['changed']
                report['config_report']['status']['applied'] = 0

            self._send_data('report', 'foreman', host, report)
            self.items[host] = []

    def send_reports(self, stats):
        if self.report_type == "foreman":
            self.send_reports_foreman(stats)
        elif self.report_type == "proxy":
            self.send_reports_proxy_host_report(stats)
        else:
            self._display.warning(u'Unknown foreman endpoint type: {type}'.format(type=self.report_type))

    def drop_nones(self, d):
        """Recursively drop Nones or empty dicts/arrays in dict d and return a new dict"""
        dd = {}
        for k, v in d.items():
            if isinstance(v, dict) and v:
                dd[k] = self.drop_nones(v)
            elif isinstance(v, list) and len(v) == 1 and v[0] == {}:
                pass
            elif isinstance(v, (list, set, tuple)) and v:
                dd[k] = type(v)(self.drop_nones(vv) if isinstance(vv, dict) else vv
                                for vv in v)
            elif not isinstance(v, (dict, list, set, tuple)) and v is not None:
                dd[k] = v
        return dd

    def append_result(self, result, failed=False):
        result_info = result._result
        if hasattr(result._task, 'serialize'):
            task_info = result._task.serialize()
        else:
            task_info = result._task.dump_attrs()
        task_info['args'] = None
        value = {}
        value['result'] = result_info
        value['task'] = task_info
        value['failed'] = failed
        if self.report_type == "proxy":
            value = self.drop_nones(value)
        host = result._host.get_name()
        self.items[host].append(value)
        self.check_mode = result._task.check_mode
        if 'ansible_facts' in result_info:
            self.facts[host].update(result_info['ansible_facts'])

    # Ansible callback API
    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.append_result(result, True)

    def v2_runner_on_unreachable(self, result):
        self.append_result(result, True)

    def v2_runner_on_async_ok(self, result):
        self.append_result(result)

    def v2_runner_on_async_failed(self, result):
        self.append_result(result, True)

    def v2_playbook_on_stats(self, stats):
        self.send_facts()
        self.send_reports(stats)

    def v2_runner_on_ok(self, result):
        self.append_result(result)
