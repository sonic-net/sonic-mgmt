#!/usr/bin/python

# Copyright: (c) 2022, Rainer Leber rainerleber@gmail.com, rainer.leber@sva.de,
#                      Robert Kraemer @rkpobe, robert.kraemer@sva.de
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: sap_control_exec

short_description: Ansible Module to execute SAPCONTROL

version_added: "1.1.0"

description:
    - Provides support for sapstartsrv formaly known as sapcontrol
    - A complete information of all functions and the parameters can be found here
      U(https://www.sap.com/documents/2016/09/0a40e60d-8b7c-0010-82c7-eda71af511fa.html)

options:
    sysnr:
        description:
            - The system number of the instance.
        required: false
        type: str
    port:
        description:
            - The port number of the sapstartsrv.
        required: false
        type: int
    username:
        description:
            - The username to connect to the sapstartsrv.
        required: false
        type: str
    password:
        description:
            - The password to connect to the sapstartsrv.
        required: false
        type: str
    hostname:
        description:
            - The hostname to connect to the sapstartsrv.
            - Could be an IP address, FQDN or hostname.
        required: false
        default: localhost
        type: str
    function:
        description:
        - The function to execute.
        required: true
        choices:
        - Start
        - Stop
        - Shutdown
        - InstanceStart
        - InstanceStop
        - Bootstrap
        - ParameterValue
        - GetProcessList
        - GetProcessList2
        - GetStartProfile
        - GetTraceFile
        - GetAlertTree
        - GetAlerts
        - RestartService
        - StopService
        - GetEnvironment
        - ListDeveloperTraces
        - ListLogFiles
        - ReadDeveloperTrace
        - ReadLogFile
        - AnalyseLogFile
        - ConfigureLogFileList
        - GetLogFileList
        - RestartInstance
        - SendSignal
        - GetVersionInfo
        - GetQueueStatistic
        - GetInstanceProperties
        - OSExecute
        - AnalyseLogFiles
        - GetAccessPointList
        - GetSystemInstanceList
        - StartSystem
        - StopSystem
        - RestartSystem
        - AccessCheck
        - GetProcessParameter
        - SetProcessParameter
        - SetProcessParameter2
        - ShmDetach
        - CreateSnapshot
        - ReadSnapshot
        - ListSnapshots
        - DeleteSnapshots
        - RequestLogonFile
        - GetNetworkId
        - GetSecNetworkId
        - UpdateSystem
        - GetSystemUpdateList
        - UpdateSCSInstance
        - ABAPReadSyslog
        - ABAPReadRawSyslog
        - ABAPGetWPTable
        - ABAPAcknoledgeAlerts
        - CMGetThreadList
        - ICMGetConnectionList
        - ICMGetCacheEntries
        - ICMGetProxyConnectionList
        - WebDispGetServerList
        - WebDispGetGroupList
        - WebDispGetVirtHostList
        - WebDispGeUrlPrefixList
        - EnqGetLockTable
        - EnqRemoveLocks
        - EnqGetStatistic
        type: str
    parameter:
        description:
            - The parameter to pass to the function.
        required: false
        type: str
    force:
        description:
            - Forces the execution of the function C(Stop).
        required: false
        default: false
        type: bool
author:
    - Rainer Leber (@RainerLeber)
    - Robert Kraemer (@rkpobe)
notes:
    - Does not support C(check_mode).
'''

EXAMPLES = r"""
- name: GetProcessList with sysnr
  community.sap_libs.sap_control_exec:
    hostname: 192.168.8.15
    sysnr: "01"
    function: GetProcessList

- name: GetProcessList with custom port
  community.sap_libs.sap_control_exec:
    hostname: 192.168.8.15
    function: GetProcessList
    port: 50113

- name: ParameterValue
  community.sap_libs.sap_control_exec:
    hostname: 192.168.8.15
    sysnr: "01"
    username: hdbadm
    password: test1234#
    function: ParameterValue
    parameter: ztta
"""

RETURN = r'''
msg:
    description: Success-message with functionname.
    type: str
    returned: always
    sample: 'Succesful execution of: GetProcessList'
out:
    description: The full output of the required function.
    type: list
    elements: dict
    returned: always
    sample: [{
            "item": [
                {
                    "description": "MessageServer",
                    "dispstatus": "SAPControl-GREEN",
                    "elapsedtime": "412:30:50",
                    "name": "msg_server",
                    "pid": 70643,
                    "starttime": "2022 03 13 15:22:42",
                    "textstatus": "Running"
                },
                {
                    "description": "EnqueueServer",
                    "dispstatus": "SAPControl-GREEN",
                    "elapsedtime": "412:30:50",
                    "name": "enserver",
                    "pid": 70644,
                    "starttime": "2022 03 13 15:22:42",
                    "textstatus": "Running"
                },
                {
                    "description": "Gateway",
                    "dispstatus": "SAPControl-GREEN",
                    "elapsedtime": "412:30:50",
                    "name": "gwrd",
                    "pid": 70645,
                    "starttime": "2022 03 13 15:22:42",
                    "textstatus": "Running"
                }
                ]
            }]
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import traceback
try:
    from suds.client import Client
    from suds.sudsobject import asdict
except ImportError:
    HAS_SUDS_LIBRARY = False
    SUDS_LIBRARY_IMPORT_ERROR = traceback.format_exc()
else:
    SUDS_LIBRARY_IMPORT_ERROR = None
    HAS_SUDS_LIBRARY = True


def choices():
    retlist = ["Start", "Stop", "Shutdown", "InstanceStart", "InstanceStop", "Bootstrap", "ParameterValue", "GetProcessList",
               "GetProcessList2", "GetStartProfile", "GetTraceFile", "GetAlertTree", "GetAlerts", "RestartService",
               "StopService", "GetEnvironment", "ListDeveloperTraces", "ListLogFiles", "ReadDeveloperTrace", "ReadLogFile",
               "AnalyseLogFile", "ConfigureLogFileList", "GetLogFileList", "RestartInstance", "SendSignal", "GetVersionInfo",
               "GetQueueStatistic", "GetInstanceProperties", "OSExecute", "AnalyseLogFiles", "GetAccessPointList",
               "GetSystemInstanceList", "StartSystem", "StopSystem", "RestartSystem", "AccessCheck", "GetProcessParameter",
               "SetProcessParameter", "SetProcessParameter2", "ShmDetach", "CreateSnapshot", "ReadSnapshot", "ListSnapshots",
               "DeleteSnapshots", "RequestLogonFile", "GetNetworkId", "GetSecNetworkId", "UpdateSystem", "GetSystemUpdateList",
               "UpdateSCSInstance", "ABAPReadSyslog", "ABAPReadRawSyslog", "ABAPGetWPTable", "ABAPAcknoledgeAlerts",
               "CMGetThreadList", "ICMGetConnectionList", "ICMGetCacheEntries", "ICMGetProxyConnectionList",
               "WebDispGetServerList", "WebDispGetGroupList", "WebDispGetVirtHostList", "WebDispGeUrlPrefixList",
               "EnqGetLockTable", "EnqRemoveLocks", "EnqGetStatistic"]
    return retlist


# converts recursively the suds object to a dictionary e.g. {'item': [{'name': hdbdaemon, 'value': '1'}]}
def recursive_dict(suds_object):
    out = {}
    if isinstance(suds_object, str):
        return suds_object
    for k, v in asdict(suds_object).items():
        if hasattr(v, '__keylist__'):
            out[k] = recursive_dict(v)
        elif isinstance(v, list):
            out[k] = []
            for item in v:
                if hasattr(item, '__keylist__'):
                    out[k].append(recursive_dict(item))
                else:
                    out[k].append(item)
        else:
            out[k] = v
    return out


def connection(hostname, port, username, password, function, parameter):
    url = 'http://{0}:{1}/sapcontrol?wsdl'.format(hostname, port)
    client = Client(url, username=username, password=password)
    _function = getattr(client.service, function)
    if parameter is not None:
        result = _function(parameter)
    elif function == "StartSystem":
        result = _function(waittimeout=0)
    elif function == "StopSystem" or function == "RestartSystem":
        result = _function(waittimeout=0, softtimeout=0)
    else:
        result = _function()

    return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            sysnr=dict(type='str', required=False),
            port=dict(type='int', required=False),
            username=dict(type='str', required=False),
            password=dict(type='str', no_log=True, required=False),
            hostname=dict(type='str', default="localhost"),
            function=dict(type='str', required=True, choices=choices()),
            parameter=dict(type='str', required=False),
            force=dict(type='bool', default=False),
        ),
        required_one_of=[('sysnr', 'port')],
        mutually_exclusive=[('sysnr', 'port')],
        supports_check_mode=False,
    )
    result = dict(changed=False, msg='', out={}, error='')
    params = module.params

    sysnr = params['sysnr']
    port = params['port']
    username = params['username']
    password = params['password']
    hostname = params['hostname']
    function = params['function']
    parameter = params['parameter']
    force = params['force']

    if not HAS_SUDS_LIBRARY:
        module.fail_json(
            msg=missing_required_lib('suds'),
            exception=SUDS_LIBRARY_IMPORT_ERROR)

    if function == "Stop":
        if force is False:
            module.fail_json(msg="Stop function requires force: True")

    if port is None:
        try:
            try:
                conn = connection(hostname, "5{0}14".format((sysnr).zfill(2)), username, password, function, parameter)
            except Exception:
                conn = connection(hostname, "5{0}13".format((sysnr).zfill(2)), username, password, function, parameter)
        except Exception as err:
            result['error'] = str(err)
    else:
        try:
            conn = connection(hostname, port, username, password, function, parameter)
        except Exception as err:
            result['error'] = str(err)

    if result['error'] != '':
        result['msg'] = 'Something went wrong connecting to the SAPCONTROL SOAP API.'
        module.fail_json(**result)

    if conn is not None:
        returned_data = recursive_dict(conn)
    else:
        returned_data = conn

    result['changed'] = True
    result['msg'] = "Succesful execution of: " + function
    result['out'] = [returned_data]

    module.exit_json(**result)


if __name__ == '__main__':
    main()
