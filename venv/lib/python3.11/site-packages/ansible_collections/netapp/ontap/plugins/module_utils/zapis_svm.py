# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2020, Laurent Nicolas <laurentn@netapp.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

''' Support class for NetApp ansible modules

    Provides accesss to SVM (vserver) resources using ZAPI calls
'''

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import traceback

from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils


def get_vserver(svm_cx, vserver_name):
    """
    Return vserver information.

    :return:
        vserver object if vserver found
        None if vserver is not found
    :rtype: object/None
    """
    vserver_info = netapp_utils.zapi.NaElement('vserver-get-iter')
    query_details = netapp_utils.zapi.NaElement.create_node_with_children(
        'vserver-info', **{'vserver-name': vserver_name})

    query = netapp_utils.zapi.NaElement('query')
    query.add_child_elem(query_details)
    vserver_info.add_child_elem(query)

    result = svm_cx.invoke_successfully(vserver_info, enable_tunneling=False)
    vserver_details = None
    if result.get_child_by_name('num-records') and int(result.get_child_content('num-records')) >= 1:
        attributes_list = result.get_child_by_name('attributes-list')
        vserver_info = attributes_list.get_child_by_name('vserver-info')
        aggr_list = []
        # vserver aggr-list can be empty by default
        get_list = vserver_info.get_child_by_name('aggr-list')
        if get_list is not None:
            aggregates = get_list.get_children()
            aggr_list.extend(aggr.get_content() for aggr in aggregates)
        protocols = []
        # allowed-protocols is not empty for data SVM, but is for node SVM
        allowed_protocols = vserver_info.get_child_by_name('allowed-protocols')
        if allowed_protocols is not None:
            get_protocols = allowed_protocols.get_children()
            protocols.extend(protocol.get_content() for protocol in get_protocols)
        vserver_details = {'name': vserver_info.get_child_content('vserver-name'),
                           'root_volume': vserver_info.get_child_content('root-volume'),
                           'root_volume_aggregate': vserver_info.get_child_content('root-volume-aggregate'),
                           'root_volume_security_style': vserver_info.get_child_content('root-volume-security-style'),
                           'subtype': vserver_info.get_child_content('vserver-subtype'),
                           'aggr_list': aggr_list,
                           'language': vserver_info.get_child_content('language'),
                           'quota_policy': vserver_info.get_child_content('quota-policy'),
                           'snapshot_policy': vserver_info.get_child_content('snapshot-policy'),
                           'allowed_protocols': protocols,
                           'ipspace': vserver_info.get_child_content('ipspace'),
                           'comment': vserver_info.get_child_content('comment'),
                           'max_volumes': vserver_info.get_child_content('max-volumes')}

    return vserver_details


def modify_vserver(svm_cx, module, name, modify, parameters=None):
    '''
    Modify vserver.
    :param name: vserver name
    :param modify: list of modify attributes
    :param parameters: customer original inputs
    modify only contains the difference between the customer inputs and current
    for some attributes, it may be safer to apply the original inputs
    '''
    if parameters is None:
        parameters = modify

    vserver_modify = netapp_utils.zapi.NaElement('vserver-modify')
    vserver_modify.add_new_child('vserver-name', name)
    for attribute in modify:
        if attribute == 'comment':
            vserver_modify.add_new_child('comment', parameters['comment'])
        if attribute == 'language':
            vserver_modify.add_new_child('language', parameters['language'])
        if attribute == 'quota_policy':
            vserver_modify.add_new_child('quota-policy', parameters['quota_policy'])
        if attribute == 'snapshot_policy':
            vserver_modify.add_new_child('snapshot-policy', parameters['snapshot_policy'])
        if attribute == 'max_volumes':
            vserver_modify.add_new_child('max-volumes', parameters['max_volumes'])
        if attribute == 'allowed_protocols':
            allowed_protocols = netapp_utils.zapi.NaElement('allowed-protocols')
            for protocol in parameters['allowed_protocols']:
                allowed_protocols.add_new_child('protocol', protocol)
            vserver_modify.add_child_elem(allowed_protocols)
        if attribute == 'aggr_list':
            aggregates = netapp_utils.zapi.NaElement('aggr-list')
            for aggr in parameters['aggr_list']:
                aggregates.add_new_child('aggr-name', aggr)
            vserver_modify.add_child_elem(aggregates)
    try:
        svm_cx.invoke_successfully(vserver_modify, enable_tunneling=False)
    except netapp_utils.zapi.NaApiError as exc:
        module.fail_json(msg='Error modifying SVM %s: %s' % (name, to_native(exc)),
                         exception=traceback.format_exc())
