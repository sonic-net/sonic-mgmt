""" Support functions for NetApp ansible modules
    Provides common processing for responses and errors from REST calls
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


def get_export_policy_id(rest_api, policy_name, svm_name, module):
    api = 'protocols/nfs/export-policies'
    query = {'name': policy_name, 'svm.name': svm_name}
    record, error = rest_generic.get_one_record(rest_api, api, query)
    if error:
        module.fail_json(msg='Could not find export policy %s on SVM %s' % (policy_name, svm_name))
    return record['id'] if record else None


def get_volume_uuid(rest_api, volume_name, svm_name, module):
    api = 'storage/volumes'
    query = {'name': volume_name, 'svm.name': svm_name}
    record, error = rest_generic.get_one_record(rest_api, api, query)
    if error:
        module.fail_json(msg='Could not find volume %s on SVM %s' % (volume_name, svm_name))
    return record['uuid'] if record else None


def get_consistency_group_uuid(rest_api, cg_name, svm_name, module):
    api = 'application/consistency-groups'
    query = {'name': cg_name, 'svm.name': svm_name}
    record, error = rest_generic.get_one_record(rest_api, api, query)
    if error:
        module.fail_json(msg='Could not find consistency group %s on SVM %s' % (cg_name, svm_name))
    return record['uuid'] if record else None
