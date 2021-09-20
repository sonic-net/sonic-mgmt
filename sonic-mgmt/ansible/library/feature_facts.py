#!/usr/bin/env python

# This ansible module is for gathering feature facts from SONiC device.
#
# Feature information will be taken from CONFIG_DB.
# Example of FEATURE info in CONFIG_DB:
#
# "FEATURE": {
#     "sflow": {
#         "status": "disabled"
#     }
#     "telemetry": {
#         "status": "enabled"
#     }
#     "what-just-happened": {
#         "status": "enabled"
#     }
# }
#
# An example result of calling the module:
# {
#     "ansible_facts": {
#         "feature_facts": {
#             "sflow": "disabled",
#             "telemetry" : "enabled"
#         }
#     }
# }


from ansible.module_utils.basic import *
SUCCESS_CODE = 0


def get_feature_facts(module):
    rc, stdout, stderr = module.run_command('sonic-db-cli CONFIG_DB keys FEATURE\*')
    if rc != SUCCESS_CODE:
        module.fail_json(msg='Failed to get feature names, rc=%s, stdout=%s, stderr=%s' % (rc, stdout, stderr))

    features = {}
    output_lines = stdout.splitlines()
    for line in output_lines:
        feature_name = line.split('|')[1]
        rc, stdout, stderr = module.run_command('sonic-db-cli CONFIG_DB HGET "FEATURE|{}" state'.format(feature_name))
        if rc != SUCCESS_CODE:
            module.fail_json(msg='Failed to get feature status, rc=%s, stdout=%s, stderr=%s' % (rc, stdout, stderr))
        features[feature_name] = stdout.rstrip('\n')

    return features


def main():
    module = AnsibleModule(argument_spec=dict())
    features = get_feature_facts(module)
    module.exit_json(ansible_facts={'feature_facts': features})


if __name__ == '__main__':
    main()
