#!/usr/bin/python

import os

def main():
    module = AnsibleModule(
             argument_spec = dict(
                 args=dict(required=True),
                 rc=dict(type='bool', default='True')),
                 supports_check_mode=True
             )
    args = module.params['args']
    rc   = module.params['rc']
    os.system('echo {0}'.format(args))

    if rc:
        result = dict(echo=args)
        module.exit_json(**result)
    else:
        module.fail_json(msg="Errors happened")

from ansible.module_utils.basic import *
if __name__=="__main__":
    main()
