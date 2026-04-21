from __future__ import absolute_import, division, print_function

__metaclass__ = type


import os

from ansible.module_utils.common.validation import check_type_bool

try:
    enable_turbo_mode = check_type_bool(os.environ.get("ENABLE_TURBO_MODE"))
except TypeError:
    enable_turbo_mode = False

if enable_turbo_mode:
    try:
        from ansible_collections.cloud.common.plugins.module_utils.turbo.module import (  # noqa: F401
            AnsibleTurboModule as AnsibleModule,
        )

        AnsibleModule.collection_name = "kubernetes.core"
    except ImportError:
        from ansible.module_utils.basic import AnsibleModule  # noqa: F401
else:
    from ansible.module_utils.basic import AnsibleModule  # noqa: F401
