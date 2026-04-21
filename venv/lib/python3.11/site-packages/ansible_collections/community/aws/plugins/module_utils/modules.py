# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible_collections.amazon.aws.plugins.module_utils.common import set_collection_info
from ansible_collections.amazon.aws.plugins.module_utils.modules import AnsibleAWSModule

from ansible_collections.community.aws.plugins.module_utils.common import COMMUNITY_AWS_COLLECTION_NAME
from ansible_collections.community.aws.plugins.module_utils.common import COMMUNITY_AWS_COLLECTION_VERSION


class AnsibleCommunityAWSModule(AnsibleAWSModule):
    def __init__(self, **kwargs):
        super(AnsibleCommunityAWSModule, self).__init__(**kwargs)
        set_collection_info(
            collection_name=COMMUNITY_AWS_COLLECTION_NAME,
            collection_version=COMMUNITY_AWS_COLLECTION_VERSION,
        )
