# Copyright (c) 2025 Clounix (Shanghai) Technology Limited.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
#    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
#    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
#    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
#    See the Apache Version 2.0 License for specific language governing
#    permissions and limitations under the License.


"""
This file contains class for clx specified functions.
"""

from platform_helper.common_sai_helper import * # pylint: disable=wildcard-import; lgtm[py/polluting-import]

class ClxSaiHelper(CommonSaiHelper):
    """
    This class contains clounix(clx) specified functions for the platform setup and test context configuration.
    """
    platform = 'clx'

    def recreate_ports(self):
        print("ClxSaiHelper::recreate_ports")
