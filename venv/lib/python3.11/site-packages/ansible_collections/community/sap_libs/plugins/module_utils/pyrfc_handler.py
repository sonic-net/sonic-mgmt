# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sean Freeman ,
#                      Rainer Leber <rainerleber@gmail.com> <rainer.leber@sva.de>
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

from ansible.module_utils.basic import missing_required_lib

import traceback

PYRFC_LIBRARY_IMPORT_ERROR = None
try:
    import pyrfc
except ImportError:
    PYRFC_LIBRARY_IMPORT_ERROR = traceback.format_exc()
    HAS_PYRFC_LIBRARY = False
else:
    HAS_PYRFC_LIBRARY = True


def get_connection(module, conn_params):
    if not HAS_PYRFC_LIBRARY:
        module.fail_json(msg=missing_required_lib(
            "pyrfc"), exception=PYRFC_LIBRARY_IMPORT_ERROR)

    module.warn('Connecting ... %s' % conn_params['ashost'])
    if "saprouter" in conn_params:
        module.warn("...via SAPRouter to SAP System")
    elif "gwhost" in conn_params:
        module.warn("...via Gateway to SAP System")
    else:
        module.warn("...direct to SAP System")

    conn = pyrfc.Connection(**conn_params)

    module.warn("Verifying connection is open/alive: %s" % conn.alive)
    return conn
