import logging
import time
import uuid
import proto_utils
import pytest

from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.gnmi.helper import gnmi_set

logger = logging.getLogger(__name__)

def apply_messages(
    localhost,
    duthost,
    ptfhost,
    messages,
    dpu_index,
    setup_ha_config,
    gnmi_key,
    filename,
    set_db=True,
    wait_after_apply=5,
    max_updates_in_single_cmd=1024,
):
    env = GNMIEnvironment(duthost)
    update_list = []
    delete_list = []
    ptfhost.copy(src=filename, dest='/root')

    if set_db:
        if proto_utils.ENABLE_PROTO:
            path = f"/APPL_DB/dpu{dpu_index}/{gnmi_key}:/root/{filename}"
        else:
            path = f"/APPL_DB/dpu{dpu_index}/{gnmi_key}:/root/{filename}"
        update_list.append(path)
    else:
        path = f"/APPL_DB/dpu{dpu_index}/{gnmi_key}"
        delete_list.append(path)

    write_gnmi_files(localhost, duthost, ptfhost, env, delete_list, update_list, max_updates_in_single_cmd)
    time.sleep(wait_after_apply)


def write_gnmi_files(localhost, duthost, ptfhost, env, delete_list, update_list, max_updates_in_single_cmd):

    if delete_list:
        gnmi_set(duthost, ptfhost, delete_list, [], [])
    if update_list:
        gnmi_set(duthost, ptfhost, [], update_list, [])
