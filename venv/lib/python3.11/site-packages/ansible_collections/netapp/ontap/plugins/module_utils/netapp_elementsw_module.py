# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

HAS_SF_SDK = False
try:
    # pylint: disable=unused-import
    import solidfire.common

    HAS_SF_SDK = True
except Exception:
    HAS_SF_SDK = False


def has_sf_sdk():
    return HAS_SF_SDK


class NaElementSWModule(object):

    def __init__(self, elem):
        self.elem_connect = elem
        self.parameters = dict()

    def volume_id_exists(self, volume_id):
        """
            Return volume_id if volume exists for given volume_id

            :param volume_id: volume ID
            :type volume_id: int
            :return: Volume ID if found, None if not found
            :rtype: int
        """
        volume_list = self.elem_connect.list_volumes(volume_ids=[volume_id])
        for volume in volume_list.volumes:
            if volume.volume_id == volume_id:
                if str(volume.delete_time) == "":
                    return volume.volume_id
        return None
