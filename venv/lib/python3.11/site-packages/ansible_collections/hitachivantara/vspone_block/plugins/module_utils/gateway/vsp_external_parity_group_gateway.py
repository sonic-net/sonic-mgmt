try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..model.vsp_parity_group_models import (
        VSPPfrestExternalParityGroup,
        VSPPfrestParityGroupSpace,
    )
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from model.vsp_parity_group_models import (
        VSPPfrestExternalParityGroup,
        VSPPfrestParityGroupSpace,
    )

GET_EXTERNAL_PARITY_GROUP = "v1/objects/external-parity-groups/{}"
ASSIGN_EXTERNAL_PARITY = (
    "v1/objects/external-parity-groups/{}/actions/assign-clpr/invoke"
)
CHANGE_MP_BLADE = "v1/objects/external-parity-groups/{}/actions/assign-mp-blade/invoke"
DISCONNECT_FROM_A_VOL_EXT_STORAGE = (
    "v1/objects/external-parity-groups/{}/actions/disconnect/invoke"
)
DELETE_EXTERNAL_PARITY = "v1/objects/external-parity-groups/{}"
CREATE_EXTERNAL_PARITY = "v1/objects/external-parity-groups"
GET_EXT_PATH_GR_BY_EXT_PARITY_GRP_ID = (
    "v1/objects/external-path-groups?externalParityGroupId={}"
)

logger = Log()


class VSPExternalParityGroupGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.serial = None

    @log_entry_exit
    def set_serial(self, serial: str):
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.get_storage_serial()

    @log_entry_exit
    def get_storage_serial(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def get_external_path_group_by_external_parity_group_id(
        self, external_parity_group_id
    ):
        end_point = GET_EXT_PATH_GR_BY_EXT_PARITY_GRP_ID.format(
            external_parity_group_id
        )
        response = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_external_path_group_by_external_parity_group_id:response={}",
            response,
        )
        return response

    @log_entry_exit
    def get_external_parity_group(self, external_parity_group_id):
        end_point = GET_EXTERNAL_PARITY_GROUP.format(external_parity_group_id)
        parity_group_dict = self.connection_manager.get(end_point)
        epg = VSPPfrestExternalParityGroup(**parity_group_dict)
        epg.spaces = dicts_to_dataclass_list(
            parity_group_dict.get("spaces", None), VSPPfrestParityGroupSpace
        )
        # return VSPPfrestExternalParityGroup(**parity_group_dict)
        return epg

    @log_entry_exit
    def assign_external_parity_group(self, external_parity_group_id, clpr_id):
        end_point = ASSIGN_EXTERNAL_PARITY.format(external_parity_group_id)
        parameters = {}
        parameters["clprId"] = clpr_id
        payload = {"parameters": parameters}
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:assign_external_parity_group:response={}", response)
        if response:
            return response
        return None

    @log_entry_exit
    def change_mp_blade(self, external_parity_group_id, mp_blade_id):
        end_point = CHANGE_MP_BLADE.format(external_parity_group_id)
        parameters = {}
        parameters["mpBladeId"] = mp_blade_id
        payload = {"parameters": parameters}
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:change_mp_blade:response={}", response)
        if response:
            return response
        return None

    @log_entry_exit
    def disconnect_from_a_volume_on_external_storage(self, external_parity_group_id):
        end_point = DISCONNECT_FROM_A_VOL_EXT_STORAGE.format(external_parity_group_id)
        data = self.connection_manager.post(end_point, data=None)
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def delete_external_parity_group(self, external_parity_group_id, force=None):
        end_point = DELETE_EXTERNAL_PARITY.format(external_parity_group_id)
        payload = None
        if force and force is True:
            payload = {"force": True}
        data = self.connection_manager.delete(end_point, data=payload)
        self.connection_info.changed = True
        return data

    @log_entry_exit
    def create_external_parity_group(self, create_epg_object):
        payload = {
            "externalParityGroupId": create_epg_object.external_parity_group_id,
            "externalPathGroupId": create_epg_object.external_path_group_id,
            "portId": create_epg_object.port_id,
            "externalWwn": create_epg_object.external_wwn,
            "lunId": create_epg_object.lun_id,
        }
        if create_epg_object.emulation_type:
            payload["emulationType"] = create_epg_object.emulation_type
        if create_epg_object.clpr_id:
            payload["clprId"] = create_epg_object.clpr_id
        if create_epg_object.is_external_attribute_migration:
            payload["isExternalAttributeMigration"] = (
                create_epg_object.is_external_attribute_migration
            )
        if create_epg_object.command_device_ldev_id:
            payload["commandDeviceLdevId"] = create_epg_object.command_device_ldev_id

        end_point = CREATE_EXTERNAL_PARITY
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:change_mp_blade:response={}", response)
        if response:
            return response
        return None
