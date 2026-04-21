try:
    from ..common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.vsp_parity_group_models import (
        VSPPfrestParityGroupList,
        VSPPfrestParityGroup,
        VSPPfrestExternalParityGroupList,
        VSPPfrestExternalParityGroup,
        VSPPfrestParityGroupSpace,
        VSPPfrestLdevList,
        VSPPfrestLdev,
    )
except ImportError:
    from common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.vsp_parity_group_models import (
        VSPPfrestParityGroupList,
        VSPPfrestParityGroup,
        VSPPfrestExternalParityGroupList,
        VSPPfrestExternalParityGroup,
        VSPPfrestParityGroupSpace,
        VSPPfrestLdevList,
        VSPPfrestLdev,
    )


class VSPParityGroupDirectGateway:

    def __init__(self, connection_info):
        self.connectionManager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )

    @log_entry_exit
    def get_all_parity_groups(self):
        endPoint = Endpoints.GET_PARITY_GROUPS
        parity_groups_dict = self.connectionManager.get(endPoint)
        return VSPPfrestParityGroupList(
            dicts_to_dataclass_list(parity_groups_dict["data"], VSPPfrestParityGroup)
        )

    @log_entry_exit
    def get_parity_group(self, parity_group_id):
        endPoint = Endpoints.GET_PARITY_GROUP.format(parity_group_id)
        parity_group_dict = self.connectionManager.get(endPoint)
        return VSPPfrestParityGroup(**parity_group_dict)

    @log_entry_exit
    def get_all_external_parity_groups(self):
        endPoint = Endpoints.GET_EXTERNAL_PARITY_GROUPS
        parity_groups_dict = self.connectionManager.get(endPoint)
        return VSPPfrestExternalParityGroupList(
            dicts_to_dataclass_list(
                parity_groups_dict["data"], VSPPfrestExternalParityGroup
            )
        )

    @log_entry_exit
    def get_external_parity_group(self, external_parity_group_id):
        endPoint = Endpoints.GET_EXTERNAL_PARITY_GROUP.format(external_parity_group_id)
        parity_group_dict = self.connectionManager.get(endPoint)
        epg = VSPPfrestExternalParityGroup(**parity_group_dict)
        epg.spaces = dicts_to_dataclass_list(
            parity_group_dict.get("spaces", None), VSPPfrestParityGroupSpace
        )
        # return VSPPfrestExternalParityGroup(**parity_group_dict)
        return epg

    @log_entry_exit
    def get_ldevs(self, ldevs_query):
        endPoint = Endpoints.GET_LDEVS.format(ldevs_query)
        rest_ldevs = self.connectionManager.get(endPoint)
        return VSPPfrestLdevList(
            dicts_to_dataclass_list(rest_ldevs["data"], VSPPfrestLdev)
        )

    @log_entry_exit
    def create_external_parity_group(
        self,
        externalPathGroupId: int,
        externalParityGroupId: str,
        portId: str,
        externalWwn: str,
        lunId: int,
    ):
        endPoint = Endpoints.GET_EXTERNAL_PARITY_GROUPS
        payload = {
            "externalPathGroupId": externalPathGroupId,
            "externalParityGroupId": externalParityGroupId,
            "portId": portId,
            "externalWwn": externalWwn,
            "lunId": lunId,
            "emulationType": "OPEN-V",
            "clprId": 0,
        }
        response = self.connectionManager.post(endPoint, payload)
        return response

    @log_entry_exit
    def create_parity_group(self, spec):
        endPoint = Endpoints.GET_PARITY_GROUPS
        payload = {
            "parityGroupId": spec.parity_group_id,
            "driveLocationIds": spec.drive_location_ids,
            "raidType": spec.raid_type,
            "isEncryptionEnabled": (
                spec.is_encryption_enabled if spec.is_encryption_enabled else False
            ),
            "isCopyBackModeEnabled": (
                spec.is_copy_back_mode_enabled
                if spec.is_copy_back_mode_enabled
                else True
            ),
            "isAcceleratedCompressionEnabled": (
                spec.is_accelerated_compression_enabled
                if spec.is_accelerated_compression_enabled
                else False
            ),
        }
        if spec.clpr_id is not None:
            payload["clprId"] = spec.clpr_id
        response = self.connectionManager.post(endPoint, payload)
        return response

    @log_entry_exit
    def delete_parity_group(self, parity_group_id):
        endPoint = Endpoints.GET_PARITY_GROUP.format(parity_group_id)
        response = self.connectionManager.delete(endPoint)
        return response

    @log_entry_exit
    def delete_external_parity_group(self, id: int):
        endPoint = Endpoints.GET_EXTERNAL_PARITY_GROUP.format(id)
        response = self.connectionManager.delete(endPoint)
        return response

    @log_entry_exit
    def delete_external_parity_group_force(self, id: int):
        endPoint = Endpoints.GET_EXTERNAL_PARITY_GROUP.format(id)
        payload = {"force": True}
        response = self.connectionManager.delete(endPoint, payload)
        return response

    @log_entry_exit
    def update_parity_group(self, spec):
        endPoint = Endpoints.GET_PARITY_GROUP.format(spec.parity_group_id)
        payload = {
            "isAcceleratedCompressionEnabled": spec.is_accelerated_compression_enabled
        }
        response = self.connectionManager.patch(endPoint, payload)
        return response

    @log_entry_exit
    def assign_parity_group_to_clpr(self, spec):
        endPoint = Endpoints.ASSIGN_PARITY.format(spec.parity_group_id)
        payload = {
            "parameters": {
                "clprId": spec.clpr_id,
            }
        }
        response = self.connectionManager.post(endPoint, payload)
        return response

    @log_entry_exit
    def get_all_drives(self):
        endPoint = Endpoints.GET_DRIVES
        drives_dict = self.connectionManager.get(endPoint)
        return drives_dict

    @log_entry_exit
    def get_one_drive(self, spec):
        endPoint = Endpoints.GET_DRIVE.format(spec.drive_location_id)
        drives_dict = self.connectionManager.get(endPoint)
        return drives_dict

    @log_entry_exit
    def change_drive_setting(self, spec):
        endPoint = Endpoints.GET_DRIVE.format(spec.drive_location_id)
        payload = {"isSpareEnabled": spec.is_spared_drive}
        response = self.connectionManager.patch(endPoint, payload)
        return response
