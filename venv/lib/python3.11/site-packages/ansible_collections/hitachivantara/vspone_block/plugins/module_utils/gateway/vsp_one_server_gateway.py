from .gateway_manager import VSPConnectionManager
from ..common.vsp_constants import (
    Endpoints,
    ServerPayloadConst,
)
from ..model.vsp_one_server_models import (
    VspOneServerResponse,
    VspOneServerList,
    CreateServerSpec,
    IscsiTargetList,
    VspOneServerPathSpec,
    VspOneServerHBAList,
    VspOneServerHBAResponse,
)
from ..common.hv_log import Log

from ..common.ansible_common import log_entry_exit
from ..common.vsp_constants import PEGASUS_MODELS
from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway

logger = Log()


class VspServerSimpleApiGateway:
    """
    VspSimpleApiGateway
    """

    def __init__(self, connection_info):
        self.rest_api = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.storage_gw = VSPStorageSystemDirectGateway(connection_info)
        self.end_points = Endpoints
        self.is_pegasus = self.get_storage_details()

    @log_entry_exit
    def get_storage_details(self):
        storage_info = self.storage_gw.get_current_storage_system_info()
        pegasus_model = any(sub in storage_info.model for sub in PEGASUS_MODELS)
        logger.writeDebug(f"Storage Model: {storage_info.model}")
        return pegasus_model

    @log_entry_exit
    def get_all_servers_with_filter(
        self, nick_name=None, hba_wwn=None, iscsi_name=None, include_details=False
    ) -> VspOneServerList:
        """
        Get all servers
        """
        end_point = self.end_points.GET_SIMPLE_SERVER_INFO
        query_params = []
        if nick_name:
            query_params.append(f"nickname={nick_name}")
        if hba_wwn:
            query_params.append(f"hbaWwn={hba_wwn}")
        if iscsi_name:
            query_params.append(f"iscsiName={iscsi_name}")
        if query_params:
            query_string = "&".join(query_params)
            end_point = self.end_points.GET_SIMPLE_SERVER_INFO_QUERY.format(
                query_string
            )
            logger.writeDebug(f"Querying servers with: {end_point}")
        response = self.rest_api.pegasus_get(end_point)

        server_objects = VspOneServerList().dump_to_object(response)

        if include_details:
            for index, server in enumerate(server_objects.data):
                server_object = self.get_server_by_id_with_details(server.id)
                server_objects.data[index] = server_object
        return server_objects

    @log_entry_exit
    def get_server_by_id(self, server_id) -> VspOneServerResponse:
        """
        Get single server
        """
        try:
            response = self.rest_api.pegasus_get(
                self.end_points.GET_SINGLE_SIMPLE_SERVER.format(server_id)
            )
            return VspOneServerResponse(**response)
        except Exception as ex:
            logger.writeError(f"Error getting server with ID {server_id}: {ex}")
            # Return an empty VspOneServerResponse object in case of error
            return None

    @log_entry_exit
    def get_server_by_id_with_details(self, server_id) -> VspOneServerResponse:
        """
        Get single server
        """
        server = None
        try:
            response = self.rest_api.pegasus_get(
                self.end_points.GET_SINGLE_SIMPLE_SERVER.format(server_id)
            )
            server = VspOneServerResponse(**response)
        except Exception as ex:
            logger.writeError(f"Error getting server with ID {server_id}: {ex}")
            # Return an empty VspOneServerResponse object in case of error
            return None

        iscsi_targets = self.get_iscsi_targets(server_id)
        server.iscsiTargets = iscsi_targets.data
        return server

    @log_entry_exit
    def get_iscsi_targets(self, server_id: int) -> IscsiTargetList:
        """
        Get iSCSI targets for a server
        """
        response = self.rest_api.pegasus_get(
            self.end_points.GET_ALL_SERVER_ISCSI.format(server_id)
        )
        logger.writeDebug(f"iSCSI Targets Response: {response}")
        return IscsiTargetList().dump_to_object(response)

    @log_entry_exit
    def register_server(self, spec: CreateServerSpec) -> VspOneServerResponse:
        """
        Register a server
        """

        response = self.rest_api.pegasus_post(
            self.end_points.GET_SIMPLE_SERVER_INFO, spec.generate_create_payload()
        )
        return response

    @log_entry_exit
    def change_server_settings(
        self, server_id: int, spec: CreateServerSpec
    ) -> VspOneServerResponse:
        """
        Change server settings
        """
        payload = spec.generate_server_settings_payload()
        if not payload:
            return None  # No changes to be made
        response = self.rest_api.pegasus_patch(
            self.end_points.GET_SINGLE_SIMPLE_SERVER.format(server_id), payload
        )
        return response

    @log_entry_exit
    def delete_server(
        self, server_id: int, spec: CreateServerSpec
    ) -> VspOneServerResponse:
        """
        Change server settings
        """
        payload = None
        if spec.keep_lun_config is not None:
            payload = {}
            payload["keepLunConfig"] = spec.keep_lun_config

        response = self.rest_api.pegasus_delete(
            self.end_points.GET_SINGLE_SIMPLE_SERVER.format(server_id), payload
        )
        return response

    @log_entry_exit
    def add_hg_to_server(self, server_id: int, spec: CreateServerSpec):
        """
        Add host group to server
        """
        logger.writeDebug(f"Adding host groups to spec.host_groups {spec.host_groups}")
        payload = {"hostGroups": []}
        if spec.host_groups is not None:
            for hg in spec.host_groups:
                obj = {ServerPayloadConst.portId: hg.port_id}
                if hg.host_group_id is not None:
                    obj[ServerPayloadConst.hostGroupId] = hg.host_group_id
                if hg.host_group_name is not None:
                    obj[ServerPayloadConst.hostGroupName] = hg.host_group_name
                payload["hostGroups"].append(obj)
        if spec.iscsi_targets is not None:
            for it in spec.iscsi_targets:
                obj = {ServerPayloadConst.portId: it.port_id}
                if it.iscsi_target_name is not None:
                    obj[ServerPayloadConst.hostGroupName] = it.iscsi_target_name
                if it.iscsi_target_id is not None:
                    obj[ServerPayloadConst.hostGroupId] = it.iscsi_target_id
                payload["hostGroups"].append(obj)

        response = self.rest_api.pegasus_post(
            self.end_points.ADD_HG_TO_SERVER.format(server_id), payload
        )
        return response

    @log_entry_exit
    def add_path_to_server(self, server_id: int, path: VspOneServerPathSpec):
        """
        Add path to server
        """
        payload = {ServerPayloadConst.portIds: path.port_ids}
        if path.iscsi_name is not None:
            payload[ServerPayloadConst.iscsiName] = path.iscsi_name
        if path.hba_wwn is not None:
            payload[ServerPayloadConst.hbaWwn] = path.hba_wwn

        response = self.rest_api.pegasus_post(
            self.end_points.ADD_PATH_TO_SERVER.format(server_id), payload
        )
        return response

    @log_entry_exit
    def remove_path_from_server(
        self, server_id: int, port_id: int, iscsi_name: str = None, hba_wwn: str = None
    ):
        """
        Remove path from server
        """
        object_id = None
        if iscsi_name is not None:
            object_id = f"{iscsi_name},{port_id}"
        elif hba_wwn is not None:
            object_id = f"{hba_wwn},{port_id}"

        response = self.rest_api.pegasus_delete(
            self.end_points.SINGLE_SERVER_PATH.format(server_id, object_id), None
        )
        return response

    @log_entry_exit
    def sync_server_nick_name(self, server_id: int):
        """
        Sync server nick name
        """
        response = self.rest_api.pegasus_post(
            self.end_points.SYNC_HG_TO_SERVER_NICKNAME.format(server_id), None
        )
        return response

    @log_entry_exit
    def add_wwn_of_hba(self, spec: CreateServerSpec):
        """
        Add WWN of HBA
        """
        payload = {ServerPayloadConst.hbas: []}

        for object in spec.hbas:
            if object.iscsi_name is not None:
                payload[ServerPayloadConst.hbas].append(
                    {ServerPayloadConst.iscsiName: object.iscsi_name}
                )
            if object.hba_wwn is not None:
                payload[ServerPayloadConst.hbas].append(
                    {ServerPayloadConst.hbaWwn: object.hba_wwn}
                )

        response = self.rest_api.pegasus_post(
            self.end_points.ADD_WWN_OF_HBA.format(spec.server_id), payload
        )
        return response

    @log_entry_exit
    def remove_wwn_of_hba(self, server_id: int, wwn_or_iscsi: str):
        """
        Remove WWN of HBA
        """
        response = self.rest_api.pegasus_delete(
            self.end_points.SINGLE_WWN_OF_HBA_PER_SERVER.format(
                server_id, wwn_or_iscsi
            ),
            None,
        )
        return response

    @log_entry_exit
    def change_iscsi_target_settings(
        self, server_id: int, port_id: int, iscsi_target_name: str
    ):
        """
        Change iSCSI target settings
        """
        payload = {}
        if iscsi_target_name is not None:
            payload[ServerPayloadConst.targetIscsiName] = iscsi_target_name

        if not payload:
            return None  # No changes to be made

        response = self.rest_api.pegasus_patch(
            self.end_points.ISCSI_TARGET_SETTINGS.format(server_id, port_id), payload
        )
        return response

    @log_entry_exit
    def get_hbas_by_server_id(self, server_id):
        """
        Get HBAs for a server
        """
        response = self.rest_api.pegasus_get(
            self.end_points.GET_WWN_OF_HBA.format(server_id)
        )
        logger.writeDebug(f"HBA Response: {response}")
        return VspOneServerHBAList().dump_to_object(response)

    @log_entry_exit
    def get_hba_by_wwn(self, server_id, hba_name: str):
        """
        Get HBA by WWN
        """
        response = self.rest_api.pegasus_get(
            self.end_points.SINGLE_WWN_OF_HBA_PER_SERVER.format(server_id, hba_name)
        )
        logger.writeDebug(f"HBA by WWN Response: {response}")
        return VspOneServerHBAResponse(**response)
