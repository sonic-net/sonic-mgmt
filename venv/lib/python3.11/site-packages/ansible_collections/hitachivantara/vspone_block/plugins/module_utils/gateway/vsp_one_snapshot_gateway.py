try:
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_one_snapshot_models import (
        VspOneSnapshotResponse,
        VspOneSnapshotList,
        SnapshotGroupDetailResponse,
        VspOneSnapshotGroupList,
    )
    from ..common.hv_log import Log

    from ..common.ansible_common import log_entry_exit
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway

except ImportError:
    from common.ansible_common import log_entry_exit
    from model.vsp_one_snapshot_models import (
        VspOneSnapshotResponse,
        VspOneSnapshotList,
    )
    from common.hv_log import Log
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway


GET_SNAPSHOTS_SIMPLE = "simple/v1/objects/snapshots"
GET_SNAPSHOT_BY_ID_SIMPLE = "simple/v1/objects/snapshots/{}"
CREATE_SNAPSHOT_SIMPLE = "simple/v1/objects/snapshots"
MAP_SNAPSHOT_SIMPLE = "simple/v1/objects/snapshots/{}/actions/map/invoke"
RESTORE_SNAPSHOT_SIMPLE = "simple/v1/objects/snapshots/{}/actions/restore/invoke"
DELETE_SNAPSHOT_SIMPLE = "simple/v1/objects/snapshots/{}"
SNAPSHOT_GROUPS = "simple/v1/objects/snapshot-groups"
SINGLE_SNAPSHOT_GROUP = "simple/v1/objects/snapshot-groups/{}"


logger = Log()


class VspOneSnapshotGateway:

    def __init__(self, connection_info):
        self.rest_api = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.storage_gw = VSPStorageSystemDirectGateway(connection_info)
        self.is_pegasus = self.storage_gw.is_pegasus()

    @log_entry_exit
    def get_query_parameters(self, spec):
        params = {}
        if spec.master_volume_id is not None:
            params["masterVolumeId"] = spec.master_volume_id
        if spec.snapshot_date_from is not None:
            params["snapshotDateFrom"] = spec.snapshot_date_from
        if spec.snapshot_date_to is not None:
            params["snapshotDateTo"] = spec.snapshot_date_to
        if spec.snapshot_group_name is not None:
            params["snapshotGroupName"] = spec.snapshot_group_name
        if spec.start_id is not None:
            params["startId"] = spec.start_id
        if spec.count is not None:
            params["count"] = spec.count

        query = ""
        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            query = "?" + "&".join(query_parts)

        return query

    @log_entry_exit
    def get_snapshots_information(self, spec):

        endpoint = GET_SNAPSHOTS_SIMPLE
        if spec and not spec.is_empty():
            endpoint += self.get_query_parameters(spec)
        response = self.rest_api.pegasus_get(endpoint)
        return VspOneSnapshotList().dump_to_object(response)

    @log_entry_exit
    def get_snapshot_by_id(self, snapshot_id):
        endpoint = GET_SNAPSHOT_BY_ID_SIMPLE.format(snapshot_id)
        try:
            response = self.rest_api.pegasus_get(endpoint)
            return VspOneSnapshotResponse(**response)
        except Exception as e:
            logger.writeError(f"Error getting snapshot by ID {snapshot_id}: {e}")
            return None

    @log_entry_exit
    def get_snapshot_groups(self):

        response = self.rest_api.pegasus_get(SNAPSHOT_GROUPS)
        return VspOneSnapshotGroupList().dump_to_object(response)

    @log_entry_exit
    def get_snapshot_group_by_name(
        self, group_name, start_snapshot_id=None, count=1000
    ):

        end_point = SINGLE_SNAPSHOT_GROUP.format(group_name)

        query = []
        if start_snapshot_id:
            query.append(f"startId={start_snapshot_id}")
        if count:
            query.append(f"count={count}")

        if query:
            end_point += "?" + "&".join(query)

        snapshots = None
        response = None
        try:
            response = self.rest_api.pegasus_get(end_point)
            snapshots = SnapshotGroupDetailResponse(**response)
        except Exception as e:
            logger.writeError(f"Error getting snapshot group by name {group_name}: {e}")
            return None
        if response:
            snapshots = SnapshotGroupDetailResponse(**response)

        return snapshots

    @log_entry_exit
    def delete_snapshot_group(self, group_name: str):
        end_point = SINGLE_SNAPSHOT_GROUP.format(group_name)
        self.rest_api.pegasus_delete(end_point, None)
        return True

    @log_entry_exit
    def create_snapshot(self, create_snapshot_list):
        logger.writeDebug(
            f"GW:create_snapshot:create_snapshot_list = {create_snapshot_list}"
        )
        endpoint = CREATE_SNAPSHOT_SIMPLE
        create_snapshot_list = self.convert_spec_params_to_rest_params_for_create(
            create_snapshot_list
        )
        params = {"params": create_snapshot_list}
        response = self.rest_api.pegasus_post(endpoint, data=params)
        result = self.get_snapshot_by_id(response)
        # return VspOneSnapshotList().dump_to_object(result)
        logger.writeDebug(f"GW:create_snapshots:result = {result}")
        return result

    @log_entry_exit
    def convert_spec_params_to_rest_params_for_create(self, spec_params):
        rest_params = []
        r_dict = {}
        r_dict["masterVolumeId"] = spec_params.master_volume_id
        r_dict["poolId"] = spec_params.pool_id
        r_dict["snapshotGroupName"] = spec_params.snapshot_group_name
        r_dict["type"] = spec_params.type
        rest_params.append(r_dict)
        return rest_params

    @log_entry_exit
    def map_snapshot(self, master_volume_id, snapshot_id, pool_id):
        object_id = f"{master_volume_id},{snapshot_id}"
        params = {"poolId": pool_id}
        end_point = MAP_SNAPSHOT_SIMPLE.format(object_id)
        response = self.rest_api.pegasus_post(end_point, data=params)
        result = self.get_snapshot_by_id(response)
        logger.writeDebug(f"GW:map_snapshot:result = {result}")
        return result

    @log_entry_exit
    def restore_snapshot(self, master_volume_id, snapshot_id):
        object_id = f"{master_volume_id},{snapshot_id}"
        end_point = RESTORE_SNAPSHOT_SIMPLE.format(object_id)
        response = self.rest_api.pegasus_post(end_point, data=None)
        result = self.get_snapshot_by_id(response)
        logger.writeDebug(f"GW:restore_snapshot:result = {result}")
        return result

    @log_entry_exit
    def delete_snapshot(self, master_volume_id, snapshot_id):
        object_id = f"{master_volume_id},{snapshot_id}"
        end_point = DELETE_SNAPSHOT_SIMPLE.format(object_id)
        response = self.rest_api.pegasus_delete(end_point, data=None)
        result = self.get_snapshot_by_id(response)
        logger.writeDebug(f"GW:delete_snapshot:result = {result}")
        return result
