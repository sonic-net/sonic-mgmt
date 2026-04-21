from typing import Optional, Dict, Any

try:
    from ..common.ansible_common import dicts_to_dataclass_list
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_snapshot_models import (
        DirectSnapshotsInfo,
        DirectSnapshotInfo,
        SnapshotGroups,
        SnapshotGroupInfo,
    )
    from ..common.hv_log import Log
    from ..common.hv_log_decorator import LogDecorator
    from ..common.vsp_constants import Endpoints as DirectEndPoints
    from ..common.vsp_constants import VSPSnapShotReq
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway
except ImportError:
    from common.ansible_common import dicts_to_dataclass_list
    from .gateway_manager import VSPConnectionManager
    from model.vsp_snapshot_models import (
        DirectSnapshotsInfo,
        DirectSnapshotInfo,
        SnapshotGroups,
        SnapshotGroupInfo,
    )
    from common.hv_log import Log
    from common.hv_log_decorator import LogDecorator
    from common.vsp_constants import Endpoints as DirectEndPoints
    from common.vsp_constants import VSPSnapShotReq
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway


COPY_SPEED_CONST = {
    "SLOW": "slower",
    "FAST": "faster",
    "MEDIUM": "medium",
}


@LogDecorator.debug_methods
class VSPHtiSnapshotDirectGateway:
    def __init__(self, connection_info):
        self.logger = Log()
        self.rest_api = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.end_points = DirectEndPoints
        self.pegasus_model = None
        self.connection_info = connection_info

    def is_pegasus(self):
        if self.pegasus_model is None:
            storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
            self.pegasus_model = storage_gw.is_pegasus()
        return self.pegasus_model

    def get_all_snapshots(
        self, pvol: Optional[int] = None, mirror_unit_id: Optional[int] = None
    ) -> DirectSnapshotsInfo:
        pegasus_model = self.is_pegasus()
        if pegasus_model and not pvol:
            return self._get_pegasus_snapshots()
        else:
            return self._get_all_snapshots_pf_rest(pvol, mirror_unit_id)

    def _get_pegasus_snapshots(self):
        groups = self.rest_api.get(self.end_points.GET_SNAPSHOT_GROUPS)
        snapshots_lists = []
        for grp in groups["data"]:
            snapshots = self.rest_api.get(
                self.end_points.GET_SNAPSHOT_GROUPS_ONE.format(grp["snapshotGroupId"])
            )["snapshots"]
            snapshots_lists.extend(snapshots)

        return DirectSnapshotsInfo(
            dicts_to_dataclass_list(snapshots_lists, DirectSnapshotInfo)
        )

    def _get_all_snapshots_pf_rest(
        self, pvol: Optional[int] = None, mirror_unit_id: Optional[int] = None
    ) -> DirectSnapshotsInfo:
        if pvol and mirror_unit_id:
            object_id = f"pvolLdevId={pvol}&muNumber={mirror_unit_id}"
        elif pvol:
            object_id = f"pvolLdevId={pvol}"
        elif mirror_unit_id:
            object_id = f"muNumber={mirror_unit_id}"
        else:
            object_id = ""

        end_point = (
            self.end_points.GET_SNAPSHOTS_QUERY.format(
                object_id + "&detailInfoType=retention"
            )
            if object_id
            else self.end_points.ALL_SNAPSHOTS
        )
        snapshots = self.rest_api.get(end_point)
        return DirectSnapshotsInfo(
            dicts_to_dataclass_list(snapshots["data"], DirectSnapshotInfo)
        )

    def get_one_snapshot(self, pvol: int, mirror_unit_id: int) -> DirectSnapshotInfo:
        object_id = f"{pvol},{mirror_unit_id}"
        end_point = self.end_points.GET_ONE_SNAPSHOTS.format(object_id)
        snapshot = self.rest_api.get(end_point)
        return DirectSnapshotInfo(**snapshot)

    def get_snapshot_by_pvol(self, pvol: int) -> DirectSnapshotsInfo:
        query = f"pvolLdevId={pvol}"
        end_point = self.end_points.GET_SNAPSHOTS_QUERY.format(query)
        snapshots = self.rest_api.get(end_point)
        return DirectSnapshotsInfo(
            dicts_to_dataclass_list(snapshots["data"], DirectSnapshotInfo)
        )

    def delete_snapshot(self, pvol: int, mirror_unit_id: int) -> Dict[str, Any]:
        object_id = f"{pvol},{mirror_unit_id}"
        end_point = self.end_points.GET_ONE_SNAPSHOTS.format(object_id)
        return self.rest_api.delete(end_point)

    def set_snapshot_retention_period(self, snapshot_id, retention_period: int):
        end_point = self.end_points.SNAPSHOT_RETENTION.format(snapshot_id)
        payload = {
            VSPSnapShotReq.parameters: {
                VSPSnapShotReq.retentionPeriod: retention_period,
            }
        }
        return self.rest_api.post(end_point, data=payload)

    def set_snapshot_retention_period_for_group(
        self, group_id: str, retention_period: int
    ):
        end_point = self.end_points.SNAPSHOT_RETENTION_BY_GRP.format(group_id)

        payload = {
            VSPSnapShotReq.parameters: {
                VSPSnapShotReq.retentionPeriod: retention_period,
            }
        }
        return self.rest_api.post(end_point, data=payload)

    def split_snapshot(self, pvol: int, mirror_unit_id: int, *args) -> Dict[str, Any]:
        return self._snapshot_action(
            pvol, mirror_unit_id, self.end_points.POST_SNAPSHOTS_SPLIT, data=None
        )

    def clone_snapshot(
        self, pvol: int, mirror_unit_id: int, copy_speed=None, *args
    ) -> Dict[str, Any]:
        self.logger.writeDebug("clone_snapshot direct")
        payload = None
        if copy_speed is not None:
            payload = {
                VSPSnapShotReq.parameters: {
                    VSPSnapShotReq.copySpeed: COPY_SPEED_CONST.get(copy_speed.upper())
                }
            }
        return self._snapshot_action(
            pvol, mirror_unit_id, self.end_points.POST_SNAPSHOTS_CLONE, data=payload
        )

    def assign_svol_to_snapshot(
        self, pvol: int, mirror_unit_id: int, svol: int, *args
    ) -> Dict[str, Any]:

        payload = {VSPSnapShotReq.parameters: {VSPSnapShotReq.svolLdevId: svol}}
        return self._snapshot_action(
            pvol, mirror_unit_id, self.end_points.POST_SNAPSHOTS_SVOL_ADD, data=payload
        )

    def unassign_svol_to_snapshot(
        self, pvol: int, mirror_unit_id: int, *args
    ) -> Dict[str, Any]:
        return self._snapshot_action(
            pvol, mirror_unit_id, self.end_points.POST_SNAPSHOTS_SVOL_REMOVE, data=None
        )

    def resync_snapshot(self, pvol: int, mirror_unit_id: int, *args) -> Dict[str, Any]:
        return self._snapshot_action(
            pvol, mirror_unit_id, self.end_points.POST_SNAPSHOTS_RESYNC, data=None
        )

    # Snapshot group related methods
    def get_snapshot_groups(self) -> Dict[str, Any]:
        ssgs = self.rest_api.get(self.end_points.GET_SNAPSHOT_GROUPS)
        return SnapshotGroups().dump_to_object(ssgs)

    def get_snapshots_using_group_id(self, gid):
        snapshots = None
        try:
            snapshots = self.rest_api.get(
                self.end_points.SNAPSHOTS_BY_GROUP_ID_WITH_RETAIN.format(gid)
            )
        except Exception as e:
            snapshots = self.rest_api.get(
                self.end_points.SNAPSHOTS_BY_GROUP_ID.format(gid)
            )
        # snapshots=  DirectSnapshotsInfo().dump_to_object({"data": ss["snapshots"]})
        # sng_grps.snapshots = snapshots.data
        sng_grps = SnapshotGroupInfo(**snapshots)
        return sng_grps

    def split_snapshot_using_ssg(self, group_id: int, *args) -> Dict[str, Any]:
        end_point = self.end_points.SPLIT_SNAPSHOT_BY_GRP.format(group_id)
        return self.rest_api.post(end_point, data=None)

    def clone_snapshot_using_ssg(
        self, group_id: int, copy_speed: str, *args
    ) -> Dict[str, Any]:
        end_point = self.end_points.CLONE_SNAPSHOT_BY_GRP.format(group_id)
        payload = None
        if copy_speed is not None:
            payload = {
                VSPSnapShotReq.parameters: {
                    VSPSnapShotReq.copySpeed: COPY_SPEED_CONST.get(copy_speed.upper())
                }
            }
        return self.rest_api.post(end_point, payload)

    def delete_garbage_data_snapshot_tree(
        self, primary_volume_id: int, operation_type: str, *args
    ) -> Dict[str, Any]:
        end_point = self.end_points.DELETE_GARBAGE_DATA
        payload = {
            VSPSnapShotReq.parameters: {
                VSPSnapShotReq.primaryLdevId: primary_volume_id,
                VSPSnapShotReq.operationType: operation_type,
            }
        }
        return self.rest_api.post(end_point, payload)

    def restore_snapshot_using_ssg(self, group_id: int, auto_split) -> Dict[str, Any]:
        payload = None
        if auto_split:
            payload = {}
            payload["parameters"] = {"autoSplit": auto_split}

        end_point = self.end_points.RESTORE_SNAPSHOT_BY_GRP.format(group_id)
        return self.rest_api.post(end_point, data=payload)

    def resync_snapshot_using_ssg(self, group_id: int, *args) -> Dict[str, Any]:
        end_point = self.end_points.RESYNC_SNAPSHOT_BY_GRP.format(group_id)
        return self.rest_api.post(end_point, data=None)

    def delete_snapshot_using_ssg(self, group_id: int, *args) -> Dict[str, Any]:
        end_point = self.end_points.SNAPSHOTS_BY_GROUP_ID.format(group_id)
        return self.rest_api.delete(end_point)

    def restore_snapshot(
        self, pvol: int, mirror_unit_id: int, auto_split: bool = False, **args
    ) -> Dict[str, Any]:
        return self._snapshot_action(
            pvol,
            mirror_unit_id,
            self.end_points.POST_SNAPSHOTS_RESTORE,
            auto_split=auto_split,
            data=None,
        )

    def create_snapshot(
        self,
        pvol: int,
        poolId: int,
        allocate_consistency_group: bool,
        snapshot_group_name: str,
        auto_split: bool,
        is_data_reduction_force_copy: bool,
        can_cascade: bool,
        svol: int,
        is_clone: bool,
        mirror_unit_id: int,
        retention_period: Optional[int] = None,
        copy_speed: Optional[str] = None,
        clones_automation: Optional[bool] = None,
    ) -> Dict[str, Any]:

        end_point, payload, pegasus_model = self._get_snapshot_payload(
            pvol,
            poolId,
            allocate_consistency_group,
            snapshot_group_name,
            auto_split,
            is_data_reduction_force_copy,
            can_cascade,
            svol,
            is_clone,
            mirror_unit_id,
            retention_period,
            copy_speed,
            clones_automation,
        )

        if pegasus_model:
            return self.rest_api.pegasus_post(end_point, payload)

        self.logger.writeDebug(f"Create Snapshot payload: {payload}")
        return self.rest_api.post(end_point, payload)

    def _snapshot_action(
        self,
        pvol: int,
        mirror_unit_id: int,
        end_point_template: str,
        auto_split: bool = False,
        data=None,
    ):
        # payload = None if not auto_split else {"parameters": {"autoSplit": auto_split}}
        object_id = f"{pvol},{mirror_unit_id}"
        end_point = end_point_template.format(object_id)
        return self.rest_api.post(end_point, data)

    def _get_snapshot_payload(
        self,
        pvol: int,
        poolId: int,
        allocate_consistency_group: bool,
        snapshot_group_name: str,
        auto_split: bool,
        is_data_reduction_force_copy: bool,
        can_cascade: bool,
        svol: int,
        is_clone: bool,
        mirror_unit_id: int,
        retention_period: int,
        copy_speed: Optional[str] = None,
        clones_automation: Optional[bool] = None,
    ):

        end_point = self.end_points.SNAPSHOTS
        payload = {
            VSPSnapShotReq.pvolLdevId: pvol,
            VSPSnapShotReq.snapshotPoolId: poolId,
            VSPSnapShotReq.snapshotGroupName: snapshot_group_name,
        }
        if auto_split is not None:
            payload[VSPSnapShotReq.autoSplit] = auto_split

        if is_data_reduction_force_copy:
            payload[VSPSnapShotReq.isDataReductionForceCopy] = (
                is_data_reduction_force_copy
            )

        if mirror_unit_id is not None:
            payload[VSPSnapShotReq.muNumber] = mirror_unit_id
        if can_cascade is not None:
            payload[VSPSnapShotReq.canCascade] = can_cascade
        if svol is not None and svol != -1:
            payload[VSPSnapShotReq.svolLdevId] = svol
        if allocate_consistency_group is not None:
            payload[VSPSnapShotReq.isConsistencyGroup] = allocate_consistency_group
        if is_clone is not None:
            payload[VSPSnapShotReq.isClone] = is_clone
            if is_clone:
                payload[VSPSnapShotReq.canCascade] = True

        if retention_period is not None:
            pegasus_model = self.is_pegasus()
            if pegasus_model:
                payload[VSPSnapShotReq.retentionPeriod] = retention_period

        if copy_speed is not None:
            payload[VSPSnapShotReq.copySpeed] = COPY_SPEED_CONST.get(copy_speed.upper())

        if clones_automation is not None:
            payload[VSPSnapShotReq.clonesAutomation] = clones_automation

        return end_point, payload, False

    def delete_ti_by_snapshot_tree(
        self, primary_volume_id: int, *args
    ) -> Dict[str, Any]:
        end_point = self.end_points.DELETE_TI_BY_SS_TREE
        payload = {
            VSPSnapShotReq.parameters: {
                VSPSnapShotReq.primaryLdevId: primary_volume_id,
            }
        }
        return self.rest_api.post(end_point, payload)
