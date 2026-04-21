try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_constants import SDSBlockEndpoints
    from ..model.sdsb_snapshot_models import (
        MasterVolumeResponseModel,
        SnapShotsResponseModel,
    )
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common import log_entry_exit
    from model.sdsb_snapshot_models import (
        MasterVolumeResponseModel,
        SnapShotsResponseModel,
    )


OPERATION_TYPE_MAP = {
    "prepare": "Prepare",
    "finalize": "Finalize",
    "prepare_and_finalize": "PrepareAndFinalize",
}


class SnapshotsGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_master_volume(self, volume_id):

        url = SDSBlockEndpoints.GET_MASTER_VOLUME.format(volume_id)
        try:
            response = self.connection_manager.get(url)
            return MasterVolumeResponseModel(**response)
        except Exception as e:
            # Handle exceptions
            return

    @log_entry_exit
    def get_snapshot_volumes(self, volume_id, vps_id=None):
        """
        Get all snapshots.
        """
        url = SDSBlockEndpoints.GET_SNAPSHOTS_VOLUMES.format(volume_id)
        if vps_id:
            url = url + f"?vpsId={vps_id}"
        response = self.connection_manager.get(url)
        return SnapShotsResponseModel().dump_to_object(response)

    @log_entry_exit
    def create_snapshot(self, spec):
        """
        Create a snapshot for the specified volume.
        """
        payload = {}
        if spec.name:
            payload["name"] = spec.name
        if spec.master_volume_id is not None:
            payload["masterVolumeId"] = spec.master_volume_id

        if spec.snapshot_volume_id is not None:
            payload["snapshotVolumeId"] = spec.snapshot_volume_id

        if spec.operation_type is not None:
            payload["operationType"] = OPERATION_TYPE_MAP.get(spec.operation_type)
        if spec.vps_id is not None:
            payload["vpsId"] = spec.vps_id

        if spec.qos:
            qos_payload = {
                "upperLimitForIops": spec.qos.upper_limit_for_iops,
                "upperLimitForTransferRate": spec.qos.upper_limit_for_transfer_rate,
                "upperAlertAllowableTime": spec.qos.upper_alert_allowable_time,
            }
            payload["qosParam"] = qos_payload
        url = SDSBlockEndpoints.CREATE_SNAPSHOT
        response = self.connection_manager.post(url, data=payload)
        return response

    @log_entry_exit
    def delete_snapshot(self, spec):
        """
        Delete a snapshot by its ID.
        """

        url = SDSBlockEndpoints.DELETE_SNAPSHOT
        payload = {}

        if spec.master_volume_id is not None:
            payload["masterVolumeId"] = spec.master_volume_id
            payload["snapshotTree"] = True
        elif spec.snapshot_volume_id is not None:
            payload["snapshotVolumeId"] = spec.snapshot_volume_id
        if spec.vps_id is not None:
            payload["vpsId"] = spec.vps_id

        response = self.connection_manager.post(url, data=payload)
        return response

    @log_entry_exit
    def restore_snapshot(self, spec):
        """
        Restore a snapshot by its ID.
        """
        url = SDSBlockEndpoints.RESTORE_SNAPSHOT
        payload = {}
        if spec.snapshot_volume_id is not None:
            payload["snapshotVolumeId"] = spec.snapshot_volume_id
        if spec.vps_id is not None:
            payload["vpsId"] = spec.vps_id
        response = self.connection_manager.post(url, data=payload)
        return response
