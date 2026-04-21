try:

    from ..common.ansible_common import log_entry_exit
    from ..gateway.sdsb_snapshots_gateway import SnapshotsGateway
    from ..model.sdsb_snapshot_models import SDSBSnapshotSpec
    from ..gateway.sdsb_volume_gateway import SDSBVolumeDirectGateway
    from .sdsb_vps_provisioner import SDSBVpsProvisioner
    from ..common.hv_log import Log
    from ..message.sdsb_snapshot_msgs import SDSSnapShotsMsgs
    from ..common.hv_constants import StateValue


except ImportError:

    from common.ansible_common import log_entry_exit
    from gateway.sdsb_snapshots_gateway import SnapshotsGateway
    from model.sdsb_snapshot_models import SDSBSnapshotSpec
    from gateway.sdsb_volume_gateway import SDSBVolumeDirectGateway
    from provisioner.sdsb_vps_provisioner import SDSBVpsProvisioner
    from common.hv_log import Log
    from message.sdsb_snapshot_msgs import SDSSnapShotsMsgs
    from common.hv_constants import StateValue


logger = Log()


class SDSBSnapshotProvisioner:
    """
    Provisioner for SDSB snapshots.
    This class handles the creation and management of snapshots for SDSB volumes.
    """

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.gateway = SnapshotsGateway(connection_info=connection_info)
        self.volume_gateway = SDSBVolumeDirectGateway(connection_info=connection_info)
        self.vps_prov = SDSBVpsProvisioner(connection_info=connection_info)

    @log_entry_exit
    def prepare_snapshot_info(self, spec: SDSBSnapshotSpec, state: str):
        """
        Prepare the snapshot specification.
        """

        # Only one of the four (master_volume_id, master_volume_name, snapshot_volume_id, snapshot_volume_name) can be provided at a time
        provided = [
            spec.master_volume_id is not None,
            spec.master_volume_name is not None,
            spec.snapshot_volume_id is not None,
            spec.snapshot_volume_name is not None,
        ]
        if sum(provided) != 1:
            raise ValueError(SDSSnapShotsMsgs.ALL_VALUES_NOT_BE_PRESENT.value)

        if spec.name is not None and (
            spec.snapshot_volume_id is not None or spec.snapshot_volume_name
        ):
            raise ValueError(SDSSnapShotsMsgs.NAME_SNAPSHOT_VOLUME.value)

        if (
            (
                spec.snapshot_volume_id is not None
                or spec.snapshot_volume_name is not None
            )
            and spec.operation_type is None
            and state == StateValue.PRESENT
        ):
            raise ValueError(SDSSnapShotsMsgs.SNAPSHOT_VOLUME_OPERATION_TYPE.value)

        if spec.master_volume_id is None and spec.master_volume_name is not None:
            vol = self.volume_gateway.get_volume_by_name(spec.master_volume_name)
            if vol:
                spec.master_volume_id = vol.id
            else:
                raise ValueError(
                    SDSSnapShotsMsgs.MASTER_VOLUME_NAME_NOT_FOUND.value.format(
                        spec.master_volume_name
                    )
                )

        if spec.snapshot_volume_id is None and spec.snapshot_volume_name is not None:
            vol = self.volume_gateway.get_volume_by_name(spec.snapshot_volume_name)
            # If snapshot_volume_name is provided, it should be a valid snapshot volume
            if vol:
                spec.snapshot_volume_id = vol.id
            else:
                raise ValueError(
                    SDSSnapShotsMsgs.SNAPSHOT_VOLUME_NAME_NOT_FOUND.value.format(
                        spec.snapshot_volume_name
                    )
                )

        if spec.vps_id is None and spec.vps_name is not None:
            vps = self.vps_prov.get_vps_by_name(spec.vps_name)
            if vps:
                spec.vps_id = vps.id
            else:
                raise ValueError(
                    SDSSnapShotsMsgs.VPS_NAME_NOT_FOUND.value.format(spec.vps_name)
                )

        snapshot = self.query_snapshot(
            spec.name,
            spec.master_volume_id if spec.master_volume_id else None,
            (spec.snapshot_volume_id if spec.snapshot_volume_id else None),
            (spec.vps_id if spec.vps_id else None),
        )
        if snapshot:
            spec.snapshot_volume_id = snapshot.snapshotVolumeId
            spec.snapshot_volume_name = snapshot.snapshotVolumeName

        return snapshot

    @log_entry_exit
    def create_snapshot(self, spec: SDSBSnapshotSpec):
        """
        Create a snapshot based on the provided specification.
        """

        unused = self.gateway.create_snapshot(spec)
        if spec.snapshot_volume_id is not None:
            master_volume = self.gateway.get_master_volume(spec.snapshot_volume_id)
            spec.master_volume_id = master_volume.masterVolumeId

        snapshot = self.query_snapshot(
            snapshot_name=spec.name,
            volume_id=spec.master_volume_id if spec.master_volume_id else None,
            snapshot_id=spec.snapshot_volume_id if spec.snapshot_volume_id else None,
            vps_id=spec.vps_id if spec.vps_id else None,
        )
        self.connection_info.changed = True
        return snapshot, SDSSnapShotsMsgs.SNAPSHOT_CREATED.value

    @log_entry_exit
    def restore_snapshot(self, spec: SDSBSnapshotSpec):
        """
        Restore a snapshot based on the provided specification.
        """
        response = self.gateway.restore_snapshot(spec)
        snapshot = self.query_snapshot(
            snapshot_name=spec.name,
            volume_id=spec.master_volume_id,
            snapshot_id=spec.snapshot_volume_id,
            vps_id=spec.vps_id if spec.vps_id else None,
        )
        self.connection_info.changed = True
        return snapshot, SDSSnapShotsMsgs.RESTORE_MSG.value

    @log_entry_exit
    def delete_snapshot(self, spec: SDSBSnapshotSpec):
        """
        Delete a snapshot based on the provided specification.
        """
        response = self.gateway.delete_snapshot(spec)
        self.connection_info.changed = True

        return None, SDSSnapShotsMsgs.DELETE_MSG.value

    @log_entry_exit
    def query_snapshot(
        self, snapshot_name: str, volume_id, snapshot_id=None, vps_id=None
    ):
        """
        Get a snapshot by its name.
        """
        if not volume_id:
            master_vol = self.gateway.get_master_volume(snapshot_id)
            if master_vol:
                volume_id = master_vol.masterVolumeId
        try:
            snapshots = self.gateway.get_snapshot_volumes(volume_id, vps_id)
        except Exception as e:
            logger.writeDebug(f"Error: {e}")
            raise ValueError(
                SDSSnapShotsMsgs.SNAPSHOT_VOLUME_NOT_FOUND.value.format(volume_id)
            )
        # snapshots = self.gateway.get_snapshot_volumes(volume_id, vps_id)

        if snapshot_name is None and snapshot_id is None:
            return snapshots.data[0] if snapshots.data else None

        for snapshot in snapshots.data:
            if (
                snapshot_name is not None
                and snapshot.snapshotVolumeName == snapshot_name
            ) or (snapshot_id and snapshot.snapshotVolumeId == snapshot_id):
                return snapshot

        return None

    @log_entry_exit
    def snapshot_facts_query(self, spec: SDSBSnapshotSpec):
        """
        Retrieve snapshot facts based on the provided specification.
        """

        provided = [
            spec.master_volume_id is not None,
            spec.master_volume_name is not None,
            spec.snapshot_volume_id is not None,
            spec.snapshot_volume_name is not None,
        ]
        if sum(provided) != 1:
            raise ValueError(SDSSnapShotsMsgs.ALL_VALUES_NOT_BE_PRESENT.value)

        if spec.master_volume_id is None and spec.master_volume_name is not None:
            vol = self.volume_gateway.get_volume_by_name(spec.master_volume_name)
            if vol:
                spec.master_volume_id = vol.id
            else:
                return SDSSnapShotsMsgs.MASTER_VOLUME_NAME_NOT_FOUND.value.format(
                    spec.master_volume_name
                )
        if spec.snapshot_volume_id is not None or spec.snapshot_volume_name is not None:

            if spec.snapshot_volume_name is not None:
                volume = self.volume_gateway.get_volume_by_name(
                    spec.snapshot_volume_name
                )
                if volume is None:
                    return SDSSnapShotsMsgs.SNAPSHOT_VOLUME_NAME_NOT_FOUND.value.format(
                        spec.snapshot_volume_name
                    )
                spec.snapshot_volume_id = volume.id
            master_volume = self.gateway.get_master_volume(spec.snapshot_volume_id)
            if master_volume:
                spec.master_volume_id = master_volume.masterVolumeId
            else:
                return SDSSnapShotsMsgs.SNAPSHOT_NOT_FOUND.value
        try:
            snapshots = self.gateway.get_snapshot_volumes(
                spec.master_volume_id, spec.vps_id
            )
        except Exception as e:
            logger.writeDebug(f"Error: {e}")
            raise ValueError(
                SDSSnapShotsMsgs.SNAPSHOT_VOLUME_NOT_FOUND.value.format(
                    spec.master_volume_id
                )
            )
        if snapshots is None:
            return SDSSnapShotsMsgs.SNAPSHOT_VOLUME_NOT_FOUND.value.format(
                spec.master_volume_id
            )
        if spec.snapshot_volume_id is None and spec.snapshot_volume_name is None:
            return snapshots.data_to_snake_case_list()

        for snapshot in snapshots.data:
            if (
                spec.snapshot_volume_id
                and snapshot.snapshotVolumeId == spec.snapshot_volume_id
            ) or (
                spec.snapshot_volume_name
                and snapshot.snapshotVolumeName == spec.snapshot_volume_name
            ):
                return snapshot.camel_to_snake_dict()
