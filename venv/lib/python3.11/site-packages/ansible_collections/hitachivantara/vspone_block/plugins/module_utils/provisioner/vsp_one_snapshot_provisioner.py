import re
from ..common.ansible_common import log_entry_exit
from ..common.hv_log import (
    Log,
)
from ..gateway.vsp_one_snapshot_gateway import VspOneSnapshotGateway
from ..gateway.vsp_volume_simple_api_gateway import VspSimpleApiGateway
from ..message.vsp_lun_msgs import VSPVolumeMSG
from ..model.vsp_one_snapshot_models import VspOneSnapshotList

logger = Log()


class VspOneSnapshotProvisioner:

    def __init__(self, connection_info):
        self.gateway = VspOneSnapshotGateway(connection_info)
        self.volume_gw = VspSimpleApiGateway(connection_info)
        self.connection_info = connection_info

        if not self.gateway.is_pegasus:
            raise Exception(VSPVolumeMSG.ONLY_SUPPORTED_ON_PEGASUS.value)

    @log_entry_exit
    def get_snapshot_by_id(self, master_volume_id, snapshot_id):
        object_id = f"{master_volume_id},{snapshot_id}"
        return self.gateway.get_snapshot_by_id(object_id)

    @log_entry_exit
    def vsp_one_snapshot_facts(self, spec):
        if spec and spec.master_volume_id is not None and spec.snapshot_id is not None:
            object_id = f"{spec.master_volume_id},{spec.snapshot_id}"
            data = self.gateway.get_snapshot_by_id(object_id)
            if data:
                return data.camel_to_snake_dict()
            else:
                return {}
        return self.gateway.get_snapshots_information(spec).data_to_snake_case_list()

    @log_entry_exit
    def get_snapshot_groups(self, spec=None):

        if (
            spec is not None
            and spec.include_snapshots
            and not spec.include_snapshots
            and spec.snapshot_group_name is not None
            and spec.snapshot_group_name != ""
        ):
            raise Exception(
                "include_snapshots cannot be true when snapshot_group_name is provided."
            )

        if spec.snapshot_group_name is not None and spec.snapshot_group_name != "":
            group = self.gateway.get_snapshot_group_by_name(spec.snapshot_group_name)
            return [group.camel_to_snake_dict()] if group else []

        groups = self.gateway.get_snapshot_groups()
        snapshots = []
        if spec.include_snapshots:
            for group in groups.data:
                snapshot = self.gateway.get_snapshot_group_by_name(group.name)
                if snapshot:
                    snapshots.append(snapshot.camel_to_snake_dict())
        else:
            snapshots = groups.data_to_snake_case_list()
        return snapshots

    @log_entry_exit
    def delete_snapshot_group(self, spec):
        group_exists = self.gateway.get_snapshot_group_by_name(spec.snapshot_group_name)

        if not group_exists:
            spec.comments = (
                f"Snapshot group {spec.snapshot_group_name} does not exist or deleted."
            )
            return False
        try:
            self.gateway.delete_snapshot_group(spec.snapshot_group_name)
        except Exception as e:
            spec.comments = (
                f"Error deleting snapshot group {spec.snapshot_group_name}: {str(e)}"
            )
            return False
        self.connection_info.changed = True
        spec.comments = f"Snapshot group {spec.snapshot_group_name} deleted."
        return

    @log_entry_exit
    def create_update_snapshot(self, spec):
        self.validate_create_spec(spec.new_snapshots)
        result_list = []
        for x in spec.new_snapshots:
            try:
                result = self.create_snapshot(x)
                self.connection_info.changed = True
                result_list.append(result)
            except Exception as e:
                logger.writeError(e)
                spec.errors.append(str(e))

        ret_result_list = VspOneSnapshotList(data=result_list)
        return ret_result_list.data_to_snake_case_list()

    @log_entry_exit
    def create_snapshot(self, create_snapshot_object):
        result = self.gateway.create_snapshot(create_snapshot_object)
        return result

    @log_entry_exit
    def map_snapshot(self, spec):
        try:
            result = self.gateway.map_snapshot(
                spec.master_volume_id, spec.snapshot_id, spec.pool_id
            )
            self.connection_info.changed = True
            mapped_volume = result.mappedVolumeId
            result = self.volume_gw.salamander_get_volume_by_id(mapped_volume)
            return result.camel_to_snake_dict()
        except Exception as e:
            logger.writeError(e)
            spec.comments = str(e)
            return {}

    @log_entry_exit
    def restore_snapshot(self, spec):
        try:
            result = self.gateway.restore_snapshot(
                spec.master_volume_id, spec.snapshot_id
            )
            self.connection_info.changed = True
            return result.camel_to_snake_dict()
        except Exception as e:
            logger.writeError(e)
            spec.comments = str(e)
            return {}

    @log_entry_exit
    def delete_snapshot(self, spec):
        snapshot_exists = self.get_snapshot_by_id(
            spec.master_volume_id, spec.snapshot_id
        )

        if not snapshot_exists:
            spec.comments = f"Snapshot with master_volueme_id {spec.master_volume_id} and snapshot_id {spec.snapshot_id} does not exist or deleted."
            return False
        try:
            result = self.gateway.delete_snapshot(
                spec.master_volume_id, spec.snapshot_id
            )
            self.connection_info.changed = True
            spec.comments = f"Snapshot with master volume id {spec.master_volume_id} and snapshot id {spec.snapshot_id} is deleted successfully."
            if spec.should_delete_svol:
                if snapshot_exists.mappedVolumeId:
                    self.volume_gw.salamander_delete_volume(
                        snapshot_exists.mappedVolumeId
                    )
                    spec.comments += " SVOL is deleted successfully."
            return
        except Exception as e:
            logger.writeError(e)
            spec.comments = str(e)
            return

    @log_entry_exit
    def validate_create_spec(self, new_snapshots):
        for x in new_snapshots:
            ret, err_msg = self.is_valid_snapshot_group_name(x.snapshot_group_name)
            if ret is True:
                continue
            else:
                display_msg = (
                    f"The specified value {x.snapshot_group_name} is invalid. "
                    "You can use alphanumeric characters (0 through 9, A through Z, a through z), "
                    "space characters, and the following symbols: Comma (,), hyphen (-), period (.), "
                    "forward slash (/), colon (:), at sign (@), back slash (\\), underscore (_). "
                    "You can use a space character between characters, but cannot use it at the beginning "
                    "or end of the snapshot group name. "
                    "You cannot use a hyphen (-) at the beginning of the snapshot group name."
                )
                raise ValueError(display_msg + " " + err_msg)

    pattern = re.compile(r"^(?! )(?!.* $)(?!-)[0-9A-Za-z ,\-\./:@\\_]{1,32}$")

    def is_valid_snapshot_group_name(self, name: str):
        """
        Validate snapshot group name according to these rules:
        - Required (non-empty) and up to 32 characters.
        - Allowed characters: alphanumeric, space, and: , - . / : @ \\ _
        - No leading or trailing space (space character specifically).
        - Cannot start with a hyphen (-).
        Returns: (is_valid: bool, message: str)
        """
        if name is None:
            return False, "Name is required (None provided)."
        if not isinstance(name, str):
            return False, "Name must be a string."
        if len(name) == 0:
            return False, "Name is required and cannot be empty."
        if len(name) > 32:
            return False, f"Name is too long ({len(name)} characters). Max is 32."
        if self.pattern.match(name):
            return True, "Valid snapshot group name."

        # Helpful diagnostics when regex fails
        if name[0] == " ":
            return False, "Name cannot start with a space."
        if name[-1] == " ":
            return False, "Name cannot end with a space."
        if name[0] == "-":
            return False, "Name cannot start with a hyphen (-)."
