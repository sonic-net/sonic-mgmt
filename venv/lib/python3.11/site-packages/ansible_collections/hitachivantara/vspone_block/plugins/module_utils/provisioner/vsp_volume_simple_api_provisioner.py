try:
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import (
        Log,
    )
    from ..gateway.vsp_volume_simple_api_gateway import VspSimpleApiGateway
    from ..model.vsp_volume_models import SalamanderCreateVolumeRequestSpec
    from ..message.vsp_lun_msgs import VSPVolumeMSG
except ImportError:
    from common.ansible_common import log_entry_exit
    from common.hv_log import (
        Log,
    )
    from gateway.vsp_volume_simple_api_gateway import VspSimpleApiGateway
    from model.vsp_volume_models import SalamanderCreateVolumeRequestSpec


logger = Log()


class VSPVolumeSimpleApiProvisioner:
    """
    VSPVolumeSimpleApiProvisioner
    """

    def __init__(self, connection_info):
        self.gateway = VspSimpleApiGateway(connection_info)
        self.connection_info = connection_info

        if not self.gateway.is_pegasus:
            raise Exception(VSPVolumeMSG.ONLY_SUPPORTED_ON_PEGASUS.value)

    @log_entry_exit
    def salamander_get_volumes(self):
        volumes = self.gateway.salamander_get_volumes()
        return volumes

    @log_entry_exit
    def salamander_get_volume_by_id(self, volume_id):
        return self.gateway.salamander_get_volume_by_id(volume_id)

    @log_entry_exit
    def salamander_delete_volume(self, spec: SalamanderCreateVolumeRequestSpec):

        if not spec.volume_id:
            raise Exception(VSPVolumeMSG.MISSING_VOLUME_ID_FOR_DELETION.value)

        try:
            unused = self.gateway.salamander_delete_volume(spec.volume_id)
            self.connection_info.changed = True
            spec.comments.append(VSPVolumeMSG.VOLUME_DELETED_SUCCESS.value)
        except Exception as e:
            spec.comments.append(VSPVolumeMSG.VOLUME_DELETE_FAILED.value + str(e))
            return

    @log_entry_exit
    def create_update_volume(self, spec: SalamanderCreateVolumeRequestSpec):
        vol_info = None
        volumes = []
        if spec.volume_id:
            vol_info = self.gateway.salamander_get_volume_by_id(spec.volume_id)
        if not vol_info:
            vol_ids = self.salamander_create_volume(spec)
            self.connection_info.changed = True
            if len(vol_ids) > 1:
                spec.comments.append(
                    VSPVolumeMSG.MULTIPLE_VOLUMES_CREATED.value.format(
                        ids=", ".join(vol_ids)
                    )
                )
            elif len(vol_ids) == 1 and spec.qos_settings is not None:
                try:
                    self.salamander_update_qos_settings(vol_ids[0], spec.qos_settings)
                    spec.comments.append(VSPVolumeMSG.QOS_UPDATED_SUCCESS.value)
                except Exception as e:
                    spec.comments.append(
                        VSPVolumeMSG.FAILED_TO_UPDATE_QOS.value.format(str(e))
                    )
            if spec.server_ids and len(spec.server_ids) > 0:
                spec.volume_ids = vol_ids
                self.attach_servers_to_volumes(spec)
            volumes = [
                self.gateway.salamander_get_volume_by_id_with_details(
                    vol_id
                ).camel_to_snake_dict()
                for vol_id in vol_ids
            ]
            return volumes
        else:
            self.salamander_update_volume(spec, vol_info)

        if self.connection_info.changed:
            spec.comment = VSPVolumeMSG.VOLUME_CREATED_UPDATED_SUCCESS.value
        vol_info = self.gateway.salamander_get_volume_by_id_with_details(spec.volume_id)
        return vol_info.camel_to_snake_dict()

    @log_entry_exit
    def salamander_create_volume(self, spec: SalamanderCreateVolumeRequestSpec):
        """
        Create a volume using the Salamander API.
        """
        if spec.pool_id is None:
            raise Exception(VSPVolumeMSG.POOL_ID_REQUIRED.value)
        if spec.capacity is None:
            raise Exception(VSPVolumeMSG.CAPACITY_REQUIRED.value)
        if spec.volume_name is None or spec.volume_name.base_name is None:
            raise Exception(VSPVolumeMSG.NICKNAME_REQUIRED.value)

        # Create the volume
        return self.gateway.salamander_create_volume(spec)

    @log_entry_exit
    def update_qos_settings(self, spec: SalamanderCreateVolumeRequestSpec):
        if not spec.volume_id:
            raise Exception(VSPVolumeMSG.VOLUME_ID_REQUIRED_FOR_QOS.value)
        if not spec.qos_settings:
            raise Exception(VSPVolumeMSG.QOS_SETTINGS_REQUIRED.value)

        volume = self.gateway.salamander_get_volume_by_id(spec.volume_id)
        if not volume:
            raise Exception(
                VSPVolumeMSG.VOLUME_NOT_FOUND.value.format(volume_id=spec.volume_id)
            )
        # Compare and update only if there are changes
        try:
            self.salamander_update_qos_settings(spec.volume_id, spec.qos_settings)
            self.connection_info.changed = True
            spec.comments.append(VSPVolumeMSG.QOS_UPDATED_SUCCESS.value)
        except Exception as e:
            spec.comments.append(VSPVolumeMSG.FAILED_TO_UPDATE_QOS.value.format(str(e)))

        return self.gateway.salamander_get_volume_by_id_with_details(
            spec.volume_id
        ).camel_to_snake_dict()

    @log_entry_exit
    def salamander_update_volume(
        self, spec: SalamanderCreateVolumeRequestSpec, vol_info
    ):

        try:
            if spec.volume_name and spec.volume_name.base_name == vol_info.nickname:
                spec.volume_name.base_name = None
            if spec.capacity_saving == vol_info.savingSetting.lower():
                spec.capacity_saving = None
            if spec.compression_acceleration == vol_info.compressionAcceleration:
                spec.compression_acceleration = None
            if (
                (
                    spec.volume_name is not None
                    and spec.volume_name.base_name is not None
                )
                or spec.capacity_saving is not None
                or spec.compression_acceleration is not None
            ):
                self.gateway.salamander_update_volume(
                    spec.volume_id,
                    spec.volume_name.base_name if spec.volume_name else None,
                    spec.capacity_saving,
                    spec.compression_acceleration,
                )

                self.connection_info.changed = True
                spec.comments.append(VSPVolumeMSG.VOLUME_SETTINGS_UPDATED_SUCCESS.value)
        except Exception as e:
            spec.comments.append(
                VSPVolumeMSG.FAILED_TO_UPDATE_VOLUME_SETTINGS.value + str(e)
            )
        try:
            if spec.capacity is not None and vol_info.totalCapacity < spec.capacity:
                spec.capacity = int(spec.capacity - vol_info.totalCapacity)
                self.gateway.salamander_update_volume_capacity(
                    spec.volume_id, spec.capacity
                )
                self.connection_info.changed = True
                spec.comments.append(
                    VSPVolumeMSG.VOLUME_CAPACITY_EXPANDED_SUCCESS.value
                )

        except Exception as e:
            spec.comments.append(
                VSPVolumeMSG.FAILED_TO_EXPAND_VOLUME_CAPACITY.value + str(e)
            )

        return

    @log_entry_exit
    def salamander_get_qos_settings(self, volume_id):
        return self.gateway.salamander_get_qos_settings(volume_id)

    @log_entry_exit
    def salamander_update_qos_settings(self, volume_id, qos_settings):
        return self.gateway.salamander_update_qos_settings(volume_id, qos_settings)

    @log_entry_exit
    def attach_servers_to_volumes(self, spec):

        if not spec.volume_ids or len(spec.volume_ids) == 0:
            raise Exception(VSPVolumeMSG.MISSING_VOLUME_ID_FOR_OPERATION.value)

        if not spec.server_ids or len(spec.server_ids) == 0:
            raise Exception(VSPVolumeMSG.MISSING_SERVER_ISD_FOR_OPERATION.value)
        try:
            affected_resource, failed_job = self.gateway.attach_servers_to_volumes(
                spec.volume_ids, spec.server_ids
            )
            if affected_resource:
                # msg = f"Attached servers {spec.server_ids} to volumes {spec.volume_ids}"
                self.connection_info.changed = True
                spec.comments.append(VSPVolumeMSG.ATTACHED_SERVER_SUCCESS.value)
            if failed_job:
                spec.comments.append(
                    VSPVolumeMSG.ATTACHED_SERVER_FAILED.value + str(failed_job)
                )
        except Exception as e:
            spec.comments.append(VSPVolumeMSG.ATTACHED_SERVER_FAILED.value + str(e))
            return

    @log_entry_exit
    def attach_server_to_volume(self, spec, server_ids):

        if not spec.volume_id:
            raise Exception(VSPVolumeMSG.MISSING_VOLUME_ID_FOR_OPERATION.value)

        volume = self.gateway.salamander_get_volume_by_id(spec.volume_id)
        if not volume:
            raise Exception(
                VSPVolumeMSG.VOLUME_NOT_FOUND.value.format(volume_id=spec.volume_id)
            )
        existing_server_ids = set(
            lun.serverId for lun in getattr(volume, "luns", []) or []
        )
        logger.writeDebug(f"Existing server IDs attached: {existing_server_ids}")
        new_server_ids = list(set(server_ids) - existing_server_ids)
        logger.writeDebug(f"New server IDs to attach: {new_server_ids}")

        if not new_server_ids:
            spec.comments.append(VSPVolumeMSG.SERVER_ALREADY_ATTACHED.value)
            return volume.camel_to_snake_dict()
        try:
            affected_resource, failed_job = self.gateway.attach_server_to_volume(
                spec.volume_id, new_server_ids
            )
            if affected_resource:
                self.connection_info.changed = True
                spec.comments.append(
                    VSPVolumeMSG.ATTACHED_SERVER_SUCCESS.value.format(affected_resource)
                )
            if failed_job:
                spec.comments.append(
                    VSPVolumeMSG.ATTACHED_SERVER_FAILED.value + str(failed_job)
                )

        except Exception as e:
            spec.comments.append(VSPVolumeMSG.ATTACHED_SERVER_FAILED.value + str(e))
            return volume.camel_to_snake_dict()

        return self.gateway.salamander_get_volume_by_id_with_details(
            spec.volume_id
        ).camel_to_snake_dict()

    @log_entry_exit
    def detach_server_from_volume(self, spec, server_ids):
        if not spec.volume_id:
            raise Exception(VSPVolumeMSG.MISSING_VOLUME_ID_FOR_OPERATION.value)
        volume = self.gateway.salamander_get_volume_by_id(spec.volume_id)
        if not volume:
            raise Exception(
                VSPVolumeMSG.VOLUME_NOT_FOUND.value.format(volume_id=spec.volume_id)
            )
        existing_server_ids = set(
            lun.serverId for lun in getattr(volume, "luns", []) or []
        )
        server_ids_to_detach = list(set(server_ids) & existing_server_ids)

        if not server_ids_to_detach:
            spec.comments.append(VSPVolumeMSG.SERVER_ALREADY_DETACHED.value)
            return volume.camel_to_snake_dict()
        passed_sever_ids = []
        failed_server_ids = []
        for server_id in server_ids_to_detach:
            try:
                unused = self.gateway.detach_server_from_volume(
                    spec.volume_id, server_id
                )
                passed_sever_ids.append(server_id)
            except Exception as e:
                failed_server_ids.append(f"{server_id}: {str(e)}")
        if passed_sever_ids:
            spec.comments.append(
                VSPVolumeMSG.DETACHED_SERVER_SUCCESS.value.format(passed_sever_ids)
            )
            self.connection_info.changed = True
        if failed_server_ids:
            spec.comments.append(
                VSPVolumeMSG.DETACHED_SERVER_FAILED.value + str(failed_server_ids)
            )

        return self.gateway.salamander_get_volume_by_id_with_details(
            spec.volume_id
        ).camel_to_snake_dict()

    @log_entry_exit
    def volume_facts_request_calls(self, spec):
        return self.gateway.filter_volume_by_specs(spec)
