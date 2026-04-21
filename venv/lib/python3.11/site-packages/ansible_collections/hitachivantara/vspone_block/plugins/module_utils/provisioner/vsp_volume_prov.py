try:
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import GatewayClassTypes, ConnectionTypes
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.vsp_constants import VolumePayloadConst
    from ..message.vsp_lun_msgs import VSPVolValidationMsg
    from .vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from ..common.hv_log import (
        Log,
    )
except ImportError:
    from common.ansible_common import log_entry_exit
    from common.hv_constants import GatewayClassTypes, ConnectionTypes
    from gateway.gateway_factory import GatewayFactory
    from common.vsp_constants import VolumePayloadConst
    from message.vsp_lun_msgs import VSPVolValidationMsg
    from .vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from common.hv_log import (
        Log,
    )

logger = Log()


class VSPVolumeProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )
        self.connection_info = connection_info
        if serial:
            self.serial = serial
            self.gateway.set_serial(serial)
        if connection_info.connection_type == ConnectionTypes.DIRECT:
            VSPStorageSystemProvisioner(connection_info).populate_basic_storage_info()

    @log_entry_exit
    def get_volume_by_ldev(self, ldev):
        return self.gateway.get_volume_by_id(ldev)

    @log_entry_exit
    def get_volumes(
        self,
        start_ldev=None,
        count=None,
        pool_id=None,
        resource_group_id=None,
        journal_id=None,
        parity_group_id=None,
    ):

        count = 0 if not count else int(count)
        start_ldev = 0 if not start_ldev else int(start_ldev)
        volumes = self.gateway.get_volumes(
            start_ldev=start_ldev,
            count=count,
            pool_id=pool_id,
            resource_group_id=resource_group_id,
            journal_id=journal_id,
            parity_group_id=parity_group_id,
        )
        return volumes

    @log_entry_exit
    def unassign_vldev(self, ldev_id, vldev_id):
        return self.gateway.unassign_vldev(ldev_id, vldev_id)

    @log_entry_exit
    def get_volumes_by_pool_id(self, pool_id):

        return self.gateway.get_volumes_by_pool_id(pool_id)

    @log_entry_exit
    def delete_volume(self, ldev, force_execute):

        return self.gateway.delete_volume(ldev, force_execute)

    @log_entry_exit
    def delete_lun_path(self, port):

        return self.gateway.delete_lun_path(port)

    @log_entry_exit
    def change_volume_settings_tier(self, spec, vol_id):
        self.gateway.change_volume_settings_tier_reloc(vol_id, spec)
        self.gateway.change_volume_settings_tier_policy(vol_id, spec)

    # sng20241205 prov change_volume_settings_vldev
    @log_entry_exit
    def change_volume_settings_vldev(self, spec, vol_info):

        logger.writeDebug("79 vol_info={}", vol_info)
        changed = False

        vldev_id = spec.vldev_id
        if vldev_id is None:
            logger.writeDebug("79 vol_info={}", vol_info)
            return False

        # vol_id: ldevId we want to change
        vol_id = vol_info.ldevId

        # existing vldevId, can be none
        vldev_id_old = vol_info.virtualLdevId

        if vldev_id_old is not None and vldev_id_old >= 0:
            if vldev_id_old != vldev_id and vldev_id_old != 65534:
                # need to unassign old first before you can assign new
                self.unassign_vldev(vol_id, vldev_id_old)
                # unassign only, we are done
                if vldev_id == -1:
                    return True
        else:
            if vldev_id:
                # unassign volume with own ldevid
                self.unassign_vldev(vol_id, vol_id)
                changed = True

        logger.writeDebug("79 vldev_id={}", vldev_id)
        if (
            vldev_id != -1
            # and vldev_id != 65534
            and vldev_id_old != vldev_id
        ):
            self.gateway.assign_vldev(vol_id, vldev_id)
            changed = True

        return changed

    # sng20241205 prov create_volume
    @log_entry_exit
    def create_volume(self, spec):
        if (
            not spec.ldev_id
            and not spec.start_ldev_id
            and not spec.is_parallel_execution_enabled
        ):
            spec.ldev_id = self.get_free_ldev_from_meta()
        vol_id = self.gateway.create_volume(spec)

        vol_info = self.get_volume_by_ldev(vol_id)
        if vol_info.status == VolumePayloadConst.BLOCK:
            force_format = (
                True
                if vol_info.dataReductionMode
                and vol_info.dataReductionMode.lower() != VolumePayloadConst.DISABLED
                else False
            )
            self.gateway.format_volume(ldev_id=vol_id, force_format=force_format)

        self.gateway.change_volume_settings_tier_reloc(vol_id, spec)
        self.gateway.change_volume_settings_tier_policy(vol_id, spec)
        self.change_volume_settings_vldev(spec, vol_info)

        return vol_id

    @log_entry_exit
    def get_free_ldev_from_meta(self):
        ldevs = self.gateway.get_free_ldev_from_meta()
        if not ldevs.data:
            err_msg = VSPVolValidationMsg.NO_FREE_LDEV.value
            logger.writeError(err_msg)
            raise Exception(err_msg)
        return ldevs.data[0].ldevId

    @log_entry_exit
    def get_free_ldevs_from_meta(
        self, count=0, start_ldev=None, end_ldev=None, resource_grp_id=0
    ):
        if count and count > 0 and end_ldev is not None:
            err_msg = VSPVolValidationMsg.COUNT_END_LDEV_MUTUALLY_EXCLUSIVE.value
            logger.writeError(err_msg)
            return err_msg

        if (end_ldev is not None and start_ldev is not None) and (
            end_ldev < start_ldev
        ):
            err_msg = VSPVolValidationMsg.END_LDEV_SHOULD_BE_GREATER.value
            logger.writeError(err_msg)
            return err_msg

        count = (
            10
            if (not count and not end_ldev) or (not count and end_ldev)
            else int(count)
        )
        resource_grp_id = 0 if not resource_grp_id else int(resource_grp_id)
        start_ldev = 0 if not start_ldev else int(start_ldev)
        each_count = 500
        ldevs_ids = []

        while True:

            if start_ldev > 65279:
                break

            ldevs = self.gateway.get_free_ldevs_from_meta_chunks(start_ldev, each_count)
            raw_ldev_ids = [ldev.ldevId for ldev in ldevs.data]
            ldevs_ids.extend(
                [
                    ldev.ldevId
                    for ldev in ldevs.data
                    if ldev.resourceGroupId == resource_grp_id
                ]
            )

            if len(ldevs_ids) == 0:
                start_ldev += each_count
                continue

            if end_ldev is None:
                if len(ldevs_ids) < count:
                    start_ldev = max(raw_ldev_ids) + 1
                else:
                    break
            else:

                if max(ldevs_ids) < end_ldev:
                    start_ldev = max(raw_ldev_ids) + 1
                else:
                    ldevs_ids = [ldev for ldev in ldevs_ids if ldev <= end_ldev]
                    break

        if len(ldevs_ids) < 1:
            err_msg = VSPVolValidationMsg.NO_FREE_LDEV.value
            logger.writeError(err_msg)
            return err_msg

        return ldevs_ids[:count] if not end_ldev else ldevs_ids

    @log_entry_exit
    def expand_volume_capacity(self, ldev_id, payload, enhanced_expansion):

        return self.gateway.expand_volume(ldev_id, payload, enhanced_expansion)

    @log_entry_exit
    def format_volume(
        self, ldev_id, force_format=True, format_type="quick", check_job_status=True
    ):

        return self.gateway.format_volume(
            ldev_id,
            force_format=force_format,
            format_type=format_type,
            check_job_status=check_job_status,
        )

    @log_entry_exit
    def change_volume_settings(self, ldev_id, name=None, adr_setting=None, spec=None):
        try:
            self.gateway.update_volume(ldev_id, name, adr_setting, spec)
            self.connection_info.changed = True
            if spec and hasattr(spec, "comment") is not None:
                spec.comment = "Volume settings updated successfully."
        except Exception as e:
            if "The specified volume is not found" in str(e):
                err_msg = VSPVolValidationMsg.VOL_NOT_FOUND.value + str(e)
                logger.writeError(err_msg)
                raise Exception(err_msg)
            elif spec and hasattr(spec, "comment") is not None:
                spec.comment = "Failed to update volume settings: " + str(e)
            else:
                raise e
        return True

    def get_qos_settings(self, ldev_id):
        return self.gateway.get_qos_settings(ldev_id)

    @log_entry_exit
    def shredding_volume(self, ldev_id, start):
        # set the volume status to block before shredding
        ldev = self.get_volume_by_ldev(ldev_id)
        if not ldev.status.upper() == VolumePayloadConst.BLOCK:
            unused = self.gateway.change_volume_status(ldev_id, True)
        return self.gateway.shredding_volume(ldev_id, start)

    @log_entry_exit
    def change_volume_status(self, ldev_id, is_block=False):
        return self.gateway.change_volume_status(ldev_id, is_block)

    @log_entry_exit
    def change_volume_settings_ext(self, ldev_id, label=None, isAluaEnabled=None):
        return self.gateway.change_volume_settings(ldev_id, label, isAluaEnabled)

    @log_entry_exit
    def change_qos_settings(self, ldev_id, qos_spec):
        return self.gateway.change_qos_settings(ldev_id, qos_spec)

    @log_entry_exit
    def change_mp_blade(self, ldev_id, mp_blade_id):
        return self.gateway.change_mp_blade(ldev_id, mp_blade_id)

    @log_entry_exit
    def assign_ldev_to_clpr(self, ldev_id, clpr_id):
        return self.gateway.assign_ldev_to_clpr(ldev_id, clpr_id)

    @log_entry_exit
    def reclaim_zero_pages(self, ldev_id):
        try:
            return self.gateway.reclaim_zero_pages(ldev_id)
        except Exception as e:
            if "412" in str(e):
                pass
                logger.writeError(
                    f"Reclaim zero pages is not supported for this volume {e}"
                )
            else:
                raise e

    @log_entry_exit
    def get_volume_by_name(self, name):
        volumes = self.gateway.get_simple_volumes(start_ldev=0, count=0)
        for v in volumes.data:
            if v.label == name:
                return v

        return None

    @log_entry_exit
    def fill_cmd_device_info(self, volume):
        return self.gateway.fill_cmd_device_info(volume)

    @log_entry_exit
    def get_all_ldevs_using_filter(self, filter_spec):
        """
        Get all LDEVs using the provided filter specification.
        """
        query_dict = {}
        if filter_spec.pool_id is None:
            query_dict["poolId"] = filter_spec.pool_id

        return self.gateway.get_all_ldevs_using_filter(filter_spec)
