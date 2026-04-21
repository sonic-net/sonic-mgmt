from typing import Optional
import time

try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_constants import ConnectionTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        convert_decimal_size_to_bytes,
    )
    from ..model.vsp_hur_models import VSPHurPairInfoList
    from .vsp_remote_replication_helper import RemoteReplicationHelperForSVol
    from ..message.vsp_hur_msgs import VSPHurValidateMsg, HurFailedMsg

    from ..model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
        DirectSpecificCopyGroupInfoList,
    )

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_constants import ConnectionTypes
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        convert_decimal_size_to_bytes,
    )
    from model.vsp_hur_models import VSPHurPairInfoList
    from message.vsp_hur_msgs import VSPHurValidateMsg, HurFailedMsg
    from .vsp_remote_replication_helper import RemoteReplicationHelperForSVol
    from model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
        DirectSpecificCopyGroupInfoList,
    )

logger = Log()


class VSPHurProvisioner:

    def __init__(self, connection_info, serial):
        self.logger = Log()
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_HUR
        )
        self.vol_gw = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )
        self.cg_gw = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_COPY_GROUPS
        )
        self.connection_info = connection_info
        self.serial = serial
        self.gateway.set_storage_serial_number(serial)

    @log_entry_exit
    def get_all_replication_pairs(self, serial=None):
        if serial is None:
            serial = self.serial
        return self.gateway.get_all_replication_pairs(serial)

    @log_entry_exit
    def get_replication_pair_info_list(self, serial=None):
        if serial is None:
            serial = self.serial
        all_rep_pairs = self.gateway.get_all_replication_pairs(serial)

        #  20240918 - get hur facts with fetchAll=true
        #  we return all hur pairs un-filtered
        #  filter all hur by the storage serial
        #  in either primary or secondary storage
        ret_list = []
        for rp in all_rep_pairs.data:
            if serial:
                if str(serial) == str(rp.serialNumber) or str(serial) == str(
                    rp.remoteSerialNumber
                ):
                    ret_list.append(rp)
        return VSPHurPairInfoList(ret_list)

    @log_entry_exit
    def get_hur_pair_info_list(self, serial=None):
        if serial is None:
            serial = self.serial

        all_rep_pairs = self.gateway.get_all_replication_pairs(serial)
        ret_list = []
        for rp in all_rep_pairs.data:
            ret_list.append(rp)  # 20240805
        return VSPHurPairInfoList(ret_list)

    @log_entry_exit
    def hur_pair_facts_direct(self, spec=None):

        # sng20241115 - hur_pair_facts_direct
        tc_pairs = self.get_all_hur_pairs_direct(spec=spec)
        self.logger.writeDebug(f"PV:: 88 pairs=  {tc_pairs}")
        if tc_pairs is None:
            return tc_pairs
        if spec is None:
            return tc_pairs
        else:
            ret_tc_pairs = self.apply_filters(tc_pairs, spec)
            logger.writeDebug("sng20241115 :ret_tc_pairs={}", ret_tc_pairs)
            # return VSPHurPairInfo(data=ret_tc_pairs)
            return ret_tc_pairs

    # sng20241115 - prov.get_all_hur_pairs_direct
    @log_entry_exit
    def get_all_hur_pairs_direct(self, serial=None, spec=None):
        if serial is None:
            serial = self.serial
        if spec is None:
            ret_list = self.gateway.get_all_replication_pairs(serial)
            self.logger.writeDebug(f"PROV:105:ret_list= {ret_list} serial = {serial}")
            return ret_list
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            # First we check if there is a copy group name present in the spec
            spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(
                spec
            )

            if (
                spec.copy_group_name
                and spec.copy_pair_name
                and spec.local_device_group_name
                and spec.remote_device_group_name
            ):
                return self.cg_gw.get_remote_copy_pair_by_id(spec)

            if spec.copy_group_name and spec.copy_pair_name:
                return self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(
                    spec
                )

            if spec.copy_group_name:
                return self.cg_gw.get_remote_pairs_for_a_copy_group(spec)

            if spec.primary_volume_id:
                return self.cg_gw.get_remote_pairs_by_pvol(spec)

            if spec.secondary_volume_id:
                return self.cg_gw.get_remote_pairs_by_svol(spec)

            # ret_list = self.cg_gw.get_all_copy_pairs(spec)
            ret_list = self.cg_gw.get_all_remote_pairs_from_copy_groups(spec)
            return ret_list
            # return DirectCopyPairInfoList(data=ret_list)

    @log_entry_exit
    def apply_filters(self, tc_pairs, spec):
        result = self.get_hur_copypairs(tc_pairs)
        return result

    # sng20241115 pair: DirectSpecificCopyGroupInfo or list
    @log_entry_exit
    def get_hur_copypairs(self, pair):

        self.logger.writeDebug("sng20241115 :pair={}", pair)

        if isinstance(pair, list):
            return self.get_hur_copypairs_from_list(pair)
        if isinstance(pair, DirectSpecificCopyGroupInfoList):
            return self.get_hur_copypairs_from_list(pair.data_to_list())

        gad_pairs = []

        if isinstance(pair, DirectCopyPairInfo):
            if pair.replicationType == "UR":
                gad_pairs.append(pair)
                return gad_pairs

        copyPairs = pair.copyPairs
        if copyPairs is None:
            return

        for copyPair in copyPairs:
            # sng20241115 change replicationType here to use other types for testing
            if copyPair.replicationType == "UR":
                gad_pairs.append(copyPair)

        return gad_pairs

    @log_entry_exit
    def get_hur_copypairs_from_list(self, cgList):

        gad_pairs = []

        logger.writeDebug("sng20241115 :cg={}", cgList)
        if isinstance(cgList, dict):
            return self.get_hur_copypairs_from_dict(cgList, gad_pairs)

        for cg in cgList:
            if cg is None:
                continue

            logger.writeDebug("sng20241115 :cg={}", cg)

            if isinstance(cg, dict):
                gad_pairs = self.get_hur_copypairs_from_dict(cg, gad_pairs)
                continue

            copyPairs = None
            #  handle cg class object if needed
            if isinstance(cg, DirectCopyPairInfo):
                copyPairs = [cg]
            elif hasattr(cg, "copyPairs"):
                copyPairs = cg.copyPairs

            logger.writeDebug("sng20241115 :copyPairs={}", cg)
            if copyPairs is None:
                continue

            for copyPair in copyPairs:
                if copyPair.replicationType == "UR":
                    gad_pairs.append(copyPair)

        return gad_pairs

    @log_entry_exit
    def get_hur_copypairs_from_dict(self, cgs, gad_pairs):

        if cgs is None:
            return gad_pairs
        if not isinstance(cgs, dict):
            return gad_pairs

        # cgs is a dict, the element of the dict can some time be an array

        for cg in cgs:

            if cg is None:
                continue

            logger.writeDebug("sng20241115 :cg={}", cg)

            if isinstance(cg, str):
                # this element of the dict is not an array,
                # we can now get the copyPairs from the cgs dict
                copyPairs = cgs["copyPairs"]

                if isinstance(copyPairs, dict):
                    for copyPair in copyPairs:
                        if copyPair["replicationType"] == "UR":
                            gad_pairs.append(copyPair)
                else:
                    # handle copyPair class objects
                    for copyPair in copyPairs:
                        if isinstance(copyPair, dict):
                            if copyPair["replicationType"] == "UR":
                                gad_pairs.append(copyPair)
                        else:
                            if copyPair.replicationType == "UR":
                                gad_pairs.append(copyPair)

                return gad_pairs

            #  cg is a list of dict
            items = cg
            if not isinstance(cg, list):
                return gad_pairs

            for cg in items:

                copyPairs = cg["copy_pairs"]
                if copyPairs is None:
                    continue

                for copyPair in copyPairs:
                    if copyPair.replicationType == "UR":
                        gad_pairs.append(copyPair)

        return gad_pairs

    @log_entry_exit
    def get_hur_facts(self, spec=None):
        # primary_volume_id = spec.get('primary_volume_id',None)
        primary_volume_id = spec.primary_volume_id
        if spec is None or (spec and primary_volume_id is None):
            return self.get_all_hurpairs()
        else:
            return self.get_all_hur_for_primary_vol_id(primary_volume_id)

    @log_entry_exit
    def get_all_hurpairs(self, serial=None):
        if serial is None:
            serial = self.serial

        all_rep_pairs = self.gateway.get_all_replication_pairs(serial)

        filtered = [
            ssp.to_dict() for ssp in all_rep_pairs.data
        ]  # 20240805, update - removed if true
        self.logger.writeDebug(f"filtered={filtered}")
        return filtered

    @log_entry_exit
    def get_hur_for_primary_vol_id(self, primary_vol_id):
        all_hurpairs = self.get_replication_pair_info_list()

        # 20240808 - one pvol can have 3 pairs, this only returns the first pair
        for tc in all_hurpairs.data:
            if tc.ldevId == primary_vol_id:
                return tc
        return None

    # 20240808 - get_hur_by_pvol_mirror, mirror id support
    @log_entry_exit
    def get_hur_by_pvol_mirror(self, primary_vol_id, mirror_unit_id):
        all_hurpairs = self.get_replication_pair_info_list()
        for tc in all_hurpairs.data:
            if tc.ldevId == primary_vol_id and tc.muNumber == mirror_unit_id:
                return tc

        return None

    #  get_hur_facts_ext
    @log_entry_exit
    def get_hur_facts_ext(
        self,
        pvol: Optional[int] = None,
        svol: Optional[int] = None,
        mirror_unit_id: Optional[int] = None,
    ):
        all_hurpairs = self.get_replication_pair_info_list()
        self.logger.writeDebug(f"all_hurpairs={all_hurpairs}")

        result = [
            ssp
            for ssp in all_hurpairs.data
            if (pvol is None or ssp.ldevId == pvol or ssp.remoteLdevId == pvol)
            and (svol is None or ssp.remoteLdevId == svol or ssp.ldevId == svol)
            and (mirror_unit_id is None or ssp.muNumber == mirror_unit_id)
        ]
        self.logger.writeDebug(f"result={result}")

        return VSPHurPairInfoList(data=result)
        # return result

    @log_entry_exit
    def get_all_hur_for_primary_vol_id(self, primary_vol_id):
        all_hurpairs = self.get_replication_pair_info_list()

        # 20240808 - one pvol can have 3 pairs
        result = []
        for tc in all_hurpairs.data:
            if tc.primaryVolumeId == primary_vol_id:
                result.append(tc)

        return result

    @log_entry_exit
    def get_hur_by_pvol_svol(self, pvol, svol):
        all_hurpairs = self.get_replication_pair_info_list()

        # 20240912 - get_hur_by_pvol_svol
        result = None

        for tc in all_hurpairs.data:
            if str(tc.primaryVolumeId) == pvol and str(tc.secondaryVolumeId) == svol:
                self.logger.writeDebug(f"151 tc: {tc}")
                result = tc
                break

        return result

    @log_entry_exit
    def get_replication_pair_by_id(self, pair_id):
        pairs = self.get_all_replication_pairs(self.serial)
        for pair in pairs.data:
            if pair.serialNumber == pair_id:
                return pair
        return None

    # 20240808 delete_hur_pair
    @log_entry_exit
    def delete_hur_pair(self, primary_volume_id, mirror_unit_id, spec=None):
        pair_exiting = self.gateway.get_replication_pair(spec)
        if pair_exiting is None:
            return VSPHurValidateMsg.NO_HUR_PAIR_FOUND.value.format(spec.copy_pair_name)
        if spec.copy_group_name and spec.copy_pair_name:
            pair_id = self.gateway.delete_hur_pair_by_pair_id(spec)
            if spec.should_delete_svol is True:
                spec.secondary_volume_id = pair_exiting["svol_ldev_id"]
                rr_prov = RemoteReplicationHelperForSVol(
                    spec.secondary_connection_info,
                    self.gateway.get_secondary_serial(spec),
                )
                rr_prov.delete_volume_and_all_mappings(spec.secondary_volume_id)
            self.connection_info.changed = True
            return None

    @log_entry_exit
    def resync_hur_pair(self, primary_volume_id, mirror_unit_id, spec=None):
        pair_exiting = self.gateway.get_replication_pair(spec)
        if (
            pair_exiting["pvol_status"] == "PAIR"
            and pair_exiting["svol_status"] == "PAIR"
        ):
            return pair_exiting
        pair_id = self.gateway.resync_hur_pair(spec)
        self.logger.writeDebug(f"PV:resync_hur_pair: pair_id=  {pair_id}")
        pair = self.gateway.get_replication_pair(spec)
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def swap_resync_hur_pair(self, primary_volume_id, spec=None):
        pair_exiting = self.gateway.get_replication_pair(spec)
        if pair_exiting is None:
            err_msg = (
                HurFailedMsg.PAIR_SWAP_RESYNC_FAILED.value
                + VSPHurValidateMsg.NO_HUR_PAIR_FOUND.value.format(spec.copy_pair_name)
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        if (
            pair_exiting["pvol_status"] == "PAIR"
            and pair_exiting["svol_status"] == "PAIR"
        ):
            return pair_exiting
        pair_id = self.gateway.swap_resync_hur_pair(spec)
        self.logger.writeDebug(f"PV:swap_resync_hur_pair: pair_id=  {pair_id}")
        pair = self.gateway.get_replication_pair(spec)
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def split_hur_pair(self, primary_volume_id, mirror_unit_id, spec=None):
        err_msg = ""
        pair_exiting = self.gateway.get_replication_pair(spec)
        if pair_exiting is None:
            err_msg = (
                HurFailedMsg.PAIR_SPLIT_FAILED.value
                + VSPHurValidateMsg.NO_HUR_PAIR_FOUND.value.format(spec.copy_pair_name)
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        if pair_exiting["remote_mirror_copy_pair_id"] is not None:
            pair_elements = pair_exiting["remote_mirror_copy_pair_id"].split(",")
            if (
                spec.local_device_group_name is not None
                or spec.remote_device_group_name is not None
            ):
                if spec.local_device_group_name != pair_elements[2]:
                    err_msg = (
                        HurFailedMsg.PAIR_SPLIT_FAILED.value
                        + VSPHurValidateMsg.NO_LOCAL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[2]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                elif spec.remote_device_group_name != pair_elements[3]:
                    err_msg = (
                        HurFailedMsg.PAIR_SPLIT_FAILED.value
                        + VSPHurValidateMsg.NO_REMOTE_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[3]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
        if (
            pair_exiting["pvol_status"] == "PSUS"
            and pair_exiting["svol_status"] == "SSUS"
        ):
            return pair_exiting
        pair_id = self.gateway.split_hur_pair(spec)
        self.logger.writeDebug(f"PV:split_hur_pair: pair_id=  {pair_id}")
        pair = self.gateway.get_replication_pair(spec)
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def swap_split_hur_pair(self, primary_volume_id, spec=None):
        pair_exiting = self.gateway.get_replication_pair(spec)
        if (
            pair_exiting["pvol_status"] == "PSUS"
            and pair_exiting["svol_status"] == "SSWS"
        ):
            return pair_exiting
        pair_id = self.gateway.swap_split_hur_pair(spec)
        self.logger.writeDebug(f"PV:swap_split_hur_pair: pair_id=  {pair_id}")
        pair = self.gateway.get_replication_pair(spec)
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def secondary_takeover_hur_pair(self, spec=None):
        # pair_exiting = self.gateway.get_replication_pair(spec)
        # if (
        #     pair_exiting["pvol_status"] != "PSUS"
        #     and pair_exiting["svol_status"] != "SSWS"
        # ):
        #     err_msg = (
        #         HurFailedMsg.SECONDARY_TAKEOVER_FAILED.value
        #         + VSPHurValidateMsg.PAIR_NOT_IN_SSWS_STATE.value.format(spec.copy_pair_name)
        #     )
        #     logger.writeError(err_msg)
        #     raise ValueError(err_msg)
        pair = self.gateway.secondary_takeover_hur_pair(spec)
        self.logger.writeDebug(f"PV:secondary_takeover_hur_pair: pair=  {pair}")
        # pair = self.gateway.get_replication_pair(spec)
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def is_resize_needed(self, volume_data, spec):
        size_in_bytes = convert_decimal_size_to_bytes(spec.new_volume_size)
        if volume_data.blockCapacity > size_in_bytes:
            logger.writeDebug(
                "PV:resize_true_copy_copy_pair: Shrink/reduce volume size is not supported."
            )
            return False

        expand_val = size_in_bytes - (
            volume_data.blockCapacity if volume_data.blockCapacity else 0
        )
        if expand_val > 0:
            return True
        return False

    @log_entry_exit
    def resize_hur_copy_pair(self, spec=None):
        hur = None
        pair_id = None
        if spec.copy_group_name and spec.copy_pair_name:
            hur = self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)
            logger.writeDebug(f"PV:resize_true_copy_copy_pair: hur=  {hur}")
            if hur is not None and len(hur) > 0:
                pvol_id = hur[0].pvolLdevId
                pvol_data = self.vol_gw.get_volume_by_id(pvol_id)
                resize_needed = self.is_resize_needed(pvol_data, spec)
                if resize_needed is False:
                    err_msg = (
                        HurFailedMsg.PAIR_RESIZE_FAILED.value
                        + VSPHurValidateMsg.REDUCE_VOLUME_SIZE_NOT_SUPPORTED.value
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    pair_id = self.gateway.resize_hur_pair(hur[0], spec)
                    logger.writeDebug(f"PV:resize_hur_copy_pair: pair_id=  {pair_id}")
                    pair = self.gateway.get_replication_pair(spec)
                    self.connection_info.changed = True
                    return pair
            else:
                err_msg = (
                    HurFailedMsg.PAIR_RESIZE_FAILED.value
                    + VSPHurValidateMsg.NO_HUR_PAIR_FOUND.value.format(
                        spec.copy_pair_name
                    )
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

    #  20240830 convert HostGroupTC to HostGroupHUR
    def convert_secondary_hostgroups(self, secondary_hostgroups):
        hgs = []
        for hg in secondary_hostgroups:
            #  we just take the first one
            #  not expect more than one
            del hg["hostGroupID"]
            del hg["resourceGroupID"]
            hgs.append(hg)
            return hgs

    @log_entry_exit
    def get_copy_group_by_name(self, spec):
        return self.cg_gw.get_copy_group_by_name(spec)

    @log_entry_exit
    def create_hur_pair(self, spec):
        pair_exiting = self.gateway.get_replication_pair(spec)

        if pair_exiting is not None:
            if pair_exiting["pvol_ldev_id"] != spec.primary_volume_id:
                return "Copy pair name : {} already exits in copy group: {}".format(
                    spec.copy_pair_name, spec.copy_group_name
                )
            else:
                return pair_exiting
        secondary_storage_connection_info = spec.secondary_connection_info
        copy_group = self.get_copy_group_by_name(spec)
        if copy_group is None:
            spec.is_new_group_creation = True
        else:
            spec.is_new_group_creation = False
            if (
                spec.local_device_group_name is not None
                and spec.local_device_group_name != copy_group.localDeviceGroupName
            ):
                err_msg = (
                    HurFailedMsg.PAIR_CREATION_FAILED.value
                    + VSPHurValidateMsg.NO_LOCAL_DEVICE_NAME_FOUND.value.format(
                        spec.copy_group_name, copy_group.localDeviceGroupName
                    )
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

            if (
                spec.remote_device_group_name is not None
                and spec.remote_device_group_name != copy_group.remoteDeviceGroupName
            ):
                err_msg = (
                    HurFailedMsg.PAIR_CREATION_FAILED.value
                    + VSPHurValidateMsg.NO_REMOTE_DEVICE_NAME_FOUND.value.format(
                        spec.copy_group_name, copy_group.localDeviceGroupName
                    )
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

        secondary_storage_connection_info.connection_type = ConnectionTypes.DIRECT
        rr_prov = RemoteReplicationHelperForSVol(
            secondary_storage_connection_info, self.gateway.get_secondary_serial(spec)
        )
        pvol = self.get_volume_by_id(spec.primary_volume_id)
        if pvol is None:
            err_msg = (
                HurFailedMsg.PAIR_CREATION_FAILED.value
                + VSPHurValidateMsg.NO_PRIMARY_VOLUME_FOUND.value.format(
                    spec.primary_volume_id
                )
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        secondary_vol_id = None
        try:
            if spec.secondary_nvm_subsystem is not None:
                secondary_vol_id = rr_prov.get_secondary_volume_id_when_nvme(pvol, spec)
            elif spec.secondary_iscsi_targets is not None:
                secondary_vol_id = rr_prov.get_secondary_volume_id(pvol, spec, True)
            else:
                secondary_vol_id = rr_prov.get_secondary_volume_id(pvol, spec, False)
            spec.secondary_volume_id = secondary_vol_id
            spec.is_data_reduction_force_copy = pvol.isDataReductionShareEnabled
            result = self.gateway.create_hur_pair(spec)
            self.logger.writeDebug(f"create_hur result: {result}")

            # get immediately after create returning Unable to find the resource. give 5 secs
            time.sleep(5)
            pair = self.gateway.get_replication_pair(spec)
            self.connection_info.changed = True
            return pair
        except Exception as ex:
            logger.writeDebug(f"HUR create failed: {ex}")
            # if the HUR creation fails, delete the secondary volume
            err_msg = HurFailedMsg.PAIR_CREATION_FAILED.value + str(ex)
            if secondary_vol_id:
                if spec.secondary_nvm_subsystem is not None:
                    rr_prov.delete_volume_when_nvme(
                        secondary_vol_id,
                        pvol.nvmSubsystemId,
                        spec.secondary_nvm_subsystem,
                        pvol.namespaceId,
                    )
                else:
                    if spec.provisioned_secondary_volume_id is None:
                        rr_prov.delete_volume(secondary_vol_id)
                logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def get_volume_by_id(self, primary_volume_id):
        volume = self.vol_gw.get_volume_by_id(primary_volume_id)
        # return vol_gw.get_volume_by_id(device_id, primary_volume_id)
        self.logger.writeDebug(f"PROV:get_volume_by_id:volume: {volume}")

        return volume

    @log_entry_exit
    def get_copy_group_list(self):
        return self.cg_gw.get_copy_group_list()
