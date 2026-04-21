from typing import Dict, Any

try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_constants import ConnectionTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        convert_decimal_size_to_bytes,
    )
    from ..message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg, TrueCopyFailedMsg
    from ..model.vsp_true_copy_models import (
        VSPTrueCopyPairInfoList,
    )
    from .vsp_remote_replication_helper import RemoteReplicationHelperForSVol
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_constants import ConnectionTypes
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        convert_decimal_size_to_bytes,
    )
    from message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg, TrueCopyFailedMsg
    from model.vsp_true_copy_models import (
        VSPTrueCopyPairInfoList,
    )
    from vsp_remote_replication_helper import RemoteReplicationHelperForSVol

logger = Log()


class VSPTrueCopyProvisioner:

    def __init__(self, connection_info, serial):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_TRUE_COPY
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
        return self.gateway.get_all_replication_pairs(self.serial)

    @log_entry_exit
    def get_tc_for_primary_vol_id(self, primary_vol_id):
        logger.writeDebug(f"PROV:60 :self.serial= {self.serial}")
        all_tc_pairs = self.gateway.get_all_true_copy_pairs(self.serial)
        for tc in all_tc_pairs.data:
            # logger.writeDebug(f"PROV:60 tc= {tc}")
            if hasattr(tc, "ldevId"):
                if tc.ldevId == primary_vol_id:
                    return tc
            if hasattr(tc, "primaryVolumeId"):
                if int(tc.primaryVolumeId) == int(primary_vol_id):
                    return tc
        return None

    def get_tc_for_secondary_vol_id(self, svol):
        logger.writeDebug(f"PROV:60 :self.serial= {self.serial}")
        all_tc_pairs = self.gateway.get_all_true_copy_pairs(self.serial)
        for tc in all_tc_pairs.data:
            logger.writeDebug(f"PROV:60 tc= {tc}")
            if hasattr(tc, "secondaryVolumeId"):
                if int(tc.secondaryVolumeId) == int(svol):
                    return tc
        return None

    @log_entry_exit
    def get_tc_by_cp_group_and_primary_vol_id(self, spec):
        tc = self.cg_gw.get_tc_by_cp_group_and_primary_vol_id(spec)
        logger.writeDebug(f"PROV:get_tc_by_cp_group_and_primary_vol_id:tc= {tc}")
        spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(spec)
        return tc

    @log_entry_exit
    def get_true_copy_facts(self, spec=None, serial=None):
        tc_pairs = self.get_all_tc_pairs_direct(spec=spec)
        logger.writeDebug(f"PV:: pairs=  {tc_pairs}")
        if tc_pairs is None:
            return tc_pairs
        if spec is None:
            return tc_pairs
        else:
            ret_tc_pairs = self.apply_filters(tc_pairs, spec)
            return VSPTrueCopyPairInfoList(data=ret_tc_pairs)

    @log_entry_exit
    def get_all_tc_pairs_direct(self, serial=None, spec=None):
        if serial is None:
            serial = self.serial
        if spec is None:
            ret_list = self.gateway.get_all_true_copy_pairs(serial)
            logger.writeDebug(
                f"PROV:get_all_tc_pairs_direct:ret_list= {ret_list} serial = {serial}"
            )
            ret_list = [
                tc for tc in ret_list.data if tc.replicationType.upper() == "TC"
            ]
            return ret_list

        spec.secondary_storage_serial_number = self.gateway.get_secondary_serial(spec)

        if (
            spec.copy_group_name
            and spec.copy_pair_name
            and spec.local_device_group_name
            and spec.remote_device_group_name
        ):
            return self.cg_gw.get_remote_copy_pair_by_id(spec)

        if spec.copy_group_name and spec.copy_pair_name:
            return self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)

        if spec.copy_group_name:
            return self.cg_gw.get_remote_pairs_for_a_copy_group(spec)

        if spec.primary_volume_id:
            return self.cg_gw.get_remote_pairs_by_pvol(spec)

        if spec.secondary_volume_id:
            return self.cg_gw.get_remote_pairs_by_svol(spec)

        ret_list = self.cg_gw.get_all_remote_pairs_from_copy_groups(spec)
        return ret_list

    @log_entry_exit
    def apply_filters(self, tc_pairs, spec):
        result = tc_pairs
        if spec.primary_volume_id is not None:
            result = self.apply_filter_pvol(result, spec.primary_volume_id)
        if spec.secondary_volume_id is not None:
            result = self.apply_filter_svol(result, spec.secondary_volume_id)

        return result

    @log_entry_exit
    def apply_filter_pvol(self, tc_pairs, primary_vol_id):
        ret_val = []
        for tc in tc_pairs:
            if tc.pvolLdevId == primary_vol_id or tc.svolLdevId == primary_vol_id:
                ret_val.append(tc)
        return ret_val

    @log_entry_exit
    def apply_filter_svol(self, tc_pairs, secondary_vol_id):
        ret_val = []

        for tc in tc_pairs:
            if tc.svolLdevId == secondary_vol_id or tc.pvolLdevId == secondary_vol_id:
                ret_val.append(tc)
        return ret_val

    @log_entry_exit
    def get_tc_copypairs(self, pair):

        if isinstance(pair, list):
            return self.get_tc_copypairs_from_list(pair)

        tc_pairs = []

        logger.writeDebug("sng20241115 :pair={}", pair)
        copyPairs = pair.copyPairs
        if copyPairs is None:
            return

        for copyPair in copyPairs:
            if copyPair.replicationType == "TC":
                tc_pairs.append(copyPair)

        return tc_pairs

    @log_entry_exit
    def get_tc_copypairs_from_list(self, cgList):
        tc_pairs = []

        for cg in cgList:
            if cg is None:
                continue
            logger.writeDebug("sng20241115 :cg={}", cg)
            copyPairs = cg.copyPairs
            if copyPairs is None:
                continue

            for copyPair in copyPairs:
                if copyPair.replicationType == "TC":
                    tc_pairs.append(copyPair)

        return tc_pairs

    def get_tc_pair_by_pvol_new(self, copyPairs, volume_id):
        logger.writeDebug("sng20241115 :copyPairs={}", copyPairs)
        if copyPairs is None:
            return
        if not isinstance(copyPairs, list):
            copyPairs = [copyPairs]
        for copyPair in copyPairs:
            if copyPair.pvolLdevId == volume_id:
                # just return the first one for now
                logger.writeDebug("sng20241115 found copyPair={}", copyPair)
                return copyPair

    @log_entry_exit
    def delete_true_copy_pair(self, spec=None):
        self.connection_info.changed = False
        comment = None

        # tc_pair_id = "remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName,copyPairName"
        # If we have both copy_group_name and copy_pair_name, we can delete the pair directly
        if spec.copy_group_name and spec.copy_pair_name:
            tc = self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)
            pair_id = self.gateway.delete_true_copy_pair_by_pair_id(spec)
            if spec.should_delete_svol is True:
                if tc is not None and len(tc) > 0:
                    for tc_pair in tc:
                        if tc_pair.copyPairName == spec.copy_pair_name:
                            spec.secondary_volume_id = tc_pair.svolLdevId
                rr_prov = RemoteReplicationHelperForSVol(
                    spec.secondary_connection_info, spec.secondary_storage_serial_number
                )
                rr_prov.delete_volume_and_all_mappings(spec.secondary_volume_id)
            self.connection_info.changed = True
            return pair_id, comment

        # Deleting TC by primary_volume_id is only supported for VSP One
        if spec.primary_volume_id:
            # secondary_storage_info = self.gateway.get_secondary_storage_info(spec.secondary_connection_info)
            # storage_model = secondary_storage_info["model"]
            storage_model = self.get_storage_model(spec)
            if "VSP One" not in storage_model:
                comment = VSPTrueCopyValidateMsg.DELETE_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED.value.format(
                    storage_model
                )
                return None, comment
            else:
                comment = None
                if spec.copy_group_name:
                    copy_group = self.get_copy_group_by_name(spec)
                    logger.writeDebug(
                        f"PV:delete_true_copy_pair:copy_group={copy_group}"
                    )
                    if copy_group:
                        self.connection_info.changed = True
                        return (
                            self.gateway.delete_true_copy_pair_by_copy_group_and_pvol_id(
                                spec.primary_volume_id
                            ),
                            comment,
                        )
                    else:
                        comment = VSPTrueCopyValidateMsg.COPY_GROUP_NAME_NOT_FOUND.value.format(
                            spec.copy_group_name
                        )
                        return None, comment
                else:
                    self.connection_info.changed = True
                    return (
                        self.gateway.delete_true_copy_pair_by_primary_volume_id(
                            self.cg_gw, spec
                        ),
                        comment,
                    )

    @log_entry_exit
    def get_copy_group_by_name(self, spec):
        return self.cg_gw.get_copy_group_by_name(spec)

    @log_entry_exit
    def get_storage_model(self, spec):
        secondary_storage_info = self.gateway.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        storage_model = secondary_storage_info["model"]
        return storage_model

    @log_entry_exit
    def resync_true_copy_pair(self, spec=None):
        tc = None

        pair_id = None
        # if we have copy_group_name and copy_pair_name, we can directly resync the
        # pair and return the pair information
        if spec.copy_group_name and spec.copy_pair_name:
            tc = self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)
            if (
                tc is not None
                and len(tc) > 0
                and tc[0].svolStatus == "PAIR"
                and tc[0].pvolStatus == "PAIR"
            ):
                return tc[0]
            else:
                pair_id = self.gateway.resync_true_copy_pair(spec)
                logger.writeDebug(f"PV:resync_true_copy_pair: pair_id=  {pair_id}")
                if pair_id:
                    pair = self.cg_gw.get_one_copy_pair_by_id(
                        pair_id, spec.secondary_connection_info
                    )
                    self.connection_info.changed = True
                    return pair
        if spec.primary_volume_id:
            if spec.copy_group_name:
                copy_group = self.get_copy_group_by_name(spec)
                logger.writeDebug(f"PV:delete_true_copy_pair:copy_group={copy_group}")
                if copy_group:
                    self.connection_info.changed = True
                    pair_id = (
                        self.gateway.resync_true_copy_pair_by_copy_group_and_pvol_id(
                            self.cg_gw, spec
                        )
                    )
                else:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_RESYNC_FAILED.value
                        + VSPTrueCopyValidateMsg.COPY_GROUP_NAME_NOT_FOUND.value.format(
                            spec.copy_group_name
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
            else:
                storage_model = self.get_storage_model(spec)
                if "VSP One" not in storage_model:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_RESYNC_FAILED.value
                        + VSPTrueCopyValidateMsg.RESYNC_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED.value.format(
                            storage_model
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    self.connection_info.changed = True
                    pair_id = self.gateway.resync_true_copy_pair_by_primary_volume_id(
                        self.cg_gw, spec
                    )
        if pair_id is None:
            err_msg = (
                TrueCopyFailedMsg.PAIR_RESYNC_FAILED.value
                + VSPTrueCopyValidateMsg.NO_TC_PAIR_FOUND_FOR_INPUTS.value
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        pair = self.cg_gw.get_one_copy_pair_by_id(
            pair_id, spec.secondary_connection_info
        )
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def swap_resync_true_copy_pair(self, spec=None):
        tc = None
        pair_id = None
        # if we have copy_group_name and copy_pair_name, we directly swap_resync the
        # pair and return the pair information
        if spec.copy_group_name and spec.copy_pair_name:
            tc = self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)
            if (
                tc is not None
                and len(tc) > 0
                and tc[0].svolStatus == "PAIR"
                and tc[0].pvolStatus == "PAIR"
            ):
                return tc[0]
            else:
                pair_id = self.gateway.swap_resync_true_copy_pair(spec)
                logger.writeDebug(f"PV:swap_resync_true_copy_pair: pair_id=  {pair_id}")
                if pair_id:
                    pair = self.cg_gw.get_one_copy_pair_by_id(
                        pair_id, spec.secondary_connection_info
                    )
                    self.connection_info.changed = True
                    return pair

        if spec.primary_volume_id:
            if spec.copy_group_name:
                copy_group = self.get_copy_group_by_name(spec)
                if copy_group:
                    self.connection_info.changed = True
                    pair_id = self.gateway.swap_resync_true_copy_pair_by_copy_group_and_pvol_id(
                        self.cg_gw, spec
                    )
                else:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_SWAP_RESYNC_FAILED.value
                        + VSPTrueCopyValidateMsg.COPY_GROUP_NAME_NOT_FOUND.value.format(
                            spec.copy_group_name
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
            else:
                storage_model = self.get_storage_model(spec)
                if "VSP One" not in storage_model:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_SWAP_RESYNC_FAILED.value
                        + VSPTrueCopyValidateMsg.RESYNC_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED.value.format(
                            storage_model
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    self.connection_info.changed = True
                    pair_id = (
                        self.gateway.swap_resync_true_copy_pair_by_primary_volume_id(
                            self.cg_gw, spec
                        )
                    )
        if pair_id is None:
            err_msg = (
                TrueCopyFailedMsg.PAIR_SWAP_RESYNC_FAILED.value
                + VSPTrueCopyValidateMsg.NO_TC_PAIR_FOUND_FOR_INPUTS.value
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        # DO NOT NEED THIS FUNCTION AS WE ARE NOW DIRECTLY RUNNING FROM SECONDARY
        # swap_pair_id =  self.gateway.swap_resync_true_copy_pair(spec)
        # pair_id = self.gateway.get_pair_id_from_swap_pair_id(swap_pair_id, spec.secondary_connection_info)
        # logger.writeDebug(f"PV:swap_resync_true_copy_pair: swap_pair_id = {swap_pair_id} pair_id = {pair_id}")
        pair = self.cg_gw.get_one_copy_pair_by_id(
            pair_id, spec.secondary_connection_info
        )
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def split_true_copy_pair(self, spec=None):
        tc = None
        pair_id = None
        if spec.copy_group_name and spec.copy_pair_name:
            # if we have copy_group_name and copy_pair_name, we directly split the
            # pair and return the pair information
            tc = self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)
            logger.writeDebug(f"PV:split_true_copy_pair: tc=  {tc}")
            if (
                tc is not None
                and len(tc) > 0
                and tc[0].svolStatus == "SSUS"
                and tc[0].pvolStatus == "PSUS"
            ):
                return tc[0]
            else:
                pair_id = self.gateway.split_true_copy_pair(spec)
                logger.writeDebug(f"PV:split_true_copy_pair: pair_id=  {pair_id}")
                if pair_id:
                    pair = self.cg_gw.get_one_copy_pair_by_id(
                        pair_id, spec.secondary_connection_info
                    )
                    self.connection_info.changed = True
                    return pair

        if spec.primary_volume_id:
            if spec.copy_group_name:
                copy_group = self.get_copy_group_by_name(spec)
                logger.writeDebug(f"PV:delete_true_copy_pair:copy_group={copy_group}")
                if copy_group:
                    self.connection_info.changed = True
                    pair_id = (
                        self.gateway.split_true_copy_pair_by_copy_group_and_pvol_id(
                            self.cg_gw, spec
                        )
                    )
                else:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_SPLIT_FAILED.value
                        + VSPTrueCopyValidateMsg.COPY_GROUP_NAME_NOT_FOUND.value.format(
                            spec.copy_group_name
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

            else:
                storage_model = self.get_storage_model(spec)
                if "VSP One" not in storage_model:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_SPLIT_FAILED.value
                        + VSPTrueCopyValidateMsg.SPLIT_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED.value.format(
                            storage_model
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    self.connection_info.changed = True
                    pair_id = self.gateway.split_true_copy_pair_by_primary_volume_id(
                        self.cg_gw, spec
                    )
        if pair_id is None:
            err_msg = (
                TrueCopyFailedMsg.PAIR_SPLIT_FAILED.value
                + VSPTrueCopyValidateMsg.NO_TC_PAIR_FOUND_FOR_INPUTS.value
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        pair = self.cg_gw.get_one_copy_pair_by_id(
            pair_id, spec.secondary_connection_info
        )
        self.connection_info.changed = True
        return pair

    @log_entry_exit
    def swap_split_true_copy_pair(self, spec=None):
        tc = None

        pair_id = None
        # if we have copy_group_name and copy_pair_name, we directly swap_split the
        # pair and return the pair information
        if spec.copy_group_name and spec.copy_pair_name:
            tc = self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)
            if tc:
                logger.writeDebug(f"PV:swap_split_true_copy_pair: tc=  {tc}")
            if (
                tc is not None
                and len(tc) > 0
                and tc[0].svolStatus == "SSWS"
                and tc[0].pvolStatus == "PSUS"
            ):
                return tc[0]
            else:
                pair_id = self.gateway.swap_split_true_copy_pair(spec)
                logger.writeDebug(f"PV:swap_split_true_copy_pair: pair_id=  {pair_id}")
                if pair_id:
                    pair = self.cg_gw.get_one_copy_pair_by_id(
                        pair_id, spec.secondary_connection_info
                    )
                    self.connection_info.changed = True
                    return pair

        if spec.primary_volume_id:
            if spec.copy_group_name:
                copy_group = self.get_copy_group_by_name(spec)
                logger.writeDebug(f"PV:delete_true_copy_pair:copy_group={copy_group}")
                if copy_group:
                    self.connection_info.changed = True
                    pair_id = self.gateway.swap_split_true_copy_pair_by_copy_group_and_pvol_id(
                        self.cg_gw, spec
                    )
                else:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_SWAP_SPLIT_FAILED.value
                        + VSPTrueCopyValidateMsg.COPY_GROUP_NAME_NOT_FOUND.value.format(
                            spec.copy_group_name
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
            else:
                storage_model = self.get_storage_model(spec)
                if "VSP One" not in storage_model:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_SWAP_SPLIT_FAILED.value
                        + VSPTrueCopyValidateMsg.SPLIT_TC_BY_PRIMARY_VOLUME_ID_NOT_SUPPORTED.value.format(
                            storage_model
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    self.connection_info.changed = True
                    pair_id = (
                        self.gateway.swap_split_true_copy_pair_by_primary_volume_id(
                            self.cg_gw, spec
                        )
                    )
        if pair_id is None:
            err_msg = (
                TrueCopyFailedMsg.PAIR_SWAP_SPLIT_FAILED.value
                + VSPTrueCopyValidateMsg.NO_TC_PAIR_FOUND_FOR_INPUTS.value
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        # swap_pair_id =  self.gateway.swap_split_true_copy_pair(spec)
        # pair_id = self.gateway.get_pair_id_from_swap_pair_id(swap_pair_id, spec.secondary_connection_info)
        # logger.writeDebug(f"PV:swap_resync_true_copy_pair: swap_pair_id = {swap_pair_id} pair_id = {pair_id}")

        pair = self.cg_gw.get_one_copy_pair_by_id(
            pair_id, spec.secondary_connection_info
        )
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
    def resize_true_copy_copy_pair(self, spec=None):
        tc = None
        pair_id = None
        if spec.copy_group_name and spec.copy_pair_name:
            tc = self.cg_gw.get_remote_pairs_by_copy_group_and_copy_pair_name(spec)
            logger.writeDebug(
                f"PV:resize_true_copy_copy_pair: tc= {tc} len _tc= {len(tc)}"
            )
            if tc is not None and len(tc) > 0:
                pvol_id = tc[0].pvolLdevId
                pvol_data = self.vol_gw.get_volume_by_id(pvol_id)
                if pvol_data is None:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_RESIZE_FAILED.value
                        + VSPTrueCopyValidateMsg.NO_PRIMARY_VOLUME_FOUND.value.format(
                            spec.primary_volume_id
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

                if pvol_data.emulationType == "NOT DEFINED":
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_RESIZE_FAILED.value
                        + VSPTrueCopyValidateMsg.INVALID_EMULATION_TYPE.value.format(
                            pvol_data.emulationType
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

                resize_needed = self.is_resize_needed(pvol_data, spec)
                if resize_needed is False:
                    err_msg = (
                        TrueCopyFailedMsg.PAIR_RESIZE_FAILED.value
                        + VSPTrueCopyValidateMsg.REDUCE_VOLUME_SIZE_NOT_SUPPORTED.value
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

                else:
                    pair_id = self.gateway.resize_true_copy_pair(tc[0], spec)
                    logger.writeDebug(
                        f"PV:resize_true_copy_copy_pair: pair_id=  {pair_id}"
                    )
                    pair = self.gateway.get_replication_pair(spec)
                    self.connection_info.changed = True
                    return pair
            else:
                err_msg = (
                    TrueCopyFailedMsg.PAIR_RESIZE_FAILED.value
                    + VSPTrueCopyValidateMsg.NO_TC_PAIR_FOUND_FOR_INPUTS.value
                )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

    @log_entry_exit
    def create_true_copy(self, spec) -> Dict[str, Any]:
        tc_exits = self.get_tc_by_cp_group_and_primary_vol_id(spec)
        if tc_exits:
            return tc_exits
        copy_group = self.get_copy_group_by_name(spec)
        if copy_group is None:
            spec.is_new_group_creation = True
        else:
            spec.is_new_group_creation = False

        pvol = self.get_volume_by_id(spec.primary_volume_id)
        logger.writeDebug(f"PV:create_true_copy: pvol = {pvol}")
        if pvol is None:
            err_msg = (
                TrueCopyFailedMsg.PAIR_CREATION_FAILED.value
                + VSPTrueCopyValidateMsg.NO_PRIMARY_VOLUME_FOUND.value.format(
                    spec.primary_volume_id
                )
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        if pvol.emulationType == "NOT DEFINED":
            err_msg = (
                TrueCopyFailedMsg.PAIR_CREATION_FAILED.value
                + VSPTrueCopyValidateMsg.INVALID_EMULATION_TYPE.value.format(
                    str(pvol.emulationType)
                )
            )
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        secondary_connection_info = spec.secondary_connection_info
        secondary_connection_info.connection_type = ConnectionTypes.DIRECT
        rr_prov = RemoteReplicationHelperForSVol(
            secondary_connection_info, spec.secondary_storage_serial_number
        )
        secondary_vol_id = None
        try:
            if spec.secondary_nvm_subsystem is not None:
                secondary_vol_id = rr_prov.get_secondary_volume_id_when_nvme(pvol, spec)
            elif spec.secondary_iscsi_targets is not None:
                secondary_vol_id = rr_prov.get_secondary_volume_id(pvol, spec, True)
            else:
                secondary_vol_id = rr_prov.get_secondary_volume_id(pvol, spec, False)
            spec.secondary_volume_id = secondary_vol_id
            # spec.is_data_reduction_force_copy = pvol.isDataReductionShareEnabled
            result = self.gateway.create_true_copy(spec)
            logger.writeDebug(f"create_true_copy: {result}")
            pair = self.cg_gw.get_one_copy_pair_by_id(
                result, spec.secondary_connection_info
            )
            self.connection_info.changed = True
            return pair
        except Exception as ex:
            # if the TC creation fails, delete the secondary volume if it was created
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
            err_msg = TrueCopyFailedMsg.PAIR_CREATION_FAILED.value + str(ex)
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def get_volume_by_id(self, primary_volume_id):

        volume = self.vol_gw.get_volume_by_id(primary_volume_id)
        # return vol_gw.get_volume_by_id(device_id, primary_volume_id)
        logger.writeDebug(f"PROV:get_volume_by_id:volume: {volume}")

        return volume
