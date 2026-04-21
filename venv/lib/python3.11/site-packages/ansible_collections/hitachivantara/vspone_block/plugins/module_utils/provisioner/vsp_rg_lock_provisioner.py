import time

try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes, ConnectionTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_rg_lock_models import (
        VSPResourceGroupNameId,
        VSPResourceGroupLockInfo,
    )
    from ..message.vsp_resource_group_msgs import VSPResourceGroupValidateMsg


except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes, ConnectionTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.vsp_rg_lock_models import (
        VSPResourceGroupNameId,
        VSPResourceGroupLockInfo,
    )
    from message.vsp_resource_group_msgs import VSPResourceGroupValidateMsg

logger = Log()


class VSPResourceGroupLockProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_RG_LOCK
        )
        self.rg_gw = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_RESOURCE_GROUP
        )
        self.connection_info = connection_info
        self.serial = serial
        if serial:
            self.gateway.set_serial(serial)
            self.rg_gw.set_serial(serial)

    @log_entry_exit
    def lock_resource_group(self, spec):
        try:
            if self.connection_info.connection_type == ConnectionTypes.DIRECT:
                return self.lock_resource_group_direct(spec)
            else:
                return self.lock_resource_group_gateway(spec)
        except Exception as e:
            err_msg = VSPResourceGroupValidateMsg.RG_LOCK_FAILED.value + str(e)
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def unlock_resource_group(self, spec):
        try:
            if self.connection_info.connection_type == ConnectionTypes.DIRECT:
                return self.unlock_resource_group_direct(spec)
            else:
                return self.unlock_resource_group_gateway(spec)
        except Exception as e:
            err_msg = VSPResourceGroupValidateMsg.RG_UNLOCK_FAILED.value + str(e)
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def lock_resource_group_direct(self, spec):
        """Lock Resource Group"""
        lock_session_id, lock_token, remote_lock_session_id, remote_lock_token = (
            self.gateway.lock_resource_group(spec)
        )
        locked_rgs = self.get_locked_resource_groups(lock_session_id)

        remote_locked_rgs = None
        if spec.secondary_connection_info:
            remote_locked_rgs = self.get_remote_locked_resource_groups(
                spec, remote_lock_session_id
            )

        return VSPResourceGroupLockInfo(
            lock_session_id,
            lock_token,
            remote_lock_session_id,
            remote_lock_token,
            locked_rgs,
            remote_locked_rgs,
        )

    @log_entry_exit
    def lock_resource_group_gateway(self, spec):
        if spec.id and spec.name is None:
            rg = self.get_resouirce_group_by_rg_id(spec.id)
            if rg is None:
                err_msg = VSPResourceGroupValidateMsg.RG_NOT_FOUND.value
                logger.writeError(err_msg)
                raise ValueError(err_msg)
            else:
                spec.name = rg.resourceGroupName
        is_rg_locked, rg = self.is_gw_resource_group_locked(spec)
        logger.writeDebug(
            f"PROV:lock_resource_group_gateway:is_rg_locked={is_rg_locked} rg={rg}"
        )
        if is_rg_locked:
            return rg
        else:
            rg_id = self.gateway.lock_resource_group(spec)
            logger.writeDebug(
                f"PROV:lock_resource_group_gateway:is_rg_locked={is_rg_locked} rg_id={rg_id}"
            )
            time.sleep(60)
            new_rg = self.get_resource_group_by_id(rg_id)
            if new_rg and new_rg.locked is True:
                return new_rg
            else:
                retry_count = 0
                while retry_count < 5:
                    time.sleep(30)
                    new_rg = self.get_resource_group_by_id(rg_id)
                    logger.writeDebug(f"try number {retry_count + 1}")
                    logger.writeDebug(f"new_rg={new_rg}")
                    if new_rg and new_rg.locked is True:
                        return new_rg
                    else:
                        retry_count += 1
                if retry_count == 5:
                    err_msg = "Did not get updated resource group after 5 retries. So waited for 3.5 minutes."
                    logger.writeError(err_msg)
                    return new_rg

    @log_entry_exit
    def unlock_resource_group_direct(self, spec):
        """Unlock Resource Group"""
        local_rg_locked, rg = self.is_resource_groups_locked()
        remote_rg_locked = False
        if spec.secondary_connection_info:
            remote_rg_locked, rg = self.is_remote_resource_groups_locked(spec)
        if local_rg_locked or remote_rg_locked:
            return self.gateway.unlock_resource_group(spec)
        else:
            return VSPResourceGroupValidateMsg.RG_ALREADY_UNLOCKED.value

    @log_entry_exit
    def unlock_resource_group_gateway(self, spec):
        """Unlock Resource Group"""
        if spec.id and spec.name is None:
            rg = self.get_resouirce_group_by_rg_id(spec.id)
            if rg is None:
                err_msg = VSPResourceGroupValidateMsg.RG_NOT_FOUND.value
                logger.writeError(err_msg)
                raise ValueError(err_msg)
            else:
                spec.name = rg.resourceGroupName
        is_rg_locked, rg = self.is_gw_resource_group_locked(spec)
        if is_rg_locked:
            rg_id = self.gateway.unlock_resource_group(spec)
            logger.writeDebug(
                f"PROV:unlock_resource_group_gateway:is_rg_locked={is_rg_locked} rg_id={rg_id}"
            )
            time.sleep(60)
            return self.get_resource_group_by_id(rg_id)
        else:
            return VSPResourceGroupValidateMsg.RG_ALREADY_UNLOCKED.value

    @log_entry_exit
    def get_locked_resource_groups(self, lock_session_id):
        """Get Locked Resource Groups"""
        locked_rgs = self.rg_gw.get_resource_groups()
        logger.writeDebug(f"PROV:get_locked_resource_groups:locked_rg: {locked_rgs}")
        affected_rgs = []
        for rg in locked_rgs.data:
            if rg.lockSessionId == lock_session_id and rg.lockStatus == "Locked":
                affected_rgs.append(
                    VSPResourceGroupNameId(rg.resourceGroupName, rg.resourceGroupId)
                )
        return affected_rgs

    @log_entry_exit
    def get_remote_locked_resource_groups(self, spec, remote_lock_session_id):
        """Get Locked Resource Groups"""
        locked_rgs = self.rg_gw.get_remote_resource_groups(spec)
        logger.writeDebug(f"PROV:get_locked_resource_groups:locked_rg: {locked_rgs}")
        affected_rgs = []
        for rg in locked_rgs.data:
            if rg.lockSessionId == remote_lock_session_id and rg.lockStatus == "Locked":
                affected_rgs.append(
                    VSPResourceGroupNameId(rg.resourceGroupName, rg.resourceGroupId)
                )
        return affected_rgs

    @log_entry_exit
    def is_resource_groups_locked(self):
        """Check if Resource Group is Locked"""
        rgs = self.rg_gw.get_resource_groups()

        for rg in rgs.data:
            if rg.lockStatus == "Locked":
                return True, rg
        return False, None

    @log_entry_exit
    def is_remote_resource_groups_locked(self, spec):
        """Check if Remote Resource Group is Locked"""
        rgs = self.rg_gw.get_remote_resource_groups(spec)

        for rg in rgs.data:
            if rg.lockStatus == "Locked":
                return True, rg
        return False, None

    @log_entry_exit
    def is_gw_resource_group_locked(self, spec):
        """Check if Resource Group is Locked"""
        if spec.name is None:
            err_msg = VSPResourceGroupValidateMsg.RG_NAME_REQD_LOCK_UNLOCK.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        rgs = self.rg_gw.get_resource_groups(spec)
        rg_found = False
        for rg in rgs.data:
            if rg.resourceGroupName == spec.name:
                rg_found = True
                if rg.locked is True:
                    return True, rg
        if rg_found is True:
            return False, None
        else:
            err_msg = VSPResourceGroupValidateMsg.RG_NOT_FOUND.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def get_resource_group_by_id(self, rg_id):
        """Get Resource Group by ID"""
        logger.writeDebug(f"PROV:lock_resource_group_gateway: rg_id={rg_id}")
        rgs = self.rg_gw.get_resource_groups()
        for rg in rgs.data:
            if rg.resourceId == rg_id:
                return rg
        return None

    @log_entry_exit
    def get_resouirce_group_by_rg_id(self, rg_id):
        """Get Resource Group by ID"""
        logger.writeDebug(f"PROV:lock_resource_group_gateway: rg_id={rg_id}")
        rgs = self.rg_gw.get_resource_groups()
        for rg in rgs.data:
            logger.writeDebug(
                f"PROV:lock_resource_group_gateway: rg_id={rg.resourceGroupId}"
            )
            if rg.resourceGroupId == rg_id:
                return rg
        return None
