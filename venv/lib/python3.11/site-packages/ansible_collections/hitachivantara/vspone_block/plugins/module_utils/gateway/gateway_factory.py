try:
    from ..common.hv_constants import ConnectionTypes, GatewayClassTypes
except ImportError:
    from common.hv_constants import ConnectionTypes, GatewayClassTypes

from .sdsb_compute_node_gateway import (
    SDSBComputeNodeDirectGateway,
)
from .sdsb_volume_gateway import SDSBVolumeDirectGateway
from .sdsb_chap_user_gateway import SDSBChapUserDirectGateway
from .sdsb_event_logs_gateway import SDSBEventLogsDirectGateway
from .sdsb_drives_gateway import SDSBBlockDrivesDirectGateway
from .sdsb_fault_domain_gateway import SDSBBlockFaultDomainDirectGateway
from .sdsb_control_port_gateway import SDSBBlockControlPortDirectGateway
from .sdsb_storage_controller_gateway import SDSBStorageControllerDirectGateway
from .sdsb_port_auth_gateway import SDSBPortAuthDirectGateway
from .sdsb_port_gateway import SDSBPortDirectGateway
from .sdsb_vps_gateway import SDSBVpsDirectGateway
from .sdsb_storage_node_gateway import SDSBStorageNodeDirectGateway
from .sdsb_storage_pool_gateway import SDSBStoragePoolDirectGateway
from .sdsb_cluster_gateway import SDSBClusterGateway
from .sdsb_job_gateway import SDSBJobGateway
from .sdsb_capacity_mgmt_settings_gateway import SDSBCapacityMgmtSettingGateway
from .sdsb_estimated_capacity_gateway import SDSBEstimatedCapacityGateway
from .sdsb_remote_iscsi_port_gateway import SDSBRemoteIscsiPortGateway
from .sdsb_journal_gateway import SDSBBlockJournalDirectGateway
from .sdsb_login_message_gateway import SDSBBlockLoginMessageDirectGateway
from .vsp_snapshot_gateway import VSPHtiSnapshotDirectGateway
from .vsp_volume import VSPVolumeDirectGateway
from .vsp_host_group_gateway import VSPHostGroupDirectGateway
from .vsp_shadow_image_pair_gateway import (
    VSPShadowImagePairDirectGateway,
)
from .vsp_storage_system_gateway import (
    VSPStorageSystemDirectGateway,
)
from .sdsb_storage_system_gateway import SDSBStorageSystemDirectGateway
from .vsp_iscsi_target_gateway import (
    VSPIscsiTargetDirectGateway,
)
from .vsp_storage_pool_gateway import (
    VSPStoragePoolDirectGateway,
)
from .vsp_journal_volume_gateway import (
    VSPSJournalVolumeDirectGateway,
)
from .vsp_parity_group_gateway import (
    VSPParityGroupDirectGateway,
)
from .vsp_storage_port_gateway import (
    VSPStoragePortDirectGateway,
)
from .vsp_copy_groups_gateway import VSPCopyGroupsDirectGateway
from .vsp_true_copy_gateway import VSPTrueCopyDirectGateway
from .vsp_hur_gateway import VSPHurDirectGateway
from .vsp_nvme_gateway import VSPOneNvmeSubsystemDirectGateway
from .vsp_resource_group_gateway import (
    VSPResourceGroupDirectGateway,
)
from .vsp_user_group_gateway import VSPUserGroupDirectGateway
from .vsp_user_gateway import VSPUserDirectGateway
from .vsp_gad_pair_gateway import VSPGadPairDirectGateway
from .vsp_cmd_dev_gateway import VSPCmdDevDirectGateway
from .vsp_rg_lock_gateway import (
    VSPResourceGroupLockDirectGateway,
)
from .vsp_remote_storage_registration_gw import (
    VSPRemoteStorageRegistrationDirectGateway,
)
from .vsp_quorum_disk_gateway import VSPQuorumDiskDirectGateway
from .vsp_remote_connection_gateway import VSPRemoteConnectionDirectGateway
from .vsp_external_volume_gateway import VSPExternalVolumeDirectGateway
from .vsp_iscsi_remote_connection_gateway import VSPIscsiRemoteConnectionDirectGateway
from .vsp_local_copy_group_gateway import (
    VSPLocalCopyGroupDirectGateway,
)
from .vsp_dynamic_pool_gateway import VspDynamicPoolGateway
from .vsp_uvm_gateway import VSPUvmGateway
from .vsp_clpr_gateway import VSPClprDirectGateway
from .vsp_external_parity_group_gateway import VSPExternalParityGroupGateway
from .vsp_spm_gateway import VSPSpmGateway
from .vsp_storage_system_monitor_gateway import VSPStorageSystemMonitorGateway
from .sdsb_cluster_information_gateway import SDSBBlockClusterInformationDirectGateway
from .sdsb_user_gateway import SDSBUserGateway
from .sdsb_bmc_access_setting_gw import SDSBBlockBmcAccessSettingGateway
from .sdsb_software_update_gateway import SDSBSoftwareUpdateGateway

GATEWAY_MAP = {
    ConnectionTypes.DIRECT: {
        GatewayClassTypes.VSP_EXT_VOLUME: VSPExternalVolumeDirectGateway,
        GatewayClassTypes.VSP_VOLUME: VSPVolumeDirectGateway,
        GatewayClassTypes.VSP_HOST_GROUP: VSPHostGroupDirectGateway,
        GatewayClassTypes.VSP_SHADOW_IMAGE_PAIR: VSPShadowImagePairDirectGateway,
        GatewayClassTypes.VSP_STORAGE_SYSTEM: VSPStorageSystemDirectGateway,
        GatewayClassTypes.VSP_ISCSI_TARGET: VSPIscsiTargetDirectGateway,
        GatewayClassTypes.VSP_STORAGE_POOL: VSPStoragePoolDirectGateway,
        GatewayClassTypes.VSP_SNAPSHOT: VSPHtiSnapshotDirectGateway,
        GatewayClassTypes.VSP_PARITY_GROUP: VSPParityGroupDirectGateway,
        GatewayClassTypes.VSP_NVME_SUBSYSTEM: VSPOneNvmeSubsystemDirectGateway,
        GatewayClassTypes.VSP_TRUE_COPY: VSPTrueCopyDirectGateway,
        GatewayClassTypes.VSP_QUORUM_DISK: VSPQuorumDiskDirectGateway,
        GatewayClassTypes.VSP_GAD_PAIR: VSPGadPairDirectGateway,
        GatewayClassTypes.VSP_HUR: VSPHurDirectGateway,
        GatewayClassTypes.VSP_RESOURCE_GROUP: VSPResourceGroupDirectGateway,
        GatewayClassTypes.VSP_COPY_GROUPS: VSPCopyGroupsDirectGateway,
        GatewayClassTypes.VSP_LOCAL_COPY_GROUP: VSPLocalCopyGroupDirectGateway,
        GatewayClassTypes.VSP_CLPR: VSPClprDirectGateway,
        GatewayClassTypes.VSP_CMD_DEV: VSPCmdDevDirectGateway,
        GatewayClassTypes.VSP_RG_LOCK: VSPResourceGroupLockDirectGateway,
        GatewayClassTypes.VSP_JOURNAL_VOLUME: VSPSJournalVolumeDirectGateway,
        GatewayClassTypes.VSP_REMOTE_STORAGE_REGISTRATION: VSPRemoteStorageRegistrationDirectGateway,
        GatewayClassTypes.VSP_USER_GROUP: VSPUserGroupDirectGateway,
        GatewayClassTypes.VSP_USER: VSPUserDirectGateway,
        GatewayClassTypes.STORAGE_PORT: VSPStoragePortDirectGateway,
        GatewayClassTypes.VSP_REMOTE_CONNECTION: VSPRemoteConnectionDirectGateway,
        GatewayClassTypes.VSP_ISCSI_REMOTE_CONNECTION: VSPIscsiRemoteConnectionDirectGateway,
        GatewayClassTypes.VSP_DYNAMIC_POOL: VspDynamicPoolGateway,
        GatewayClassTypes.VSP_UVM: VSPUvmGateway,
        GatewayClassTypes.VSP_EXT_PARITY_GROUP: VSPExternalParityGroupGateway,
        GatewayClassTypes.VSP_SPM: VSPSpmGateway,
        GatewayClassTypes.VSP_STORAGE_MONITOR: VSPStorageSystemMonitorGateway,
        # Add SDSB Gateways below and VSP Gayeways above this line
        GatewayClassTypes.SDSB_CHAP_USER: SDSBChapUserDirectGateway,
        GatewayClassTypes.SDSB_COMPUTE_NODE: SDSBComputeNodeDirectGateway,
        GatewayClassTypes.SDSB_STORAGE_SYSTEM: SDSBStorageSystemDirectGateway,
        GatewayClassTypes.SDSB_VOLUME: SDSBVolumeDirectGateway,
        GatewayClassTypes.SDSB_PORT_AUTH: SDSBPortAuthDirectGateway,
        GatewayClassTypes.SDSB_PORT: SDSBPortDirectGateway,
        GatewayClassTypes.SDSB_VPS: SDSBVpsDirectGateway,
        GatewayClassTypes.SDSB_STORAGE_NODE: SDSBStorageNodeDirectGateway,
        GatewayClassTypes.SDSB_STORAGE_POOL: SDSBStoragePoolDirectGateway,
        GatewayClassTypes.SDSB_CLUSTER: SDSBClusterGateway,
        GatewayClassTypes.SDSB_JOB: SDSBJobGateway,
        GatewayClassTypes.SDSB_EVENT_LOGS: SDSBEventLogsDirectGateway,
        GatewayClassTypes.SDSB_BLOCK_DRIVES: SDSBBlockDrivesDirectGateway,
        GatewayClassTypes.SDSB_FAULT_DOMAIN: SDSBBlockFaultDomainDirectGateway,
        GatewayClassTypes.SDSB_STORAGE_CONTROLLER: SDSBStorageControllerDirectGateway,
        GatewayClassTypes.SDSB_CONTROL_PORT: SDSBBlockControlPortDirectGateway,
        GatewayClassTypes.SDSB_CLUSTER_INFORMATION: SDSBBlockClusterInformationDirectGateway,
        GatewayClassTypes.SDSB_USER: SDSBUserGateway,
        GatewayClassTypes.SDSB_BMC_ACCESS_SETTING: SDSBBlockBmcAccessSettingGateway,
        GatewayClassTypes.SDSB_CAPACITY_MGMT_SETTING: SDSBCapacityMgmtSettingGateway,
        GatewayClassTypes.SDSB_ESTIMATED_CAPACITY: SDSBEstimatedCapacityGateway,
        GatewayClassTypes.SDSB_REMOTE_ISCSI_PORT: SDSBRemoteIscsiPortGateway,
        GatewayClassTypes.SDSB_SOFTWARE_UPDATE: SDSBSoftwareUpdateGateway,
        GatewayClassTypes.SDSB_JOURNAL: SDSBBlockJournalDirectGateway,
        GatewayClassTypes.SDSB_LOGIN_MESSAGE: SDSBBlockLoginMessageDirectGateway,
    },
}


class GatewayFactory:
    """Factory class to get the gateway object"""

    @staticmethod
    def get_gateway(connection_info, gateway_type):
        """
        it takes the connection_info and the gateway_type argument and returns the gateway object
        """
        connection_map = GATEWAY_MAP.get(connection_info.connection_type.lower())
        if not connection_map:
            raise ValueError(
                f"Unsupported connection type: {connection_info.connection_type}"
            )

        gateway_class = connection_map.get(gateway_type)
        if not gateway_class:
            raise ValueError(f"Unsupported gateway type: {gateway_type}")

        return gateway_class(connection_info)
