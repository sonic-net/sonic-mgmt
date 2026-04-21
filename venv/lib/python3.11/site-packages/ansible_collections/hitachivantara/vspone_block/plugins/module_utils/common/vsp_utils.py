import copy
import re

try:
    from ..common.hv_log import (
        Log,
    )
    from ..model.common_base_models import (
        ConnectionInfo,
        StorageSystemInfo,
        TenantInfo,
    )
    from ..model.vsp_volume_models import (
        VolumeFactSpec,
        CreateVolumeSpec,
        SalamanderCreateVolumeRequestSpec,
        SimpleAPIVolumeFactsSpec,
    )
    from ..model.vsp_host_group_models import GetHostGroupSpec, HostGroupSpec
    from ..model.vsp_shadow_image_pair_models import (
        GetShadowImageSpec,
        ShadowImagePairSpec,
    )
    from ..model.vsp_clpr_models import ClprFactSpec, ClprSpec
    from ..model.vsp_iscsi_target_models import IscsiTargetFactSpec, IscsiTargetSpec
    from ..model.vsp_storage_system_models import (
        StorageSystemFactSpec,
        VSPStorageSystemSpec,
        VSPStorageSystemMonitorSpec,
    )
    from ..model.vsp_snapshot_models import (
        SnapshotFactSpec,
        SnapshotReconcileSpec,
        SnapshotGroupSpec,
        SnapshotGroupFactSpec,
    )
    from ..model.vsp_storage_pool_models import PoolFactSpec, StoragePoolSpec
    from ..model.vsp_quorum_disk_models import (
        QuorumDiskSpec,
        QuorumDiskFactSpec,
    )
    from ..model.vsp_external_volume_models import (
        ExternalVolumeSpec,
        ExternalVolumeFactSpec,
    )
    from ..model.vsp_external_path_group_models import (
        ExternalPathGroupSpec,
        ExternalPathGroupFactSpec,
    )
    from ..model.vsp_external_parity_group_models import (
        ExternalParityGroupFactSpec,
        ExternalParityGroupSpec,
    )
    from ..model.vsp_storage_pool_models import JournalVolumeSpec, JournalVolumeFactSpec
    from ..model.vsp_parity_group_models import (
        ParityGroupFactSpec,
        ParityGroupSpec,
        DrivesFactSpec,
    )
    from ..model.vsp_storage_port_models import PortFactSpec, ChangePortSettingSpec
    from ..model.vsp_hur_models import HurSpec, HurFactSpec
    from ..model.vsp_true_copy_models import (
        TrueCopyFactSpec,
        TrueCopySpec,
    )
    from ..model.vsp_gad_pairs_models import VspGadPairSpec, GADPairFactSpec
    from ..model.vsp_nvme_models import VSPNvmeSubsystemFactSpec, VSPNvmeSubsystemSpec
    from ..model.uaig_subscriber_models import UnsubscribeSpec
    from ..model.vsp_copy_groups_models import CopyGroupsFactSpec, CopyGroupSpec
    from ..model.vsp_resource_group_models import (
        VSPResourceGroupSpec,
        VSPResourceGroupFactSpec,
    )
    from ..model.vsp_user_group_models import (
        VSPUserGroupSpec,
        VSPUserGroupFactSpec,
    )
    from ..model.vsp_user_models import (
        VSPUserSpec,
        VSPUserFactSpec,
    )
    from ..model.vsp_cmd_dev_models import VSPCmdDevSpec
    from ..model.vsp_rg_lock_models import VSPResourceGroupLockSpec
    from ..model.vsp_remote_storage_registration_models import (
        VSPRemoteStorageRegistrationFactSpec,
        VSPRemoteStorageRegistrationSpec,
    )
    from ..model.vsp_remote_connection_models import (
        RemoteConnectionSpec,
        RemoteConnectionFactSpec,
        RemoteIscsiConnectionSpec,
        RemoteIscsiConnectionFactSpec,
    )
    from ..model.vsp_local_copy_group_models import (
        LocalCopyGroupFactSpec,
        LocalCopyGroupSpec,
    )
    from ..model.vsp_dynamic_pool_models import (
        VspDynamicPoolSpec,
        VspDynamicPoolFactsSpec,
    )
    from ..model.vsp_initial_system_settings_models import (
        UploadFileSpec,
        SpecifyTransferDestinationFileSpec,
        SNMPRequestSpec,
    )
    from ..model.vsp_mp_blade_models import MPBladeFactsSpec
    from ..model.vsp_server_priority_manager_models import SpmFactSpec, SpmSpec
    from ..common.hv_constants import ConnectionTypes, StateValue
    from ..common.vsp_constants import AutomationConstants
    from ..common.ansible_common import (
        camel_to_snake_case,
        convert_to_bytes,
        check_range,
    )
    from ..model.vsp_one_server_models import (
        CreateServerSpec,
        ServerFactsSpec,
        ServerHBAFactsSpec,
    )
    from ..model.vsp_one_port_models import (
        VspOnePortSpec,
        vsp_one_port_args,
        VspOnePortFactsSpec,
    )
    from ..model.vsp_one_snapshot_models import (
        VspOneSnapshotFactSpec,
        VspOneSnapshotSpec,
        VspOneSnapshotGroupFactSpec,
    )
    from ..message.vsp_lun_msgs import VSPVolValidationMsg
    from ..message.vsp_snapshot_msgs import VSPSnapShotValidateMsg
    from ..message.vsp_parity_group_msgs import VSPParityGroupValidateMsg
    from ..message.vsp_storage_pool_msgs import VSPStoragePoolValidateMsg
    from ..message.vsp_iscsi_target_msgs import VSPIscsiTargetValidationMsg
    from ..message.vsp_host_group_msgs import VSPHostGroupValidationMsg
    from ..message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
    from ..message.vsp_hur_msgs import VSPHurValidateMsg
    from ..message.common_msgs import CommonMessage
    from ..message.vsp_shadow_image_pair_msgs import VSPShadowImagePairValidateMsg
    from ..message.vsp_storage_port_msgs import VSPStoragePortValidateMsg
    from ..message.vsp_gad_pair_msgs import GADPairValidateMSG
    from ..message.gateway_msgs import GatewayValidationMsg
    from ..message.vsp_nvm_msgs import VspNvmValidationMsg
    from ..message.vsp_resource_group_msgs import VSPResourceGroupValidateMsg
    from ..message.vsp_user_group_msgs import VSPUserGroupValidateMsg
    from ..message.vsp_user_msgs import VSPUserValidateMsg
    from ..message.vsp_dynamic_pool_msg import DynamicPoolValidationMsg
    from ..message.vsp_copy_group_msgs import VSPCopyGroupsValidateMsg
    from ..message.vsp_spm_msgs import VSPSpmValidateMsg
    from ..message.vsp_storage_system_monitor_msgs import (
        VSPStotageSystemMonitorValidateMsg,
    )
    from ..message.vsp_external_parity_group_msgs import (
        VSPSExternalParityGroupValidateMsg,
    )
except ImportError:
    from model.common_base_models import (
        ConnectionInfo,
        StorageSystemInfo,
        TenantInfo,
    )
    from model.vsp_volume_models import (
        VolumeFactSpec,
        CreateVolumeSpec,
        SalamanderCreateVolumeRequestSpec,
        SimpleAPIVolumeFactsSpec,
    )
    from model.vsp_host_group_models import GetHostGroupSpec, HostGroupSpec
    from model.vsp_shadow_image_pair_models import (
        GetShadowImageSpec,
        ShadowImagePairSpec,
    )
    from model.vsp_clpr_models import ClprFactSpec, ClprSpec
    from model.vsp_iscsi_target_models import IscsiTargetFactSpec, IscsiTargetSpec
    from model.vsp_snapshot_models import (
        SnapshotFactSpec,
        SnapshotReconcileSpec,
        SnapshotGroupSpec,
        SnapshotGroupFactSpec,
    )
    from model.vsp_storage_system_models import (
        StorageSystemFactSpec,
        VSPStorageSystemSpec,
        VSPStorageSystemMonitorSpec,
    )
    from model.vsp_storage_pool_models import PoolFactSpec, StoragePoolSpec
    from model.vsp_storage_pool_models import JournalVolumeSpec, JournalVolumeFactSpec
    from model.vsp_quorum_disk_models import (
        QuorumDiskSpec,
        QuorumDiskFactSpec,
    )
    from model.vsp_external_volume_models import (
        ExternalVolumeSpec,
        ExternalVolumeFactSpec,
    )
    from model.vsp_external_path_group_models import (
        ExternalPathGroupSpec,
        ExternalPathGroupFactSpec,
    )
    from model.vsp_external_parity_group_models import (
        ExternalParityGroupFactSpec,
        ExternalParityGroupSpec,
    )
    from model.vsp_parity_group_models import (
        ParityGroupFactSpec,
        ParityGroupSpec,
        DrivesFactSpec,
    )
    from model.vsp_storage_port_models import PortFactSpec, ChangePortSettingSpec
    from model.vsp_hur_models import HurSpec, HurFactSpec
    from model.vsp_true_copy_models import (
        TrueCopyFactSpec,
        TrueCopySpec,
    )
    from model.vsp_gad_pairs_models import VspGadPairSpec, GADPairFactSpec
    from model.vsp_nvme_models import VSPNvmeSubsystemFactSpec, VSPNvmeSubsystemSpec
    from model.uaig_subscriber_models import UnsubscribeSpec
    from model.vsp_copy_groups_models import CopyGroupsFactSpec, CopyGroupSpec
    from model.vsp_resource_group_models import (
        VSPResourceGroupSpec,
        VSPResourceGroupFactSpec,
    )
    from model.vsp_user_group_models import (
        VSPUserGroupSpec,
        VSPUserGroupFactSpec,
    )
    from model.vsp_user_models import (
        VSPUserSpec,
        VSPUserFactSpec,
    )
    from model.vsp_cmd_dev_models import VSPCmdDevSpec
    from model.vsp_rg_lock_models import VSPResourceGroupLockSpec
    from model.vsp_remote_storage_registration_models import (
        VSPRemoteStorageRegistrationFactSpec,
        VSPRemoteStorageRegistrationSpec,
    )
    from model.vsp_remote_connection_models import (
        RemoteConnectionSpec,
        RemoteConnectionFactSpec,
        RemoteIscsiConnectionSpec,
        RemoteIscsiConnectionFactSpec,
    )
    from model.vsp_local_copy_group_models import (
        LocalCopyGroupFactSpec,
        LocalCopyGroupSpec,
    )
    from model.vsp_dynamic_pool_models import (
        VspDynamicPoolSpec,
        VspDynamicPoolFactsSpec,
    )
    from model.vsp_mp_blade_models import MPBladeFactsSpec
    from model.vsp_initial_system_settings_models import (
        UploadFileSpec,
        SpecifyTransferDestinationFileSpec,
        SNMPRequestSpec,
    )
    from model.vsp_server_priority_manager_models import SpmFactSpec, SpmSpec
    from model.vsp_one_snapshot_models import (
        VspOneSnapshotFactSpec,
        VspOneSnapshotSpec,
    )
    from common.hv_constants import ConnectionTypes, StateValue
    from common.vsp_constants import AutomationConstants
    from common.ansible_common import camel_to_snake_case, convert_to_bytes, check_range
    from common.hv_log import Log

    from message.vsp_lun_msgs import VSPVolValidationMsg
    from message.common_msgs import CommonMessage
    from message.vsp_snapshot_msgs import VSPSnapShotValidateMsg
    from message.vsp_parity_group_msgs import VSPParityGroupValidateMsg
    from message.vsp_storage_pool_msgs import VSPStoragePoolValidateMsg
    from message.vsp_shadow_image_pair_msgs import VSPShadowImagePairValidateMsg
    from message.vsp_iscsi_target_msgs import VSPIscsiTargetValidationMsg
    from message.vsp_host_group_msgs import VSPHostGroupValidationMsg
    from message.vsp_storage_port_msgs import VSPStoragePortValidateMsg
    from message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
    from message.vsp_hur_msgs import VSPHurValidateMsg
    from message.vsp_gad_pair_msgs import GADPairValidateMSG
    from message.gateway_msgs import GatewayValidationMsg
    from message.vsp_nvm_msgs import VspNvmValidationMsg
    from message.vsp_user_group_msgs import VSPUserGroupValidateMsg
    from message.vsp_user_msgs import VSPUserValidateMsg
    from message.vsp_dynamic_pool_msg import DynamicPoolValidationMsg
    from message.vsp_copy_group_msgs import VSPCopyGroupsValidateMsg
    from message.vsp_spm_msgs import VSPSpmValidateMsg
    from message.vsp_storage_system_monitor_msgs import (
        VSPStotageSystemMonitorValidateMsg,
    )
    from message.vsp_external_parity_group_msgs import (
        VSPSExternalParityGroupValidateMsg,
    )


# # VSP Parameter manager # #
class VSPParametersManager:

    def __init__(self, params):
        self.params = params
        if (
            "storage_system_info" in self.params
            and self.params.get("storage_system_info") is not None
        ):
            self.storage_system_info = StorageSystemInfo(
                **self.params.get("storage_system_info", {"serial": None})
            )
        else:
            self.storage_system_info = StorageSystemInfo(**{"serial": None})
            if (
                self.params.get("connection_info").get("connection_type")
                == ConnectionTypes.GATEWAY
            ):
                raise ValueError(CommonMessage.STORAGE_SYSTEM_INFO_MISSING.value)

        self.connection_info = ConnectionInfo(**self.params.get("connection_info", {}))
        self.state = self.params.get("state", None)

        if "tenant_info" in self.params:
            self.tenant_info = TenantInfo(**self.params.get("tenant_info", {}))
        else:
            self.tenant_info = TenantInfo()

        if "secondary_connection_info" in self.params:
            self.secondary_connection_info = None
            if self.params.get("secondary_connection_info") is not None:
                self.secondary_connection_info = ConnectionInfo(
                    **self.params.get("secondary_connection_info", {})
                )
        else:
            self.secondary_connection_info = None

        VSPSpecValidators.validate_connection_info(self.connection_info)

    def get_state(self):
        return self.state

    def get_connection_info(self):
        return self.connection_info

    def get_serial(self):
        return self.storage_system_info.serial

    def get_tenant_info(self):
        return self.tenant_info

    def get_secondary_connection_info(self):
        return self.secondary_connection_info

    def set_volume_fact_spec(self):

        input_spec = VolumeFactSpec(
            **self.params["spec"] if self.params["spec"] else {}
        )
        VSPSpecValidators().validate_volume_facts(input_spec)
        return input_spec

    def set_volume_spec(self):
        input_spec = CreateVolumeSpec(**self.params["spec"])
        VSPSpecValidators().validate_volume_spec(self.get_state(), input_spec)
        return input_spec

    def get_host_group_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = GetHostGroupSpec(**self.params["spec"])
        else:
            input_spec = GetHostGroupSpec()
        return input_spec

    def host_group_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = HostGroupSpec(**self.params["spec"])
            VSPSpecValidators().validate_host_group_spec(input_spec)
        else:
            input_spec = HostGroupSpec()
        return input_spec

    def set_shadow_image_pair_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = GetShadowImageSpec(**self.params["spec"])
        else:
            input_spec = GetShadowImageSpec()
        return input_spec

    def set_clpr_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ClprFactSpec(**self.params["spec"])
        else:
            input_spec = ClprFactSpec()
        return input_spec

    def set_storage_system_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = StorageSystemFactSpec(**self.params["spec"])
        else:
            input_spec = StorageSystemFactSpec()
        return input_spec

    def set_storage_system_spec(self):

        input_spec = VSPStorageSystemSpec(**self.params["spec"])

        return input_spec

    def set_shadow_image_pair_spec(self):
        input_spec = ShadowImagePairSpec(**self.params["spec"])
        VSPSpecValidators.validate_shadow_image_module(input_spec, self.connection_info)
        return input_spec

    def set_clpr_spec(self):
        input_spec = ClprSpec(**self.params["spec"])
        # VSPSpecValidators.validate_shadow_image_module(input_spec, self.connection_info)
        return input_spec

    def get_iscsi_target_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = IscsiTargetFactSpec(**self.params["spec"])
        else:
            input_spec = IscsiTargetFactSpec()
        return input_spec

    def get_iscsi_target_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = IscsiTargetSpec(**self.params["spec"])
            VSPSpecValidators().validate_iscsi_target_spec(input_spec)
        else:
            input_spec = IscsiTargetSpec()
        return input_spec

    def get_snapshot_fact_spec(self):
        self.spec = SnapshotFactSpec(
            **self.params["spec"] if self.params["spec"] else {}
        )
        VSPSpecValidators().validate_snapshot_fact(self.spec)
        return self.spec

    def get_storage_system_monitor_fact_spec(self):
        spec = VSPStorageSystemMonitorSpec(
            **self.params["spec"] if self.params["spec"] else {}
        )
        VSPSpecValidators().validate_storage_system_monitor_fact(spec)
        return spec

    def get_spm_fact_spec(self):
        spec = SpmFactSpec(**self.params["spec"] if self.params["spec"] else {})
        VSPSpecValidators().validate_server_priority_manager_fact(spec)
        return spec

    def get_spm_spec(self):
        input_spec = SpmSpec(**self.params["spec"])
        VSPSpecValidators.validate_server_priority_manager(input_spec, self.get_state())
        return input_spec

    def get_hur_fact_spec(self):
        self.spec = HurFactSpec(**self.params["spec"] if self.params["spec"] else {})
        VSPSpecValidators().validate_hur_fact(self.spec)
        return self.spec

    def get_snapshot_reconcile_spec(self):
        self.spec = SnapshotReconcileSpec(
            **self.params["spec"], state=self.params["state"]
        )
        VSPSpecValidators().validate_snapshot_module(self.spec, self.connection_info)
        return self.spec

    def get_pool_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = PoolFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_storage_pool_fact(input_spec)
        else:
            input_spec = PoolFactSpec()
        return input_spec

    def storage_pool_spec(self):

        input_spec = StoragePoolSpec(**self.params["spec"])
        VSPSpecValidators().validate_storage_pool(input_spec, self.get_state())
        return input_spec

    def get_external_volume_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ExternalVolumeFactSpec(**self.params["spec"])
        else:
            input_spec = None
        return input_spec

    def external_volume_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ExternalVolumeSpec(**self.params["spec"])
        else:
            input_spec = None
        return input_spec

    def get_external_parity_group_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ExternalParityGroupFactSpec(**self.params["spec"])
        else:
            input_spec = None
        return input_spec

    def get_external_parity_group_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ExternalParityGroupSpec(**self.params["spec"])
            VSPSpecValidators().validate_external_parity_group(
                input_spec, self.get_state()
            )
        else:
            input_spec = None
        return input_spec

    def get_external_path_group_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ExternalPathGroupFactSpec(**self.params["spec"])
        else:
            input_spec = None
        return input_spec

    def get_external_path_group_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ExternalPathGroupSpec(**self.params["spec"])
        else:
            input_spec = None
        return input_spec

    def get_quorum_disk_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = QuorumDiskFactSpec(**self.params["spec"])
        else:
            input_spec = None
        return input_spec

    def quorum_disk_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = QuorumDiskSpec(**self.params["spec"])
        else:
            input_spec = None
        return input_spec

    def get_journal_volume_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = JournalVolumeFactSpec(**self.params["spec"])
        else:
            input_spec = None
        return input_spec

    def journal_volume_spec(self):
        input_spec = JournalVolumeSpec(**self.params["spec"])
        return input_spec

    def get_port_fact_spec(self):
        self.spec = PortFactSpec(**self.params["spec"] if self.params["spec"] else {})
        return self.spec

    def port_module_spec(self):
        self.spec = ChangePortSettingSpec(**self.params["spec"])
        VSPSpecValidators().validate_port_module(self.spec)
        return self.spec

    def get_parity_group_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ParityGroupFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_parity_group_fact(input_spec)
        else:
            input_spec = ParityGroupFactSpec()
        return input_spec

    def get_parity_group_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = ParityGroupSpec(**self.params["spec"])
            VSPSpecValidators().validate_parity_group(input_spec)
        else:
            input_spec = ParityGroupSpec()
        return input_spec

    def get_drives_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = DrivesFactSpec(**self.params["spec"])
            # VSPSpecValidators().validate_parity_group_fact(input_spec)
        else:
            input_spec = DrivesFactSpec()
        return input_spec

    def true_cpoy_spec(self):
        self.spec = TrueCopySpec(**self.params["spec"])
        VSPSpecValidators().validate_true_copy_module(self.spec)
        return self.spec

    def get_true_copy_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = TrueCopyFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_true_copy_fact(input_spec)
        else:
            input_spec = TrueCopyFactSpec()
        return input_spec

    def get_copy_groups_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = CopyGroupsFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_copy_groups_fact(input_spec)
        else:
            input_spec = CopyGroupsFactSpec()
        return input_spec

    def get_local_copy_groups_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = LocalCopyGroupFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_local_copy_groups_fact(input_spec)
        else:
            input_spec = LocalCopyGroupFactSpec()
        return input_spec

    def get_local_copy_group_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = LocalCopyGroupSpec(**self.params["spec"])
            # VSPSpecValidators().validate_local_copy_groups_fact(input_spec)
        else:
            input_spec = LocalCopyGroupSpec()
        return input_spec

    def get_nvme_subsystem_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = VSPNvmeSubsystemFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_nvme_subsystem_fact(input_spec)
        else:
            input_spec = VSPNvmeSubsystemFactSpec()
        return input_spec

    def get_nvme_subsystem_spec(self):
        self.spec = VSPNvmeSubsystemSpec(
            **self.params["spec"] if self.params["spec"] else {}
        )
        VSPSpecValidators().validate_nvme_subsystem(self.spec)
        return self.spec

    def hur_spec(self):
        self.spec = HurSpec(**self.params["spec"])
        # VSPSpecValidators().validate_hur_module(self.spec, self.state)
        return self.spec

    def copy_group_spec(self):
        self.spec = CopyGroupSpec(**self.params["spec"])
        # VSPSpecValidators().validate_hur_module(self.spec, self.state)
        return self.spec

    def gad_pair_spec(self):
        self.spec = VspGadPairSpec(**self.params["spec"])
        VSPSpecValidators().validate_gad_pair_spec(self.spec, self.state)
        return self.spec

    def gad_pair_fact_spec(self):
        self.spec = GADPairFactSpec(
            **self.params["spec"] if self.params["spec"] else {}
        )
        return self.spec

    def snapshot_grp_spec(self):
        self.spec = SnapshotGroupSpec(**self.params["spec"])
        return self.spec

    def snapshot_grp_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = SnapshotGroupFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_true_copy_fact(input_spec)
        else:
            input_spec = SnapshotGroupFactSpec()

        # self.spec = SnapshotGroupFactSpec(**self.params["spec"])
        # return self.spec
        return input_spec

    def unsubscribe_spec(self):
        if (
            "spec" in self.params
            and self.params["spec"] is not None
            and self.params["spec"]["resources"] is None
        ):
            raise ValueError("Ensure resources is not empty.")

        self.spec = UnsubscribeSpec(**self.params["spec"])
        VSPSpecValidators().validate_unsubscribe_module(self.spec)
        return self.spec

    def get_resource_group_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = VSPResourceGroupFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_resource_group_fact(input_spec)
        else:
            input_spec = VSPResourceGroupFactSpec()
        return input_spec

    def get_resource_group_spec(self):
        self.spec = VSPResourceGroupSpec(
            **self.params["spec"] if self.params["spec"] else {}
        )
        VSPSpecValidators().validate_resource_group(self.spec)
        return self.spec

    def get_user_group_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = VSPUserGroupFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_user_group_fact(input_spec)
        else:
            input_spec = VSPUserGroupFactSpec()
        return input_spec

    def get_user_group_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = VSPUserGroupSpec(**self.params["spec"])
            VSPSpecValidators().validate_user_group(input_spec)
        else:
            input_spec = VSPUserGroupSpec()
        return input_spec

    def get_user_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = VSPUserFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_user_fact(input_spec)
        else:
            input_spec = VSPUserFactSpec()
        return input_spec

    def get_user_spec(self):
        self.spec = VSPUserSpec(**self.params["spec"] if self.params["spec"] else {})
        VSPSpecValidators().validate_user(self.spec)
        return self.spec

    def get_cmd_dev_spec(self):
        self.spec = VSPCmdDevSpec(**self.params["spec"] if self.params["spec"] else {})
        VSPSpecValidators().validate_cmd_dev(self.spec)
        return self.spec

    def get_rg_lock_spec(self):
        self.spec = VSPResourceGroupLockSpec(
            **self.params["spec"] if self.params["spec"] else {}
        )
        VSPSpecValidators().validate_rg_lock(self.spec)
        return self.spec

    def get_remote_storage_registration_spec(self):
        self.spec = VSPRemoteStorageRegistrationSpec(
            **self.params["spec"] if self.params["spec"] else {}
        )
        VSPSpecValidators().validate_remote_storage_registration(self.spec)
        return self.spec

    def get_remote_storage_registration_fact_spec(self):
        if "spec" in self.params and self.params["spec"] is not None:
            input_spec = VSPRemoteStorageRegistrationFactSpec(**self.params["spec"])
            VSPSpecValidators().validate_remote_storage_registration_fact(input_spec)
        else:
            input_spec = VSPRemoteStorageRegistrationFactSpec()
        return input_spec

    def get_remote_connection_spec(self):
        self.spec = RemoteConnectionSpec(**self.params["spec"])
        return self.spec

    def get_remote_connection_facts_spec(self):
        self.spec = RemoteConnectionFactSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )
        return self.spec

    def get_iscsi_remote_connection_spec(self):
        self.spec = RemoteIscsiConnectionSpec(**self.params["spec"])
        return self.spec

    def get_iscsi_remote_connection_facts_spec(self):
        self.spec = RemoteIscsiConnectionFactSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )
        return self.spec

    def get_dynamic_pool_spec(self):

        self.spec = VspDynamicPoolSpec(**self.params["spec"])
        if self.params.get("state") == StateValue.PRESENT:
            VSPSpecValidators().validate_dynamic_storage_pool_spec(self.spec)

        return self.spec

    def get_dynamic_pool_facts_spec(self):
        self.spec = VspDynamicPoolFactsSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )
        return self.spec

    def mp_blade_facts_spec(self):
        self.spec = MPBladeFactsSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )
        return self.spec

    def get_upload_file_spec(self):
        """
        This method is used to get the upload file spec.
        :return: Upload file spec
        """
        self.spec = UploadFileSpec(**self.params["spec"])
        return self.spec

    def get_audit_log_spec(self):
        """
        This method is used to get the upload file spec.
        :return: Upload file spec
        """
        self.spec = SpecifyTransferDestinationFileSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )
        return self.spec

    def get_snmp_settings_spec(self):
        """
        This method is used to get the upload file spec.
        :return: Upload file spec
        """
        self.spec = SNMPRequestSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )
        return self.spec

    def get_vsp_volume_spec(self):
        """
        This method is used to get the VSP volume spec.
        :return: VSP volume spec
        """
        self.spec = SalamanderCreateVolumeRequestSpec(**self.params["spec"])
        return self.spec

    def get_volume_simple_api_facts_spec(self):
        """
        This method is used to get the VSP volume spec.
        :return: VSP volume spec
        """
        return SimpleAPIVolumeFactsSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )

    def get_vsp_one_server_spec(self):
        """
        This method is used to get the VSP One server spec.
        :return: VSP One server spec
        """
        return CreateServerSpec(**self.params["spec"])

    def get_vsp_one_server_facts_spec(self):
        """
        This method is used to get the VSP One server facts spec.
        :return: VSP One server facts spec
        """
        return ServerFactsSpec(**self.params["spec"] if self.params.get("spec") else {})

    def get_vsp_server_hba_facts_spec(self):
        """
        This method is used to get the VSP One server HBA facts spec.
        :return: VSP One server HBA facts spec
        """
        return ServerHBAFactsSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )

    def get_vsp_one_port_spec(self):
        """
        This method is used to get the VSP One port spec.
        :return: VSP One port spec
        """
        return VspOnePortSpec(**self.params["spec"])

    def get_vsp_one_port_facts_spec(self):
        """
        This method is used to get the VSP One port spec.
        :return: VSP One port spec
        """
        return VspOnePortFactsSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )

    def get_vsp_one_snapshot_facts_spec(self):

        return VspOneSnapshotFactSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )

    def get_vsp_one_snapshot_spec(self):
        """
        This method is used to get the VSP One snapshot spec.
        :return: VSP One server spec
        """
        return VspOneSnapshotSpec(**self.params["spec"])

    def get_vsp_one_snapshot_group_facts_spec(self):
        return VspOneSnapshotGroupFactSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )

    def get_vsp_one_snapshot_group_spec(self):
        return VspOneSnapshotGroupFactSpec(
            **self.params["spec"] if self.params.get("spec") else {}
        )


# Arguments Managements ##


class VSPCommonParameters:

    @staticmethod
    def storage_system_info():
        return {
            "required": False,
            "type": "dict",
            "options": {
                "serial": {
                    "required": False,
                    "type": "str",
                }
            },
        }

    @staticmethod
    def task_level():
        return {
            "required": True,
            "type": "dict",
            "options": {
                "state": {
                    "required": False,
                    "type": "str",
                    "choices": [
                        "present",
                        "absent",
                        "split",
                        "restore",
                        "resync",
                        "query",
                    ],
                    "default": "present",
                }
            },
        }

    @staticmethod
    def connection_info():
        return {
            "required": True,
            "type": "dict",
            "options": {
                "address": {
                    "required": True,
                    "type": "str",
                },
                "username": {
                    "required": False,
                    "type": "str",
                },
                "password": {
                    "required": False,
                    "no_log": True,
                    "type": "str",
                },
                "api_token": {
                    "required": False,
                    "type": "str",
                    "no_log": True,
                },
                # "subscriber_id": {
                #     "required": False,
                #     "type": "str",
                # },
                "connection_type": {
                    "required": False,
                    "type": "str",
                    "choices": ["direct"],
                    "default": "direct",
                },
            },
        }

    @staticmethod
    def state():
        return {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        }

    @staticmethod
    def tenant_info():
        return {
            "required": False,
            "type": "dict",
            "options": {
                "partnerId": {
                    "required": False,
                    "type": "str",
                },
                "subscriberId": {
                    "required": False,
                    "type": "str",
                },
            },
        }


class VSPVolumeArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent", "assign_virtual_ldev"],
            "default": "present",
        },
    }

    @classmethod
    def volume_fact(cls):
        spec_options = {
            "ldev_id": {
                "required": False,
                "type": "str",
            },
            "start_ldev_id": {
                "required": False,
                "type": "str",
            },
            "end_ldev_id": {
                "required": False,
                "type": "str",
            },
            "count": {
                "required": False,
                "type": "int",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "is_detailed": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "query": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "resource_group_id": {
                "required": False,
                "type": "int",
            },
            "journal_id": {
                "required": False,
                "type": "int",
            },
            "parity_group_id": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def volume(cls):

        tiering_policy = {
            "tier_level": {
                "required": False,
                "type": "int",
            },
            "tier1_allocation_rate_min": {
                "required": False,
                "type": "int",
            },
            "tier1_allocation_rate_max": {
                "required": False,
                "type": "int",
            },
            "tier3_allocation_rate_min": {
                "required": False,
                "type": "int",
            },
            "tier3_allocation_rate_max": {
                "required": False,
                "type": "int",
            },
        }

        qos_settings = {
            "upper_iops": {
                "required": False,
                "type": "int",
            },
            "lower_iops": {
                "required": False,
                "type": "int",
            },
            "upper_transfer_rate": {
                "required": False,
                "type": "int",
            },
            "lower_transfer_rate": {
                "required": False,
                "type": "int",
            },
            "upper_alert_allowable_time": {
                "required": False,
                "type": "int",
            },
            "lower_alert_allowable_time": {
                "required": False,
                "type": "int",
            },
            "response_priority": {
                "required": False,
                "type": "int",
            },
            "response_alert_allowable_time": {
                "required": False,
                "type": "int",
            },
        }
        spec_options = {
            "ldev_id": {
                "required": False,
                "type": "str",
            },
            "vldev_id": {
                "required": False,
                "type": "str",
            },
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "size": {
                "required": False,
                "type": "str",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "capacity_saving": {
                "required": False,
                "type": "str",
            },
            "parity_group": {
                "required": False,
                "type": "str",
            },
            "data_reduction_share": {
                "required": False,
                "type": "bool",
            },
            "force": {
                "required": False,
                "type": "bool",
            },
            "is_relocation_enabled": {
                "required": False,
                "type": "bool",
            },
            "is_compression_acceleration_enabled": {
                "required": False,
                "type": "bool",
            },
            "tier_level_for_new_page_allocation": {
                "required": False,
                "type": "str",
            },
            "tiering_policy": {
                "required": False,
                "type": "dict",
                "options": tiering_policy,
            },
            "state": {
                "required": False,
                "type": "str",
                "choices": ["add_host_nqn", "remove_host_nqn"],
                "default": "add_host_nqn",
            },
            "nvm_subsystem_name": {
                "required": False,
                "type": "str",
            },
            "host_nqns": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "should_shred_volume_enable": {
                "required": False,
                "type": "bool",
            },
            "qos_settings": {
                "required": False,
                "type": "dict",
                "options": qos_settings,
            },
            "should_reclaim_zero_pages": {
                "required": False,
                "type": "bool",
            },
            "mp_blade_id": {
                "required": False,
                "type": "int",
            },
            "clpr_id": {
                "required": False,
                "type": "int",
            },
            "is_parallel_execution_enabled": {
                "required": False,
                "type": "bool",
            },
            "start_ldev_id": {
                "required": False,
                "type": "str",
            },
            "end_ldev_id": {
                "required": False,
                "type": "str",
            },
            "external_parity_group": {
                "required": False,
                "type": "str",
            },
            "should_format_volume": {
                "required": False,
                "type": "bool",
            },
            "format_type": {
                "required": False,
                "type": "str",
                "choices": [
                    "quick",
                    "normal",
                ],
                "default": "quick",
            },
            "data_reduction_process_mode": {
                "required": False,
                "type": "str",
                "choices": [
                    "post_process",
                    "inline",
                ],
            },
            "is_full_allocation_enabled": {
                "required": False,
                "type": "bool",
            },
            "is_alua_enabled": {
                "required": False,
                "type": "bool",
            },
        }

        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPHostGroupArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": VSPCommonParameters.state(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def host_group_facts(cls):
        spec_options = {
            "query": {
                "required": False,
                "type": "list",
                "elements": "str",
                "choices": ["wwns", "ldevs"],
                "default": [],
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "ports": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "lun": {
                "required": False,
                "type": "int",
            },
            "host_group_number": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args

    @classmethod
    def host_group(cls):
        # cls.common_arguments["spec"]["required"] = True
        spec_options = {
            "state": {
                "required": False,
                "type": "str",
                "choices": [
                    "present",
                    "present_ldev",
                    "unpresent_ldev",
                    "add_wwn",
                    "remove_wwn",
                    "set_host_mode_and_hmo",
                ],
                "default": "present",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "port": {
                "required": True,
                "type": "str",
            },
            "host_mode": {
                "required": False,
                "type": "str",
                "choices": [
                    "LINUX",
                    "VMWARE",
                    "HP",
                    "OPEN_VMS",
                    "TRU64",
                    "SOLARIS",
                    "NETWARE",
                    "WINDOWS",
                    "HI_UX",
                    "AIX",
                    "VMWARE_EXTENSION",
                    "WINDOWS_EXTENSION",
                    "UVM",
                    "HP_XP",
                    "DYNIX",
                ],
            },
            # sng20250212 host_mode_options validations
            "host_mode_options": {
                "required": False,
                "type": "list",
                "elements": "int",
            },
            "ldevs": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "wwns": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "wwn": {
                        "required": True,
                        "type": "str",
                    },
                    "nick_name": {
                        "required": False,
                        "type": "str",
                    },
                },
            },
            "should_delete_all_ldevs": {
                "required": False,
                "type": "bool",
            },
            "asymmetric_access_priority": {
                "required": False,
                "type": "str",
                "choices": ["high", "low"],
            },
            "host_group_number": {
                "required": False,
                "type": "int",
            },
            "should_release_host_reserve": {
                "required": False,
                "type": "bool",
            },
            "lun": {
                "required": False,
                "type": "int",
            },
        }
        # args = copy.deepcopy(cls.common_arguments)
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPShadowImagePairArguments:

    shadow_image_pair_state = VSPCommonParameters.state()
    shadow_image_pair_state["choices"].extend(["split", "sync", "restore", "migrate"])

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": shadow_image_pair_state,
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def get_all_shadow_image_pair_fact(cls):
        spec_options = {
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            "copy_group_name": {
                "required": False,
                "type": "str",
            },
            "copy_pair_name": {
                "required": False,
                "type": "str",
            },
            "refresh": {
                "required": False,
                "type": "bool",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def shadow_image_pair(cls):
        spec_options = {
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            "secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "should_delete_svol": {
                "required": False,
                "type": "bool",
            },
            "auto_split": {
                "required": False,
                "type": "bool",
            },
            "allocate_new_consistency_group": {
                "required": False,
                "type": "bool",
            },
            "consistency_group_id": {
                "required": False,
                "type": "int",
            },
            "copy_pace_track_size": {
                "required": False,
                "type": "str",
                "choices": ["SLOW", "MEDIUM", "FAST"],
            },
            # "is_new_group_creation": {
            #     "required": False,
            #     "type": "bool",
            # },
            "enable_quick_mode": {
                "required": False,
                "type": "bool",
            },
            "enable_read_write": {
                "required": False,
                "type": "bool",
            },
            "pair_id": {
                "required": False,
                "type": "str",
            },
            "is_data_reduction_force_copy": {
                "required": False,
                "type": "bool",
            },
            "secondary_pool_id": {
                "required": False,
                "type": "int",
            },
            "copy_group_name": {
                "required": False,
                "type": "str",
            },
            "copy_pair_name": {
                "required": False,
                "type": "str",
            },
            "primary_volume_device_group_name": {
                "required": False,
                "type": "str",
            },
            "secondary_volume_device_group_name": {
                "required": False,
                "type": "str",
            },
            "should_force_split": {
                "required": False,
                "type": "bool",
            },
            "create_for_migration": {
                "required": False,
                "type": "bool",
            },
        }

        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPClprArguments:

    clpr_state = VSPCommonParameters.state()
    clpr_state["choices"].extend(["update", "assign_ldev", "assign_parity_group"])

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": clpr_state,
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def get_all_clpr_fact(cls):
        spec_options = {
            "clpr_id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def clpr(cls):
        spec_options = {
            "clpr_id": {"required": False, "type": "int"},
            "clpr_name": {"required": False, "type": "str"},
            "cache_memory_capacity_mb": {"required": False, "type": "int"},
            "ldev_id": {
                "required": False,
                "type": "int",
            },
            "parity_group_id": {
                "required": False,
                "type": "str",
            },
        }

        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPSnapshotArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    ssi["options"]["connection_type"]["choices"] = ["direct"]

    snapshot_image_state = VSPCommonParameters.state()
    snapshot_image_state["choices"].extend(
        ["split", "sync", "restore", "clone", "defragment"]
    )
    snapshot_image_state_sng = VSPCommonParameters.state()
    snapshot_image_state_sng["choices"] = [
        "split",
        "sync",
        "restore",
        "clone",
        "absent",
        "defragment",
    ]
    snapshot_image_state_sng["required"] = True
    snapshot_image_state_sng.pop("default")

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
        "state": snapshot_image_state,
    }
    common_arguments_sng = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": ssi,
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
        "state": snapshot_image_state_sng,
    }

    @classmethod
    def snapshot_grp_args(cls):
        spec_options = {
            "snapshot_group_name": {
                "required": True,
                "type": "str",
            },
            "auto_split": {
                "required": False,
                "type": "bool",
            },
            "retention_period": {
                "required": False,
                "type": "int",
            },
            "copy_speed": {
                "required": False,
                "type": "str",
                "choices": ["SLOW", "MEDIUM", "FAST"],
            },
        }

        cls.common_arguments_sng["spec"]["options"] = spec_options
        return cls.common_arguments_sng

    @classmethod
    def snapshot_grp_fact_args(cls):
        spec_options = {
            "snapshot_group_name": {
                "required": True,
                "type": "str",
            }
        }
        args = copy.deepcopy(cls.common_arguments_sng)
        args["spec"]["required"] = False
        args["spec"]["options"] = spec_options
        args.pop("state")
        # args.pop("storage_system_info")
        return args

    @classmethod
    def get_snapshot_fact_args(cls):
        spec_options = {
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            "mirror_unit_id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def get_snapshot_reconcile_args(cls):
        spec_options = {
            "primary_volume_id": {
                "required": True,
                "type": "str",
            },
            "secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "allocate_new_consistency_group": {
                "required": False,
                "type": "bool",
            },
            # "enable_quick_mode": {
            #     "required": False,
            #     "type": "bool",
            # },
            "auto_split": {
                "required": False,
                "type": "bool",
            },
            "mirror_unit_id": {
                "required": False,
                "type": "int",
            },
            "snapshot_group_name": {
                "required": False,
                "type": "str",
            },
            "is_data_reduction_force_copy": {
                "required": False,
                "type": "bool",
            },
            "can_cascade": {
                "required": False,
                "type": "bool",
            },
            "is_clone": {
                "required": False,
                "type": "bool",
            },
            "retention_period": {
                "required": False,
                "type": "int",
            },
            "copy_speed": {
                "required": False,
                "type": "str",
                "choices": ["SLOW", "MEDIUM", "FAST"],
            },
            "clones_automation": {
                "required": False,
                "type": "bool",
            },
            "should_delete_tree": {
                "required": False,
                "type": "bool",
            },
            "operation_type": {
                "required": False,
                "type": "str",
                "choices": [
                    "start",
                    "stop",
                ],
            },
        }

        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPStorageSystemArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def storage_system_fact(cls):
        spec_options = {
            "query": {
                "required": False,
                "type": "list",
                "elements": "str",
                "choices": [
                    # "ports",
                    # "quorumdisks",
                    # "journalPools",
                    # "freeLogicalUnitList",
                    "time_zone",
                ],
            },
            # "refresh": {
            #     "required": False,
            #     "type": "bool",
            # },
        }

        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPIscsiTargetArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": VSPCommonParameters.state(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def iscsi_target_facts(cls):
        spec_options = {
            "ports": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "iscsi_id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args

    @classmethod
    def iscsi_target(cls):
        cls.common_arguments["spec"]["required"] = True
        spec_options = {
            "state": {
                "required": False,
                "type": "str",
                "default": "present",
                "choices": [
                    "present",
                    "absent",
                    "add_iscsi_initiator",
                    "remove_iscsi_initiator",
                    "attach_ldev",
                    "detach_ldev",
                    "add_chap_user",
                    "remove_chap_user",
                ],
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "port": {
                "required": True,
                "type": "str",
            },
            "host_mode": {
                "required": False,
                "type": "str",
                "choices": [
                    "LINUX",
                    "VMWARE",
                    "HP",
                    "OPEN_VMS",
                    "TRU64",
                    "SOLARIS",
                    "NETWARE",
                    "WINDOWS",
                    "HI_UX",
                    "AIX",
                    "VMWARE_EXTENSION",
                    "WINDOWS_EXTENSION",
                    "UVM",
                    "HP_XP",
                    "DYNIX",
                ],
            },
            # sng20250212 host_mode_options validations
            "host_mode_options": {
                "required": False,
                "type": "list",
                "elements": "int",
            },
            "ldevs": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "chap_users": {
                "required": False,
                "type": "list",
                "elements": "dict",
            },
            "should_delete_all_ldevs": {
                "required": False,
                "type": "bool",
            },
            "iqn_initiators": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "iqn": {
                        "required": True,
                        "type": "str",
                    },
                    "nick_name": {
                        "required": False,
                        "type": "str",
                    },
                },
            },
            "should_release_host_reserve": {
                "required": False,
                "type": "bool",
            },
            "lun": {
                "required": False,
                "type": "int",
            },
            "iscsi_id": {
                "required": False,
                "type": "int",
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPStoragePoolArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "monitor_performance",
                "tier_relocate",
                "restore",
                "init_capacity_saving",
            ],
            "default": "present",
        },
    }

    @classmethod
    def storage_pool_fact(cls):
        spec_options = {
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "pool_name": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args

    @classmethod
    def storage_pool(cls):
        spec_options = {
            "id": {
                "required": False,
                "type": "int",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "type": {
                "required": False,
                "type": "str",
                "choices": ["HDT", "HDP", "HRT", "HTI"],
            },
            "should_enable_deduplication": {
                "required": False,
                "type": "bool",
            },
            "depletion_threshold_rate": {
                "required": False,
                "type": "int",
            },
            "warning_threshold_rate": {
                "required": False,
                "type": "int",
            },
            "resource_group_id": {
                "required": False,
                "type": "int",
            },
            "operation_type": {
                "required": False,
                "type": "str",
                "choices": ["start", "stop"],
            },
            "pool_volumes": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "capacity": {
                        "required": True,
                        "type": "str",
                    },
                    "parity_group_id": {
                        "required": True,
                        "type": "str",
                    },
                },
            },
            "start_ldev_id": {
                "required": False,
                "type": "str",
            },
            "end_ldev_id": {
                "required": False,
                "type": "str",
            },
            "ldev_ids": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "suspend_snapshot": {
                "required": False,
                "type": "bool",
            },
            "virtual_volume_capacity_rate": {
                "required": False,
                "type": "int",
            },
            "blocking_mode": {
                "required": False,
                "type": "str",
                "choices": ["PF", "PB", "FB", "NB"],
            },
            "monitoring_mode": {
                "required": False,
                "type": "str",
                "choices": ["PM", "CM"],
            },
            "tier": {
                "required": False,
                "type": "dict",
                "options": {
                    "tier_number": {
                        "required": False,
                        "type": "int",
                    },
                    "table_space_rate": {
                        "required": False,
                        "type": "int",
                    },
                    "buffer_rate": {
                        "required": False,
                        "type": "int",
                    },
                },
            },
            "should_delete_pool_volumes": {
                "required": False,
                "type": "bool",
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPStorageSystemMonitorArguments:

    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def storage_system_monitor_fact(cls):
        spec_options = {
            "alert_type": {
                "required": False,
                "type": "str",
                "choices": [
                    "DKC",
                    "CTL1",
                    "CTL2",
                ],
            },
            "alert_start_number": {
                "required": False,
                "type": "int",
            },
            "alert_count": {
                "required": False,
                "type": "int",
            },
            "include_component_option": {
                "required": False,
                "type": "bool",
            },
            "query": {
                "required": True,
                "type": "str",
                "choices": [
                    "alerts",
                    "hardware_installed",
                    "channel_boards",
                ],
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        # args.pop("state")
        return args


class VSPServerPriorityManagerArguments:

    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
            ],
            "default": "present",
        },
    }

    @classmethod
    def server_priority_manager_fact(cls):
        spec_options = {
            "ldev_id": {
                "required": False,
                "type": "str",
            },
            "host_wwn": {
                "required": False,
                "type": "str",
            },
            "iscsi_name": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args

    @classmethod
    def server_priority_manager(cls):
        spec_options = {
            "ldev_id": {
                "required": True,
                "type": "str",
            },
            "host_wwn": {
                "required": False,
                "type": "str",
            },
            "iscsi_name": {
                "required": False,
                "type": "str",
            },
            "upper_limit_for_iops": {
                "required": False,
                "type": "int",
            },
            "upper_limit_for_transfer_rate_in_MBps": {
                "required": False,
                "type": "int",
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPJournalVolumeArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "update",
                "expand_journal_volume",
                "shrink_journal_volume",
            ],
            "default": "present",
        },
    }

    @classmethod
    def journal_volume_fact(cls):
        spec_options = {
            "journal_id": {
                "required": False,
                "type": "int",
            },
            "is_free_journal_pool_id": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "free_journal_pool_id_count": {
                "required": False,
                "type": "int",
                "default": 1,
            },
            "is_mirror_not_used": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args

    @classmethod
    def journal_volume(cls):
        spec_options = {
            "journal_id": {
                "required": False,
                "type": "int",
            },
            "start_ldev_id": {
                "required": False,
                "type": "str",
                "aliases": ["startLdevId"],
            },
            "end_ldev_id": {
                "required": False,
                "type": "str",
                "aliases": ["endLdevId"],
            },
            "is_cache_mode_enabled": {
                "required": False,
                "type": "bool",
            },
            "data_overflow_watch_in_seconds": {
                "required": False,
                "type": "int",
                "aliases": ["data_overflow_watchIn_seconds"],
            },
            "mp_blade_id": {
                "required": False,
                "type": "int",
            },
            "ldev_ids": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "mirror_unit_number": {
                "required": False,
                "type": "int",
            },
            "copy_pace": {
                "required": False,
                "type": "str",
                "choices": ["SLOW", "MEDIUM", "FAST"],
            },
            "path_blockade_watch_in_minutes": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args


class VSPJournalArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "update",
                "expand_journal",
                "shrink_journal",
            ],
            "default": "present",
        },
    }

    @classmethod
    def journal_fact(cls):
        spec_options = {
            "journal_id": {
                "required": False,
                "type": "int",
            },
            "is_free_journal_pool_id": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "free_journal_pool_id_count": {
                "required": False,
                "type": "int",
                "default": 1,
            },
            "is_mirror_not_used": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args

    @classmethod
    def journal(cls):
        spec_options = {
            "journal_id": {
                "required": False,
                "type": "int",
            },
            "start_ldev_id": {
                "required": False,
                "type": "str",
                "aliases": ["startLdevId"],
            },
            "end_ldev_id": {
                "required": False,
                "type": "str",
                "aliases": ["endLdevId"],
            },
            "is_cache_mode_enabled": {
                "required": False,
                "type": "bool",
            },
            "data_overflow_watch_in_seconds": {
                "required": False,
                "type": "int",
                "aliases": ["data_overflow_watchIn_seconds"],
            },
            "mp_blade_id": {
                "required": False,
                "type": "int",
            },
            "ldev_ids": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "mirror_unit_number": {
                "required": False,
                "type": "int",
            },
            "copy_pace": {
                "required": False,
                "type": "str",
                "choices": ["SLOW", "MEDIUM", "FAST"],
            },
            "path_blockade_watch_in_minutes": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args


class VSPQuorumDiskArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
            ],
            "default": "present",
        },
    }

    @classmethod
    def quorum_disk_fact(cls):
        spec_options = {
            "id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args

    @classmethod
    def quorum_disk(cls):
        spec_options = {
            "remote_storage_serial_number": {
                "required": False,
                "type": "str",
            },
            "remote_storage_type": {
                "required": False,
                "type": "str",
                "choices": ["M8", "R8", "R9", "RH20ETP"],
            },
            "ldev_id": {
                "required": False,
                "type": "str",
            },
            "id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args


class VSPExternalVolumeArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "disconnect",
            ],
            "default": "present",
        },
    }

    @classmethod
    def external_volume_fact(cls):
        spec_options = {
            "external_storage_serial": {
                "required": False,
                "type": "str",
            },
            "external_ldev_id": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        # args["connection_info"]["options"].pop("subscriber_id")
        # args["connection_info"]["options"].pop("api_token")
        return args

    @classmethod
    def external_volume(cls):
        spec_options = {
            "external_storage_serial": {
                "required": False,
                "type": "str",
            },
            "external_ldev_id": {
                "required": False,
                "type": "str",
            },
            "ldev_id": {
                "required": False,
                "type": "str",
            },
            "external_parity_group": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        # args["connection_info"]["options"].pop("subscriber_id")
        # args["connection_info"]["options"].pop("api_token")
        return args


class VSPExternalParityGroupArguments:

    common_arguments = {
        # "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "assign_external_parity_group",
                "change_mp_blade",
                "disconnect",
            ],
            "default": "present",
        },
    }

    @classmethod
    def external_parity_group_fact(cls):
        spec_options = {
            "external_parity_group": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        # args["connection_info"]["options"].pop("api_token")
        return args

    @classmethod
    def external_parity_group(cls):
        spec_options = {
            "external_parity_group_id": {
                "required": True,
                "type": "str",
            },
            "mp_blade_id": {
                "required": False,
                "type": "int",
            },
            "clpr_id": {
                "required": False,
                "type": "int",
            },
            "force": {
                "required": False,
                "type": "bool",
            },
            "external_path_group_id": {
                "required": False,
                "type": "int",
            },
            "port_id": {
                "required": False,
                "type": "str",
            },
            "external_wwn": {
                "required": False,
                "type": "str",
            },
            "lun_id": {
                "required": False,
                "type": "int",
            },
            "emulation_type": {
                "required": False,
                "type": "str",
                "choices": [
                    "OPEN-3",
                    "OPEN-8",
                    "OPEN-9",
                    "OPEN-E",
                    "OPEN-K",
                    "OPEN-L",
                    "OPEN-V",
                    "3380-3",
                    "3380-3A",
                    "3380-3B",
                    "3380-3C",
                    "3390-1",
                    "3390-2",
                    "3390-3",
                    "3390-A",
                    "3390-3A",
                    "3390-3B",
                    "3390-3C",
                    "3390-3R",
                    "3390-9",
                    "3390-9A",
                    "3390-9B",
                    "3390-9C",
                    "3390-L",
                    "3390-LA",
                    "3390-LB",
                    "3390-LC",
                    "3390-M",
                    "3390-MA",
                    "3390-MB",
                    "3390-MC",
                    "3390-V",
                    "6586-G",
                    "6586-J",
                    "6586-K",
                    "6586-KA",
                    "6586-KB",
                    "6586-KC",
                    "6588-1",
                    "6588-3",
                    "6588-9",
                    "6588-A",
                    "6588-3A",
                    "6588-3B",
                    "6588-3C",
                    "6588-9A",
                    "6588-9B",
                    "6588-9C",
                    "6588-L",
                    "6588-LA",
                    "6588-LB",
                    "6588-LC",
                ],
                "default": "OPEN-V",
            },
            "is_external_attribute_migration": {
                "required": False,
                "type": "bool",
            },
            "command_device_ldev_id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        # args["connection_info"]["options"].pop("api_token")
        return args


class VSPExternalPathGroupArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "add_external_path",
                "remove_external_path",
            ],
            "default": "present",
        },
    }

    @classmethod
    def external_path_group_fact(cls):
        spec_options = {
            "external_path_group_id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        args["connection_info"]["options"].pop("api_token")
        args["connection_info"]["options"]["username"]["required"] = True
        args["connection_info"]["options"]["password"]["required"] = True
        return args

    @classmethod
    def external_path_group(cls):
        spec_options = {
            "external_path_group_id": {
                "required": True,
                "type": "int",
            },
            "external_fc_paths": {
                "required": False,
                "type": "list",
                "elements": "dict",
            },
            "external_iscsi_target_paths": {
                "required": False,
                "type": "list",
                "elements": "dict",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["connection_info"]["options"].pop("api_token")
        args["connection_info"]["options"]["username"]["required"] = True
        args["connection_info"]["options"]["password"]["required"] = True
        return args


class VSPStoragePortArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("api_token")
    # ssi["options"].pop("subscriber_id")
    # ssi["options"]["username"]["required"] = True
    # ssi["options"]["password"]["required"] = True
    ssi["options"]["connection_type"]["choices"] = ["direct"]
    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": ssi,
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "login_test",
                "register_external_iscsi_target",
                "unregister_external_iscsi_target",
            ],
            "default": "present",
        },
    }

    @classmethod
    def storage_port_fact(cls):
        spec_options = {
            "ports": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "query": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "external_iscsi_ip_address": {
                "required": False,
                "type": "str",
            },
            "external_iscsi_name": {
                "required": False,
                "type": "str",
            },
            "external_wwn": {
                "required": False,
                "type": "str",
            },
            "external_tcp_port": {
                "required": False,
                "type": "int",
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        cls.common_arguments.pop("state")
        return cls.common_arguments

    @classmethod
    def storage_port(cls):
        spec_options = {
            "port": {
                "required": True,
                "type": "str",
            },
            "port_attribute": {
                "required": False,
                "type": "str",
            },
            "port_mode": {
                "required": False,
                "type": "str",
            },
            "port_speed": {
                "required": False,
                "type": "str",
            },
            "fabric_mode": {
                "required": False,
                "type": "bool",
            },
            "port_connection": {
                "required": False,
                "type": "str",
            },
            "enable_port_security": {
                "required": False,
                "type": "bool",
            },
            "host_ip_address": {
                "required": False,
                "type": "str",
            },
            "external_iscsi_targets": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "name": {
                        "required": True,
                        "type": "str",
                    },
                    "ip_address": {
                        "required": True,
                        "type": "str",
                    },
                    "tcp_port": {
                        "required": False,
                        "type": "int",
                    },
                },
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPParityGroupArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent", "update", "assign_clpr_id"],
            "default": "present",
        },
    }

    @classmethod
    def parity_group_fact(cls):
        spec_options = {
            "parity_group_id": {
                "required": False,
                "type": "str",
            }
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args
        # cls.common_arguments["spec"]["options"] = spec_options
        # return cls.common_arguments

    @classmethod
    def drives_fact(cls):
        spec_options = {
            "drive_location_id": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        # args.pop("storage_system_info")
        args["connection_info"]["options"].pop("connection_type")
        args["connection_info"]["options"].pop("api_token")
        args["connection_info"]["options"]["username"]["required"] = True
        args["connection_info"]["options"]["password"]["required"] = True
        # args["connection_info"]["options"].pop("subscriber_id")
        return args

    @classmethod
    def drives(cls):
        spec_options = {
            "drive_location_id": {
                "required": False,
                "type": "str",
            },
            "is_spared_drive": {
                "required": False,
                "type": "bool",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args["state"]["choices"] = ["present"]
        args.pop("storage_system_info")
        args["connection_info"]["options"].pop("connection_type")
        # args["connection_info"]["options"].pop("subscriber_id")
        args["connection_info"]["options"].pop("api_token")
        args["connection_info"]["options"]["username"]["required"] = True
        args["connection_info"]["options"]["password"]["required"] = True
        return args

    @classmethod
    def parity_group(cls):
        spec_options = {
            "parity_group_id": {
                "required": False,
                "type": "str",
            },
            "drive_location_ids": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "raid_type": {
                "required": False,
                "type": "str",
            },
            "is_encryption_enabled": {
                "required": False,
                "type": "bool",
            },
            "is_copy_back_mode_enabled": {
                "required": False,
                "type": "bool",
            },
            "is_accelerated_compression_enabled": {
                "required": False,
                "type": "bool",
            },
            "clpr_id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("storage_system_info")
        # args["connection_info"]["options"].pop("subscriber_id")
        # args["connection_info"]["options"].pop("api_token")
        return args


class VSPCopyGroupsArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    common_arguments = {
        # "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "secondary_connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent", "sync", "split", "restore", "resync"],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def copy_groups_facts(cls):
        spec_options = {
            "name": {
                "required": False,
                "type": "str",
            },
            "should_include_remote_replication_pairs": {
                "required": False,
                "type": "bool",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        args["connection_info"]["options"].pop("connection_type")
        # args["connection_info"]["options"].pop("subscriber_id")
        return args


class VSPLocalCopyGroupArguments:

    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "sync",
                "split",
                "resync",
                "restore",
                "migrate",
            ],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def local_copy_group_facts(cls):
        spec_options = {
            "name": {
                "required": False,
                "type": "str",
            },
            "primary_volume_device_group_name": {
                "required": False,
                "type": "str",
            },
            "secondary_volume_device_group_name": {
                "required": False,
                "type": "str",
            },
            "should_include_copy_pairs": {
                "required": False,
                "type": "bool",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        args["connection_info"]["options"].pop("connection_type")
        # args["connection_info"]["options"].pop("subscriber_id")
        return args

    @classmethod
    def local_copy_group_args(cls):
        spec_options = {
            # "name": {
            #     "required": False,
            #     "type": "str",
            # },
            "copy_group_name": {
                "required": True,
                "type": "str",
            },
            "primary_volume_device_group_name": {
                "required": False,
                "type": "str",
            },
            "secondary_volume_device_group_name": {
                "required": False,
                "type": "str",
            },
            "copy_pace": {
                "required": False,
                "type": "int",
            },
            "quick_mode": {
                "required": False,
                "type": "bool",
            },
            "force_suspend": {
                "required": False,
                "type": "bool",
            },
            "force_delete": {
                "required": False,
                "type": "bool",
            },
            "should_force_split": {
                "required": False,
                "type": "bool",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["connection_info"]["options"].pop("connection_type")
        # args["connection_info"]["options"].pop("subscriber_id")
        return args


class VSPTrueCopyArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    ssi["required"] = False

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "secondary_connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "resize",
                "expand",
                "resync",
                "split",
                "swap_split",
                "swap_resync",
            ],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def true_copy(cls):
        hg_options = {
            "name": {
                "required": True,
                "type": "str",
            },
            "port": {
                "required": True,
                "type": "str",
            },
            "lun_id": {
                "required": False,
                "type": "int",
            },
        }

        spec_options = {
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            "consistency_group_id": {
                "required": False,
                "type": "int",
            },
            "fence_level": {
                "required": False,
                "type": "str",
                "choices": ["NEVER", "DATA", "STATUS"],
                "default": "NEVER",
            },
            "secondary_pool_id": {
                "required": False,
                "type": "int",
            },
            "begin_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "end_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "provisioned_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "secondary_hostgroup": {
                "required": False,
                "type": "dict",
                "options": hg_options,
            },
            "copy_group_name": {
                "required": False,
                "type": "str",
            },
            "copy_pair_name": {
                "required": False,
                "type": "str",
            },
            "path_group_id": {
                "required": False,
                "type": "int",
            },
            "local_device_group_name": {
                "required": False,
                "type": "str",
            },
            "remote_device_group_name": {
                "required": False,
                "type": "str",
            },
            "is_new_group_creation": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "is_consistency_group": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "copy_pace": {
                "required": False,
                "type": "str",
                "choices": ["SLOW", "MEDIUM", "FAST"],
                "default": "MEDIUM",
            },
            "do_initial_copy": {
                "required": False,
                "type": "bool",
                "default": True,
            },
            "is_data_reduction_force_copy": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "is_svol_readwriteable": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "new_volume_size": {
                "required": False,
                "type": "str",
            },
            "secondary_nvm_subsystem": {
                "required": False,
                "type": "dict",
                "options": {
                    "name": {
                        "required": True,
                        "type": "str",
                    },
                    "paths": {
                        "required": False,
                        "type": "list",
                        "elements": "str",
                    },
                },
            },
            "secondary_iscsi_targets": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_options,
            },
            "secondary_hostgroups": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_options,
            },
            "should_delete_svol": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments

    @classmethod
    def true_copy_facts(cls):
        spec_options = {
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            "secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "copy_group_name": {
                "required": False,
                "type": "str",
            },
            "copy_pair_name": {
                "required": False,
                "type": "str",
            },
            "local_device_group_name": {
                "required": False,
                "type": "str",
            },
            "remote_device_group_name": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args


class VSPVolTierArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
            ],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def get_args(cls):
        tiering_policy = {
            "tier_level": {
                "required": False,
                "type": "int",
            },
            "tier1_allocation_rate_min": {
                "required": False,
                "type": "int",
            },
            "tier1_allocation_rate_max": {
                "required": False,
                "type": "int",
            },
            "tier3_allocation_rate_min": {
                "required": False,
                "type": "int",
            },
            "tier3_allocation_rate_max": {
                "required": False,
                "type": "int",
            },
        }

        spec_options = {
            "ldev_id": {
                "required": True,
                "type": "int",
            },
            "is_relocation_enabled": {
                "required": False,
                "type": "bool",
            },
            "tier_level_for_new_page_allocation": {
                "required": False,
                "type": "bool",
            },
            "tiering_policy": {
                "required": False,
                "type": "dict",
                "default": False,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPHurArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    ssi["required"] = False
    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "secondary_connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "split",
                "resync",
                "resize",
                "expand",
                "swap_split",
                "swap_resync",
                "takeover",
            ],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def hur(cls):
        hg_options = {
            "name": {
                "required": True,
                "type": "str",
            },
            "port": {
                "required": True,
                "type": "str",
            },
            "lun_id": {
                "required": False,
                "type": "int",
            },
        }

        spec_options = {
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            # "secondary_volume_id": {
            #     "required": False,
            #     "type": "str",
            # },
            "mirror_unit_id": {
                "required": False,
                "choices": [0, 1, 2, 3],
                "type": "int",
            },
            "consistency_group_id": {
                "required": False,
                "type": "int",
            },
            "is_consistency_group": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "enable_delta_resync": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "allocate_new_consistency_group": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "primary_volume_journal_id": {
                "required": False,
                "type": "int",
            },
            "secondary_volume_journal_id": {
                "required": False,
                "type": "int",
            },
            "secondary_storage_serial_number": {
                "required": False,
                "type": "int",
            },
            "secondary_pool_id": {
                "required": False,
                "type": "int",
            },
            "copy_group_name": {
                "required": False,
                "type": "str",
            },
            "copy_pair_name": {
                "required": False,
                "type": "str",
            },
            "is_new_group_creation": {
                "required": False,
                "type": "bool",
            },
            "fence_level": {
                "required": False,
                "type": "str",
                "choices": ["ASYNC"],
                "default": "ASYNC",
            },
            "local_device_group_name": {
                "required": False,
                "type": "str",
            },
            "remote_device_group_name": {
                "required": False,
                "type": "str",
            },
            "do_initial_copy": {
                "required": False,
                "type": "bool",
                "default": True,
            },
            "is_data_reduction_force_copy": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "do_delta_resync_suspend": {
                "required": False,
                "type": "bool",
            },
            "is_svol_readwriteable": {
                "required": False,
                "type": "bool",
            },
            "path_group_id": {
                "required": False,
                "type": "int",
            },
            "new_volume_size": {
                "required": False,
                "type": "str",
            },
            "begin_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "end_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "provisioned_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "secondary_hostgroup": {
                "required": False,
                "type": "dict",
                "options": hg_options,
            },
            "secondary_hostgroups": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_options,
            },
            "secondary_nvm_subsystem": {
                "required": False,
                "type": "dict",
                "options": {
                    "name": {
                        "required": True,
                        "type": "str",
                    },
                    "paths": {
                        "required": False,
                        "type": "list",
                        "elements": "str",
                    },
                },
            },
            "secondary_iscsi_targets": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_options,
            },
            "should_delete_svol": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = True

        return args

    # 20240812 HUR facts spec
    @classmethod
    def get_hur_fact_args(cls):
        spec_options = {
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            "secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "copy_group_name": {
                "required": False,
                "type": "str",
            },
            "secondary_storage_serial_number": {
                "required": False,
                "type": "int",
            },
            "copy_pair_name": {
                "required": False,
                "type": "str",
            },
            "local_device_group_name": {
                "required": False,
                "type": "str",
            },
            "remote_device_group_name": {
                "required": False,
                "type": "str",
            },
            "mirror_unit_id": {
                "required": False,
                "type": "int",
                "choices": [0, 1, 2, 3],
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")
        return args


class VSPRemoteCopyGroupArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    ssi["required"] = True
    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "secondary_connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "split",
                "resync",
                "swap_split",
                "swap_resync",
                "takeover",
            ],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def get_copy_group_args(cls):
        spec_options = {
            "copy_group_name": {
                "required": True,
                "type": "str",
            },
            "replication_type": {
                "required": False,
                "type": "str",
                "choices": [
                    "TC",
                    "UR",
                    "GAD",
                    "HUR",
                ],
            },
            "local_device_group_name": {
                "required": False,
                "type": "str",
            },
            "remote_device_group_name": {
                "required": False,
                "type": "str",
            },
            "is_svol_writable": {
                "required": False,
                "type": "bool",
            },
            "svol_operation_mode": {
                "required": False,
                "type": "str",
            },
            "do_pvol_write_protect": {
                "required": False,
                "type": "bool",
            },
            "do_data_suspend": {
                "required": False,
                "type": "bool",
            },
            "do_failback": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "failback_mirror_unit_number": {
                "required": False,
                "type": "int",
            },
            "is_consistency_group": {
                "required": False,
                "type": "bool",
            },
            "consistency_group_id": {
                "required": False,
                "type": "int",
            },
            "fence_level": {
                "required": False,
                "type": "str",
                "choices": [
                    "DATA",
                    "STATUS",
                    "NEVER",
                ],
            },
            "copy_pace": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = True
        # args["connection_info"]["options"].pop("subscriber_id")
        # args["connection_info"]["options"].pop("api_token")
        args["connection_info"]["options"].pop("connection_type")
        return args


class VSPNvmeSubsystemArguments:
    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def nvme_subsystem_facts(cls):
        spec_options = {
            "name": {
                "required": False,
                "type": "str",
            },
            "id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        # args["connection_info"]["options"].pop("subscriber_id")
        args["connection_info"]["options"].pop("connection_type")
        args.pop("state")
        return args

    @classmethod
    def nvme_subsystem(cls):
        namespace_options = {
            "ldev_id": {
                "required": True,
                "type": "str",
            },
            "nickname": {
                "required": False,
                "type": "str",
            },
            "paths": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
        }
        spec_options = {
            "id": {
                "required": False,
                "type": "int",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "host_mode": {
                "required": False,
                "type": "str",
            },
            "enable_namespace_security": {
                "required": False,
                "type": "bool",
                "default": True,
            },
            "ports": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "host_nqns": {
                "required": False,
                "type": "list",
                "elements": "dict",
            },
            "state": {
                "required": False,
                "type": "str",
                "choices": [
                    "add_port",
                    "remove_port",
                    "add_host_nqn",
                    "remove_host_nqn",
                    "add_namespace",
                    "remove_namespace",
                    "add_namespace_path",
                    "remove_namespace_path",
                ],
            },
            "namespaces": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": namespace_options,
            },
            "force": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        # args["connection_info"]["options"].pop("subscriber_id")
        args["connection_info"]["options"].pop("connection_type")
        return args


class VSPResourceGroupArguments:
    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def resource_group_facts(cls):
        spec_options = {
            "name": {
                "required": False,
                "type": "str",
            },
            "id": {
                "required": False,
                "type": "int",
            },
            "is_locked": {
                "required": False,
                "type": "bool",
            },
            "query": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def resource_group(cls):
        hg_args = {
            "name": {
                "required": True,
                "type": "str",
            },
            "port": {
                "required": True,
                "type": "str",
            },
        }
        spec_options = {
            "id": {
                "required": False,
                "type": "int",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "virtual_storage_serial": {
                "required": False,
                "type": "str",
            },
            "virtual_storage_model": {
                "required": False,
                "type": "str",
                "choices": [
                    "VSP_5100H",
                    "VSP_5200H",
                    "VSP_5500H",
                    "VSP_5600H",
                    "VSP_5100",
                    "VSP_5200",
                    "VSP_5500",
                    "VSP_5600",
                    "VSP_E1090",
                    "VSP_E1090H",
                    "VSP_E590",
                    "VSP_E590H",
                    "VSP_E790",
                    "VSP_E790H",
                    "VSP_E990",
                    "VSP_F350",
                    "VSP_F370",
                    "VSP_F400",
                    "VSP_F600",
                    "VSP_F700",
                    "VSP_F800",
                    "VSP_F900",
                    "VSP_F1500",
                    "VSP_G130",
                    "VSP_G150",
                    "VSP_G200",
                    "VSP_G350",
                    "VSP_G370",
                    "VSP_G400",
                    "VSP_G600",
                    "VSP_G700",
                    "VSP_G800",
                    "VSP_G900",
                    "VSP_G1000",
                    "VSP_G1500",
                    "VSP_ONE_B28",
                    "VSP_ONE_B26",
                    "VSP_ONE_B24",
                ],
            },
            "ldevs": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "start_ldev": {
                "required": False,
                "type": "str",
            },
            "end_ldev": {
                "required": False,
                "type": "str",
            },
            "ports": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "parity_groups": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "external_parity_groups": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "storage_pool_ids": {
                "required": False,
                "type": "list",
                "elements": "int",
            },
            "host_groups": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_args,
            },
            "iscsi_targets": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_args,
            },
            "nvm_subsystem_ids": {
                "required": False,
                "type": "list",
                "elements": "int",
            },
            "force": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "add_resource_time_out_in_sec": {
                "required": False,
                "type": "int",
            },
            "state": {
                "required": False,
                "type": "str",
                "choices": [
                    "add_resource",
                    "remove_resource",
                ],
                "default": "add_resource",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args


class VSPGADArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    ssi["required"] = False
    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "secondary_connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "split",
                "resync",
                "swap_split",
                "swap_resync",
                "resize",
                "expand",
            ],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def gad_pair_fact_args(cls):
        spec_options = {
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            "copy_group_name": {"required": False, "type": "str"},
            "secondary_storage_serial_number": {
                "required": False,
                "type": "int",
            },
            "secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "copy_pair_name": {
                "required": False,
                "type": "str",
            },
            "local_device_group_name": {
                "required": False,
                "type": "str",
            },
            "remote_device_group_name": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args.pop("state")

        return args

    @classmethod
    def gad_pair_args_spec(cls):
        hg_options = {
            "name": {
                "required": True,
                "type": "str",
            },
            "enable_preferred_path": {
                "required": False,
                "type": "bool",
            },
            "port": {
                "required": True,
                "type": "str",
            },
            "lun_id": {
                "required": False,
                "type": "int",
            },
        }

        spec_options = {
            "primary_storage_serial_number": {
                "required": False,
                "type": "str",
            },
            "secondary_storage_serial_number": {
                "required": False,
                "type": "str",
            },
            "primary_volume_id": {
                "required": False,
                "type": "str",
            },
            "secondary_pool_id": {
                "required": False,
                "type": "int",
            },
            "consistency_group_id": {
                "required": False,
                "type": "int",
            },
            "allocate_new_consistency_group": {
                "required": False,
                "type": "bool",
            },
            "set_alua_mode": {
                "required": False,
                "type": "bool",
            },
            "primary_hostgroups": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_options,
            },
            "secondary_hostgroups": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_options,
            },
            "secondary_iscsi_targets": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": hg_options,
            },
            "primary_resource_group_name": {
                "required": False,
                "type": "str",
            },
            "secondary_resource_group_name": {
                "required": False,
                "type": "str",
            },
            "quorum_disk_id": {
                "required": False,
                "type": "int",
            },
            "local_device_group_name": {
                "required": False,
                "type": "str",
            },
            "remote_device_group_name": {
                "required": False,
                "type": "str",
            },
            "copy_pair_name": {
                "required": False,
                "type": "str",
            },
            "path_group_id": {
                "required": False,
                "type": "int",
            },
            "copy_group_name": {
                "required": False,
                "type": "str",
            },
            "copy_pace": {
                "required": False,
                "type": "str",
                "choices": ["HIGH", "MEDIUM", "LOW"],
                "default": "MEDIUM",
            },
            "mu_number": {
                "required": False,
                "type": "str",
            },
            "fence_level": {
                "required": False,
                "type": "str",
                "choices": ["NEVER", "DATA", "STATUS", "UNKNOWN"],
                "default": "NEVER",
            },
            "is_data_reduction_force_copy": {
                "required": False,
                "type": "bool",
                "default": True,
            },
            "do_initial_copy": {
                "required": False,
                "type": "bool",
                "default": True,
            },
            "is_consistency_group": {
                "required": False,
                "type": "bool",
            },
            "is_new_group_creation": {
                "required": False,
                "type": "bool",
            },
            "new_volume_size": {
                "required": False,
                "type": "str",
            },
            "begin_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "end_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "provisioned_secondary_volume_id": {
                "required": False,
                "type": "str",
            },
            "secondary_nvm_subsystem": {
                "required": False,
                "type": "dict",
                "options": {
                    "name": {
                        "required": True,
                        "type": "str",
                    },
                    "paths": {
                        "required": False,
                        "type": "list",
                        "elements": "str",
                    },
                },
            },
            "should_delete_svol": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        cls.common_arguments["spec"]["required"] = True
        return cls.common_arguments


#  20240822 - VSPVolumeTieringArguments
class VSPVolumeTieringArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent", "split", "resync"],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def args_spec(cls):
        tiering_policy = {
            "tier_level": {
                "required": False,
                "type": "int",
            },
            "tier1_allocation_rate_min": {
                "required": False,
                "type": "int",
            },
            "tier1_allocation_rate_max": {
                "required": False,
                "type": "int",
            },
            "tier3_allocation_rate_min": {
                "required": False,
                "type": "int",
            },
            "tier3_allocation_rate_max": {
                "required": False,
                "type": "int",
            },
        }

        spec_options = {
            "ldev_id": {
                "required": True,
                "type": "int",
            },
            "is_relocation_enabled": {
                "required": False,
                "type": "bool",
            },
            "tier_level_for_new_page_allocation": {
                "required": False,
                "type": "bool",
            },
            "tiering_policy": {
                "required": False,
                "type": "list",
                "element": "dict",
                "options": tiering_policy,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPUnsubscriberArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def unsubscribe(cls):

        resource = {
            "type": {
                "required": True,
                "type": "str",
            },
            "values": {
                "required": True,
                "type": "list",
                "elements": "str",
            },
        }
        spec_options = {
            "resources": {
                "required": True,
                "type": "list",
                "elements": "dict",
                "options": resource,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        cls.common_arguments.pop("state")
        cls.common_arguments["storage_system_info"]["options"]["serial"][
            "required"
        ] = True
        cls.common_arguments["connection_info"]["options"]["connection_type"][
            "default"
        ] = "gateway"
        cls.common_arguments["connection_info"]["options"].pop("username")
        cls.common_arguments["connection_info"]["options"].pop("password")
        return cls.common_arguments


class VSPCmdDevArguments:

    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": {
            "required": True,
            "type": "dict",
            "options": {
                "address": {
                    "required": True,
                    "type": "str",
                },
                "username": {
                    "required": True,
                    "type": "str",
                },
                "password": {
                    "required": True,
                    "no_log": True,
                    "type": "str",
                },
                "connection_type": {
                    "required": False,
                    "type": "str",
                    "choices": ["direct"],
                    "default": "direct",
                },
            },
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def cmd_dev(cls):
        spec_options = {
            "ldev_id": {
                "required": True,
                "type": "str",
            },
            # "is_command_device_enabled": {
            #     "required": False,
            #     "type": "bool",
            # },
            "is_security_enabled": {
                "required": False,
                "type": "bool",
            },
            "is_user_authentication_enabled": {
                "required": False,
                "type": "bool",
            },
            "is_device_group_definition_enabled": {
                "required": False,
                "type": "bool",
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPResourceGroupLockArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    ssi["required"] = False
    ssi["options"].pop("connection_type")
    # ssi["options"].pop("subscriber_id")
    common_arguments = {
        "storage_system_info": VSPCommonParameters.storage_system_info(),
        "connection_info": VSPCommonParameters.connection_info(),
        "secondary_connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def rg_lock(cls):
        spec_options = {
            "lock_timeout_sec": {
                "required": False,
                "type": "int",
            },
            # "name": {
            #     "required": False,
            #     "type": "str",
            # },
            # "id": {
            #     "required": False,
            #     "type": "int",
            # },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        args = copy.deepcopy(cls.common_arguments)
        # args["connection_info"]["options"].pop("subscriber_id")
        return args


class VSPRemoteStorageRegistrationArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    ssi["required"] = True
    ssi["options"].pop("connection_type")
    # ssi["options"].pop("subscriber_id")
    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "secondary_connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def remote_storage_registration_facts(cls):
        spec_options = {}
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        args.pop("spec")
        # args["connection_info"]["options"].pop("subscriber_id")
        args["connection_info"]["options"].pop("connection_type")
        return args

    @classmethod
    def remote_storage_registration(cls):
        spec_options = {
            # "storage_device_id": {
            #     "required": False,
            #     "type": "str",
            # },
            "rest_server_ip": {
                "required": False,
                "type": "str",
            },
            "rest_server_port": {
                "required": False,
                "type": "int",
            },
            "is_mutual_discovery": {
                "required": False,
                "type": "bool",
            },
            "is_mutual_deletion": {
                "required": False,
                "type": "bool",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        # args["connection_info"]["options"].pop("subscriber_id")
        args["connection_info"]["options"].pop("connection_type")
        return args


class VSPRemoteConnectionArgs:

    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }
    # common_arguments["connection_info"]["options"].pop("subscriber_id")
    common_arguments["connection_info"]["options"].pop("api_token")

    @classmethod
    def remote_connection_facts(cls):
        spec_options = {
            "path_group_id": {
                "required": False,
                "type": "int",
            }
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        args["connection_info"]["options"]["username"]["required"] = True
        args["connection_info"]["options"]["password"]["required"] = True
        return args

    @classmethod
    def remote_iscsi_connection_facts(cls):

        args = copy.deepcopy(cls.common_arguments)
        args.pop("state")
        args.pop("spec")
        args["connection_info"]["options"]["username"]["required"] = True
        args["connection_info"]["options"]["password"]["required"] = True
        return args

    @classmethod
    def remote_connection_args(cls):
        spec_options = {
            "path_group_id": {
                "required": True,
                "type": "int",
            },
            "remote_storage_serial_number": {
                "required": True,
                "type": "str",
            },
            "remote_paths": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "local_port": {
                        "required": True,
                        "type": "str",
                    },
                    "remote_port": {
                        "required": True,
                        "type": "str",
                    },
                },
            },
            "min_remote_paths": {
                "required": False,
                "type": "int",
            },
            "remote_io_timeout_in_sec": {
                "required": False,
                "type": "int",
            },
            "round_trip_in_msec": {
                "required": False,
                "type": "int",
            },
        }

        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = True
        args["connection_info"]["options"]["username"]["required"] = True
        args["connection_info"]["options"]["password"]["required"] = True
        return args

    @classmethod
    def iscsi_remote_connection_args(cls):
        spec_options = {
            "remote_storage_serial_number": {
                "required": True,
                "type": "str",
            },
            "local_port": {
                "required": True,
                "type": "str",
            },
            "remote_port": {
                "required": True,
                "type": "str",
            },
            "remote_storage_ip_address": {
                "required": False,
                "type": "str",
            },
            "remote_tcp_port": {
                "required": False,
                "type": "int",
            },
        }

        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = True
        args["connection_info"]["options"]["username"]["required"] = True
        args["connection_info"]["options"]["password"]["required"] = True
        return args


class VSPDynamicPoolArgs:

    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    ssi["options"].pop("connection_type")
    common_arguments = {
        "connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent", "expand"],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def vsp_dynamic_pool_spec(cls):
        spec_options = {
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "pool_name": {
                "required": False,
                "type": "str",
            },
            "is_encryption_enabled": {
                "required": False,
                "type": "bool",
            },
            "threshold_warning": {
                "required": False,
                "type": "int",
            },
            "threshold_depletion": {
                "required": False,
                "type": "int",
            },
            "drives": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "drive_type_code": {
                        "required": False,
                        "type": "str",
                    },
                    "data_drive_count": {
                        "required": False,
                        "type": "int",
                    },
                },
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args

    @classmethod
    def vsp_dynamic_pool_facts_spec(cls):
        spec_options = {
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "pool_name": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args


class VSPUserGroupArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    common_arguments = {
        "connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def user_group_facts(cls):
        spec_options = {
            "id": {
                "required": False,
                "type": "str",
            },
            "name": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def user_group(cls):
        spec_options = {
            "id": {
                "required": False,
                "type": "str",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "role_names": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "resource_group_ids": {
                "required": False,
                "type": "list",
                "elements": "int",
            },
            "state": {
                "required": False,
                "type": "str",
                "choices": [
                    "add_resource_group",
                    "remove_resource_group",
                    "add_role",
                    "remove_role",
                ],
                "default": None,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPUserArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    common_arguments = {
        "connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def user_facts(cls):
        spec_options = {
            "id": {
                "required": False,
                "type": "str",
            },
            "name": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def user(cls):
        spec_options = {
            "id": {
                "required": False,
                "type": "str",
            },
            "name": {
                "required": False,
                "type": "str",
            },
            "password": {
                "required": False,
                "type": "str",
                "no_log": True,
            },
            "authentication": {
                "required": False,
                "type": "str",
                "choices": ["local", "external"],
                "default": "local",
            },
            "group_names": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "state": {
                "required": False,
                "type": "str",
                "choices": ["add_user_group", "remove_user_group"],
                "default": None,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPMPBladeArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    common_arguments = {
        "connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def mp_facts(cls):
        spec_options = {
            "mp_id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args


class VSPSNMPArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    common_arguments = {
        "connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "test"],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def snmp_facts(cls):
        args = copy.deepcopy(cls.common_arguments)
        args.pop("spec")
        args.pop("state")
        return args

    @classmethod
    def snmp_args(cls):
        authentication = {
            "protocol": {
                "required": False,
                "type": "str",
                "choices": ["MD5", "SHA"],
            },
            "password": {
                "required": False,
                "type": "str",
                "no_log": True,
            },
            "encryption": {
                "required": False,
                "type": "dict",
                "options": {
                    "protocol": {
                        "required": False,
                        "type": "str",
                        "choices": ["AES", "DES"],
                    },
                    "key": {
                        "required": False,
                        "type": "str",
                        "no_log": True,
                    },
                },
            },
        }
        spec_options = {
            "is_snmp_agent_enabled": {
                "required": True,
                "type": "bool",
            },
            "snmp_version": {
                "required": True,
                "type": "str",
                "choices": ["v1", "v2c", "v3"],
            },
            "snmp_v1v2c_trap_destination_settings": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "community": {
                        "required": True,
                        "type": "str",
                    },
                    "send_trap_to": {
                        "required": True,
                        "type": "list",
                        "elements": "str",
                    },
                },
            },
            "snmp_v3_trap_destination_settings": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "user_name": {
                        "required": True,
                        "type": "str",
                    },
                    "send_trap_to": {
                        "required": True,
                        "type": "str",
                    },
                    "authentication": {
                        "required": False,
                        "type": "dict",
                        "options": authentication,
                    },
                },
            },
            "snmp_v1v2c_authentication_settings": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "community": {
                        "required": True,
                        "type": "str",
                    },
                    "requests_permitted": {
                        "required": True,
                        "type": "list",
                        "elements": "str",
                    },
                },
            },
            "snmp_v3_authentication_settings": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "user_name": {
                        "required": True,
                        "type": "str",
                    },
                    "authentication": {
                        "required": False,
                        "type": "dict",
                        "options": authentication,
                    },
                },
            },
            "system_group_information": {
                "required": True,
                "type": "dict",
                "options": {
                    "storage_system_name": {
                        "required": True,
                        "type": "str",
                    },
                    "contact": {
                        "required": True,
                        "type": "str",
                    },
                    "location": {
                        "required": True,
                        "type": "str",
                    },
                },
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPAuditLogArguments:
    ssi = copy.deepcopy(VSPCommonParameters.connection_info())
    # ssi["options"].pop("subscriber_id")
    ssi["options"].pop("connection_type")
    common_arguments = {
        "connection_info": ssi,
        "state": {
            "required": False,
            "type": "str",
            "choices": ["present", "test"],
            "default": "present",
        },
        "spec": {
            "required": False,
            "type": "dict",
            "options": {},
        },
    }

    @classmethod
    def audit_log_facts(cls):
        args = copy.deepcopy(cls.common_arguments)
        args.pop("state")
        args.pop("spec")
        return args

    @classmethod
    def audit_log(cls):
        sys_log_options = {
            "is_enabled": {
                "required": True,
                "type": "bool",
            },
            "ip_address": {
                "required": False,
                "type": "str",
            },
            "port": {
                "required": False,
                "type": "int",
            },
            "client_cert_file_name": {
                "required": False,
                "type": "str",
            },
            "client_cert_file_password": {
                "required": False,
                "type": "str",
                "no_log": True,
            },
            "root_cert_file_name": {
                "required": False,
                "type": "str",
            },
        }

        spec_options = {
            "transfer_protocol": {
                "required": True,
                "type": "str",
                "choices": ["TLS", "UDP"],
            },
            "location_name": {
                "required": True,
                "type": "str",
            },
            "retries": {
                "required": False,
                "type": "bool",
            },
            "retry_interval": {
                "required": False,
                "type": "int",
            },
            "is_detailed": {
                "required": False,
                "type": "bool",
            },
            "primary_syslog_server": {
                "required": False,
                "type": "dict",
                "options": sys_log_options,
            },
            "secondary_syslog_server": {
                "required": False,
                "type": "dict",
                "options": sys_log_options,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class UploadCertFileArgs:
    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }
    common_arguments["connection_info"]["options"].pop("connection_type")

    @classmethod
    def upload_cert_file_args(cls):
        spec_options = {
            "file_path": {
                "required": True,
                "type": "str",
            },
            "file_type": {
                "required": True,
                "type": "str",
                "choices": [
                    "primary_client",
                    "primary_root",
                    "secondary_client",
                    "secondary_root",
                ],
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args


class VSPStorageSystemARgs:
    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }
    common_arguments["connection_info"]["options"].pop("connection_type")

    @classmethod
    def storage_system_args(cls):
        date_time = {
            "is_ntp_enabled": {
                "required": True,
                "type": "bool",
            },
            "ntp_server_names": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "time_zone_id": {
                "required": True,
                "type": "str",
            },
            "system_time": {
                "required": True,
                "type": "str",
            },
            "synchronizing_local_time": {
                "required": False,
                "type": "str",
            },
            "adjusts_daylight_saving_time": {
                "required": False,
                "type": "bool",
            },
            "synchronizes_now": {
                "required": False,
                "type": "bool",
            },
        }
        spec_options = {
            "date_time": {
                "required": True,
                "type": "dict",
                "options": date_time,
            },
        }
        cls.common_arguments["spec"]["options"] = spec_options
        return cls.common_arguments


class VSPVolumeSimpleAPIArguments:
    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "attach_server",
                "detach_server",
                "change_qos_settings",
                "server_present",
            ],
            "default": "present",
        },
    }
    common_arguments["connection_info"]["options"].pop("connection_type")

    @classmethod
    def get_volume_simple_api_args(cls):
        spec_options = {
            "capacity": {
                "required": False,
                "type": "str",
            },
            "number_of_volumes": {
                "required": False,
                "type": "int",
                "default": 1,
            },
            "volume_ids": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "volume_name": {
                "required": False,
                "type": "dict",
                "options": {
                    "base_name": {
                        "required": True,
                        "type": "str",
                    },
                    "start_number": {
                        "required": False,
                        "type": "int",
                    },
                    "number_of_digits": {
                        "required": False,
                        "type": "int",
                    },
                },
            },
            "is_data_reduction_share_enabled": {
                "required": False,
                "type": "bool",
                "default": False,
            },
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "volume_id": {
                "required": False,
                "type": "str",
            },
            "qos_settings": {
                "required": False,
                "type": "dict",
                "options": {
                    "threshold": {
                        "required": False,
                        "type": "dict",
                        "options": {
                            "is_upper_iops_enabled": {
                                "required": False,
                                "type": "bool",
                            },
                            "upper_iops": {
                                "required": False,
                                "type": "int",
                            },
                            "is_upper_transfer_rate_enabled": {
                                "required": False,
                                "type": "bool",
                            },
                            "upper_transfer_rate": {
                                "required": False,
                                "type": "int",
                            },
                            "is_lower_iops_enabled": {
                                "required": False,
                                "type": "bool",
                            },
                            "lower_iops": {
                                "required": False,
                                "type": "int",
                            },
                            "is_lower_transfer_rate_enabled": {
                                "required": False,
                                "type": "bool",
                            },
                            "lower_transfer_rate": {
                                "required": False,
                                "type": "int",
                            },
                            "is_response_priority_enabled": {
                                "required": False,
                                "type": "bool",
                            },
                            "response_priority": {
                                "required": False,
                                "type": "int",
                            },
                        },
                    },
                    "alert_setting": {
                        "required": False,
                        "type": "dict",
                        "options": {
                            "is_upper_alert_enabled": {
                                "required": False,
                                "type": "bool",
                            },
                            "upper_alert_allowable_time": {
                                "required": False,
                                "type": "int",
                            },
                            "is_lower_alert_enabled": {
                                "required": False,
                                "type": "bool",
                            },
                            "lower_alert_allowable_time": {
                                "required": False,
                                "type": "int",
                            },
                            "is_response_alert_enabled": {
                                "required": False,
                                "type": "bool",
                            },
                            "response_alert_allowable_time": {
                                "required": False,
                                "type": "int",
                            },
                        },
                    },
                },
            },
            "server_ids": {
                "required": False,
                "type": "list",
                "elements": "int",
            },
            "capacity_saving": {
                "aliases": ["saving_setting"],
                "required": False,
                "type": "str",
                "choices": ["compression", "deduplication_and_compression", "disable"],
            },
            "compression_acceleration": {
                "required": False,
                "type": "bool",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args

    @classmethod
    def get_volume_simple_api_facts_args(cls):
        spec_options = {
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "pool_name": {
                "required": False,
                "type": "str",
            },
            "server_id": {
                "required": False,
                "type": "int",
            },
            "server_nickname": {
                "required": False,
                "type": "str",
            },
            "nickname": {
                "required": False,
                "type": "str",
            },
            "min_total_capacity": {
                "required": False,
                "type": "str",
            },
            "max_total_capacity": {
                "required": False,
                "type": "str",
            },
            "min_used_capacity": {
                "required": False,
                "type": "str",
            },
            "max_used_capacity": {
                "required": False,
                "type": "str",
            },
            "start_volume_id": {
                "required": False,
                "type": "str",
            },
            "count": {
                "required": False,
                "type": "int",
            },
            "volume_id": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args


class VSPOneSnapshotArguments:
    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "map",
                "restore",
            ],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }
    common_arguments["connection_info"]["options"].pop("connection_type")

    @classmethod
    def get_vsp_one_snapshot_facts_args(cls):
        spec_options = {
            "master_volume_id": {
                "required": False,
                "type": "str",
            },
            "snapshot_date_from": {
                "required": False,
                "type": "str",
            },
            "snapshot_date_to": {
                "required": False,
                "type": "str",
            },
            "snapshot_group_name": {
                "required": False,
                "type": "str",
            },
            "start_id": {
                "required": False,
                "type": "str",
            },
            "count": {
                "required": False,
                "type": "int",
            },
            "snapshot_id": {
                "required": False,
                "type": "int",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def get_vsp_one_snapshot_args(cls):
        new_snapshot_arg = {
            "master_volume_id": {
                "required": True,
                "type": "str",
            },
            "pool_id": {
                "required": True,
                "type": "int",
            },
            "snapshot_group_name": {
                "required": True,
                "type": "str",
            },
            "type": {
                "required": True,
                "type": "str",
            },
        }
        spec_options = {
            "new_snapshots": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": new_snapshot_arg,
            },
            "master_volume_id": {
                "required": False,
                "type": "str",
            },
            "snapshot_id": {
                "required": False,
                "type": "int",
            },
            "pool_id": {
                "required": False,
                "type": "int",
            },
            "should_delete_svol": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args

    @classmethod
    def get_vsp_one_snapshot_group_args(cls):
        spec_options = {
            "snapshot_group_name": {
                "required": False,
                "type": "str",
            },
            "include_snapshots": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def get_vsp_one_snapshot_group(cls):
        spec_options = {
            "snapshot_group_name": {
                "required": True,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        state = args.get("state", {})
        choices = state.get("choices", [])
        for item in ["map", "restore"]:
            if item in choices:
                choices.remove(item)
        return args


class VSPOneServerArguments:
    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "state": {
            "required": False,
            "type": "str",
            "choices": [
                "present",
                "absent",
                "sync_server_nick_name",
                "add_host_groups",
                "add_hba",
                "remove_hba",
                "add_path",
                "remove_path",
                "change_iscsi_target_settings",
            ],
            "default": "present",
        },
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }
    common_arguments["connection_info"]["options"].pop("connection_type")

    @classmethod
    def get_vsp_one_server_args(cls):
        spec_options = {
            "nick_name": {
                "required": False,
                "type": "str",
            },
            "protocol": {
                "required": False,
                "type": "str",
                "choices": ["FC", "iSCSI"],
            },
            "server_id": {
                "required": False,
                "type": "int",
            },
            "os_type": {
                "required": False,
                "type": "str",
                "choices": ["Linux", "HP-UX", "Solaris", "AIX", "VMware", "Windows"],
            },
            "port_ids": {
                "required": False,
                "type": "list",
                "elements": "str",
            },
            "is_reserved": {
                "required": False,
                "type": "bool",
            },
            "os_type_options": {
                "required": False,
                "type": "list",
                "elements": "int",
            },
            "hbas": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "hba_wwn": {
                        "required": False,
                        "type": "str",
                    },
                    "iscsi_name": {
                        "required": False,
                        "type": "str",
                    },
                },
            },
            "paths": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "port_ids": {
                        "required": True,
                        "type": "list",
                        "elements": "str",
                    },
                    "hba_wwn": {
                        "required": False,
                        "type": "str",
                    },
                    "iscsi_name": {
                        "required": False,
                        "type": "str",
                    },
                },
            },
            "keep_lun_config": {
                "required": False,
                "type": "bool",
            },
            "iscsi_target_settings": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "port_id": {
                        "required": True,
                        "type": "str",
                    },
                    "target_iscsi_name": {
                        "required": True,
                        "type": "str",
                    },
                },
            },
            "host_groups": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "host_group_id": {
                        "required": False,
                        "type": "int",
                    },
                    "host_group_name": {
                        "required": False,
                        "type": "str",
                    },
                    "port_id": {
                        "required": False,
                        "type": "str",
                    },
                },
            },
            "iscsi_targets": {
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": {
                    "iscsi_target_id": {
                        "required": False,
                        "type": "int",
                    },
                    "iscsi_target_name": {
                        "required": False,
                        "type": "str",
                    },
                    "port_id": {
                        "required": False,
                        "type": "str",
                    },
                },
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args

    @classmethod
    def get_vsp_one_server_facts_args(cls):
        spec_options = {
            "server_id": {
                "required": False,
                "type": "int",
            },
            "nick_name": {
                "required": False,
                "type": "str",
            },
            "hba_wwn": {
                "required": False,
                "type": "str",
            },
            "iscsi_name": {
                "required": False,
                "type": "str",
            },
            "include_details": {
                "required": False,
                "type": "bool",
                "default": False,
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args

    @classmethod
    def get_vsp_one_hba_facts_args(cls):
        spec_options = {
            "server_id": {
                "required": False,
                "type": "int",
            },
            "hba_wwn": {
                "required": False,
                "type": "str",
            },
            "iscsi_name": {
                "required": False,
                "type": "str",
            },
            "nick_name": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        args.pop("state")
        return args


class VSPOnePortArguments:
    common_arguments = {
        "connection_info": VSPCommonParameters.connection_info(),
        "spec": {
            "required": True,
            "type": "dict",
            "options": {},
        },
    }
    common_arguments["connection_info"]["options"].pop("connection_type")

    @classmethod
    def get_vsp_one_port_facts_args(cls):
        spec_options = {
            "port_id": {
                "required": False,
                "type": "str",
            },
            "protocol": {
                "required": False,
                "type": "str",
            },
        }
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        args["spec"]["required"] = False
        return args

    @classmethod
    def get_vsp_one_port_args(cls):
        spec_options = vsp_one_port_args()
        args = copy.deepcopy(cls.common_arguments)
        args["spec"]["options"] = spec_options
        return args


# # Validator functions # #


RE_INT = re.compile(r"^([0-9]+)$")


class VSPSpecValidators:

    RE_INT = re.compile(r"^([0-9]+)$")

    @staticmethod
    def validate_connection_info(conn_info: ConnectionInfo):

        # For direct connect, api_token is used to pass the lock token
        # if conn_info.connection_type == ConnectionTypes.DIRECT and conn_info.api_token:
        #     raise ValueError(VSPVolValidationMsg.DIRECT_API_TOKEN_ERROR.value)
        if conn_info.username and conn_info.password and conn_info.api_token:
            raise ValueError(VSPVolValidationMsg.BOTH_API_TOKEN_USER_DETAILS.value)
        elif (
            not conn_info.username
            and not conn_info.password
            and not conn_info.api_token
        ):
            raise ValueError(VSPVolValidationMsg.NOT_API_TOKEN_USER_DETAILS.value)
        # elif conn_info.subscriber_id:
        #     is_numeric = RE_INT.match(conn_info.subscriber_id)
        #     if is_numeric is None:
        #         raise ValueError(VSPVolValidationMsg.SUBSCRIBER_ID_NOT_NUMERIC.value)

    @staticmethod
    def validate_volume_facts(input_spec: VolumeFactSpec):
        VALID_QUERY = [
            "cmd_device_settings",
            "encryption_settings",
            "nvm_subsystem_info",
            "qos_settings",
            "snapshots_info",
            "free_ldev_id",
        ]
        logger = Log()

        if input_spec.ldev_id:
            try:
                lun_value = int(input_spec.ldev_id)
                if lun_value < 0 or lun_value > AutomationConstants.LDEV_ID_MAX:
                    raise ValueError(VSPVolValidationMsg.LDEV_ID_OUT_OF_RANGE.value)
            except ValueError as e:
                if "invalid literal" not in str(e):
                    # Handle the case where the input is not a valid integer format
                    raise e
                else:
                    # Handle other ValueErrors, like out-of-range checks
                    logger.writeDebug(f"exception in validate_volume_facts {e}")

        if isinstance(input_spec.start_ldev_id, int) and (
            input_spec.start_ldev_id < 0
            or input_spec.start_ldev_id > AutomationConstants.LDEV_ID_MAX
        ):
            raise ValueError(VSPVolValidationMsg.MAX_LDEV_ID_OUT_OF_RANGE.value)

        if input_spec.count and input_spec.end_ldev_id:
            raise ValueError(VSPVolValidationMsg.END_LDEV_AND_COUNT.value)
        elif isinstance(input_spec.count, int) and input_spec.count < 0:
            raise ValueError(VSPVolValidationMsg.COUNT_VALUE.value)

        if (
            isinstance(input_spec.start_ldev_id, int)
            and isinstance(input_spec.end_ldev_id, int)
            and input_spec.end_ldev_id < input_spec.start_ldev_id
        ):
            raise ValueError(VSPVolValidationMsg.START_LDEV_LESS_END.value)

        if input_spec.query:
            if not isinstance(input_spec.query, list):
                raise ValueError(VSPVolValidationMsg.QUERY_NOT_LIST.value)
            for query in input_spec.query:
                x = query.lower()
                if x not in VALID_QUERY:
                    raise ValueError(
                        VSPVolValidationMsg.INVALID_QUERY.value.format(
                            query, VALID_QUERY
                        )
                    )

    @staticmethod
    def validate_volume_spec(state, input_spec: CreateVolumeSpec):
        valid_capacity_saving = [
            "compression",
            "compression_deduplication",
            "disabled",
        ]

        if isinstance(input_spec.ldev_id, int) and (
            input_spec.ldev_id < 0
            or input_spec.ldev_id > AutomationConstants.LDEV_ID_MAX
        ):
            raise ValueError(VSPVolValidationMsg.LDEV_ID_OUT_OF_RANGE.value)
        if isinstance(input_spec.vldev_id, int) and (
            input_spec.vldev_id < -1
            or input_spec.vldev_id > AutomationConstants.LDEV_ID_MAX_FULL
        ):
            raise ValueError(VSPVolValidationMsg.VLDEV_ID_OUT_OF_RANGE.value)
        if state == StateValue.ABSENT:
            # 2.3 gateway defines spec.ldev for one set of logics,
            # it also defines spec.ldevs as str (not list) for other business logics, it's a mess
            if not input_spec.ldev_id:
                raise ValueError(VSPVolValidationMsg.LUN_REQUIRED.value)
        if input_spec.name:
            if (
                len(input_spec.name) < AutomationConstants.LDEV_NAME_LEN_MIN
                or len(input_spec.name) > AutomationConstants.LDEV_NAME_LEN_MAX
            ):
                raise ValueError(VSPVolValidationMsg.INVALID_LDEV_NAME_LEN.value)
        if input_spec.capacity_saving:
            if input_spec.capacity_saving.lower() not in valid_capacity_saving:
                raise ValueError(
                    VSPVolValidationMsg.INVALID_CAPACITY_SAVING.value.format(
                        input_spec.capacity_saving, valid_capacity_saving
                    )
                )
        if input_spec.start_ldev_id:
            if (
                input_spec.start_ldev_id < AutomationConstants.START_LDEV_ID_MIN
                or input_spec.start_ldev_id > AutomationConstants.START_LDEV_ID_MAX
            ):
                raise ValueError(VSPVolValidationMsg.INVALID_START_LDEV_ID.value)

            if input_spec.end_ldev_id is None:
                raise ValueError(VSPVolValidationMsg.END_LDEV_ID_REQUIRED.value)
            else:
                if (
                    input_spec.end_ldev_id < AutomationConstants.END_LDEV_ID_MIN
                    or input_spec.end_ldev_id > AutomationConstants.END_LDEV_ID_MAX
                ):
                    raise ValueError(VSPVolValidationMsg.INVALID_END_LDEV_ID.value)
                if input_spec.end_ldev_id < input_spec.start_ldev_id:
                    raise ValueError(VSPVolValidationMsg.END_LDEV_LESS_START_LDEV.value)

        else:
            if input_spec.end_ldev_id:
                raise ValueError(VSPVolValidationMsg.START_LDEV_ID_REQUIRED.value)

        if (
            input_spec.is_parallel_execution_enabled is not None
            and input_spec.is_parallel_execution_enabled is True
        ):
            if input_spec.ldev_id:
                raise ValueError(
                    VSPVolValidationMsg.PARALLEL_EXE_LDEV_ID_NOT_ALLOWED.value
                )
            if input_spec.parity_group:
                raise ValueError(
                    VSPVolValidationMsg.PARALLEL_EXE_PG_ID_NOT_ALLOWED.value
                )
            if input_spec.external_parity_group:
                raise ValueError(
                    VSPVolValidationMsg.PARALLEL_EXE_EXT_PG_ID_NOT_ALLOWED.value
                )

        if input_spec.ldev_id and input_spec.start_ldev_id and input_spec.end_ldev_id:
            if (int(input_spec.ldev_id) < input_spec.start_ldev_id) or (
                int(input_spec.ldev_id) > input_spec.end_ldev_id
            ):
                raise ValueError(
                    VSPVolValidationMsg.LDEV_ID_NOT_IN_START_END_LDEV.value
                )

    @staticmethod
    def validate_snapshot_fact(input_spec: SnapshotFactSpec):
        if isinstance(input_spec.pvol, int) and input_spec.pvol < 0:
            raise ValueError(VSPSnapShotValidateMsg.PVOL_VALID_RANGE.value)
        if isinstance(input_spec.mirror_unit_id, int) and (
            input_spec.mirror_unit_id < 0
            or input_spec.mirror_unit_id > AutomationConstants.LDEV_MAX_MU_NUMBER
        ):
            raise ValueError(VSPSnapShotValidateMsg.MU_VALID_RANGE.value)

        if isinstance(input_spec.mirror_unit_id, int) and not isinstance(
            input_spec.pvol, int
        ):
            raise ValueError(VSPSnapShotValidateMsg.MU_VALID_PVOL_VALUE.value)

    @staticmethod
    def validate_hur_fact(input_spec: HurFactSpec):
        if isinstance(input_spec.pvol, int) and input_spec.pvol < 0:
            raise ValueError(VSPSnapShotValidateMsg.PVOL_VALID_RANGE.value)
        if isinstance(input_spec.mirror_unit_id, int) and (
            input_spec.mirror_unit_id < 0
            or input_spec.mirror_unit_id > AutomationConstants.LDEV_MAX_MU_NUMBER
        ):
            raise ValueError(VSPSnapShotValidateMsg.MU_VALID_RANGE.value)

        if isinstance(input_spec.mirror_unit_id, int) and not isinstance(
            input_spec.primary_volume_id, int
        ):
            raise ValueError(VSPSnapShotValidateMsg.MU_VALID_PVOL_VALUE.value)

    @staticmethod
    def validate_snapshot_module(spec: SnapshotReconcileSpec, conn: ConnectionInfo):
        # if spec.state == StateValue.PRESENT:
        # this is incorrect if an existing pair is in the spec
        # ex. for assign/unassign, we don't need group name
        # if spec.snapshot_group_name is None:
        #     raise ValueError(VSPSnapShotValidateMsg.SNAPSHOT_GRP_NAME.value)

        if spec.state in (
            StateValue.RESTORE,
            StateValue.SYNC,
            StateValue.SPLIT,
            # StateValue.ABSENT,
        ) and (not spec.pvol or not spec.mirror_unit_id):
            raise ValueError(VSPSnapShotValidateMsg.MU_PVOL_REQUIRED.value)

        if spec.state == StateValue.ABSENT and not spec.pvol:
            raise ValueError(VSPSnapShotValidateMsg.PVOL_REQUIRED_FOR_DEL.value)

        if spec.state == StateValue.ABSENT:
            if not spec.should_delete_tree:
                if not spec.pvol or not spec.mirror_unit_id:
                    raise ValueError(
                        VSPSnapShotValidateMsg.MU_PVOL_REQUIRED_FOR_REG_DEL.value
                    )
            else:
                if not spec.pvol:
                    raise ValueError(
                        VSPSnapShotValidateMsg.MU_PVOL_REQUIRED_FOR_REG_DEL.value
                    )

        if spec.state == StateValue.SPLIT:
            if not isinstance(spec.pvol, int):
                raise ValueError(VSPSnapShotValidateMsg.PVOL_REQUIRED.value)

            # we have added the support of using pvol pool_id if spec.pool_id is None
            # hence this check is not needed
            #
            # 1) if pool_id is None and mirror_unit_id is None,
            # then we will create new pair and do the auto-split
            # 2) if the user makes the mistake of not providing the mirror_unit_id,
            # we will go ahead and create the pair and auto-split.
            # This can create confusion for the user until the input error is realized.
            #
            # if not isinstance(spec.pool_id, int) and not isinstance(
            #     spec.mirror_unit_id, int
            # ):
            #     raise ValueError(VSPSnapShotValidateMsg.POOL_ID_REQUIRED.value)

            if (
                conn.connection_type == ConnectionTypes.DIRECT
                and not spec.snapshot_group_name
                and not isinstance(spec.mirror_unit_id, int)
            ):
                raise ValueError(VSPSnapShotValidateMsg.SNAPSHOT_GRP_NAME_SPLIT.value)

    @staticmethod
    def validate_parity_group_fact(input_spec: ParityGroupFactSpec):
        if input_spec.parity_group_id is None:
            raise ValueError(VSPParityGroupValidateMsg.EMPTY_PARITY_GROUP_ID.value)

    @staticmethod
    def validate_parity_group(input_spec: ParityGroupSpec):
        if input_spec.parity_group_id is None:
            raise ValueError(VSPParityGroupValidateMsg.EMPTY_PARITY_GROUP_ID.value)

    @staticmethod
    def validate_server_priority_manager_fact(spec):
        if spec.host_wwn and spec.iscsi_name:
            raise ValueError(VSPSpmValidateMsg.BOTH_NOT_ALLOWED.value)

    @staticmethod
    def validate_storage_system_monitor_fact(spec):
        if spec.query == "alerts":
            if spec.alert_type is None:
                raise ValueError(
                    VSPStotageSystemMonitorValidateMsg.ALERT_TYPE_NEEDED.value
                )

    @staticmethod
    def validate_external_parity_group(spec, state):
        if state == StateValue.PRESENT:
            if (
                spec.external_path_group_id is None
                and spec.port_id is None
                and spec.external_wwn
                and spec.lun_id is None
            ):
                raise ValueError(
                    VSPSExternalParityGroupValidateMsg.PRESENT_STATE_FIELD_MISSING.value
                )

    @staticmethod
    def validate_server_priority_manager(spec, state):
        if spec.host_wwn and spec.iscsi_name:
            raise ValueError(VSPSpmValidateMsg.BOTH_NOT_ALLOWED.value)
        if spec.host_wwn is None and spec.iscsi_name is None:
            raise ValueError(VSPSpmValidateMsg.ONE_HBA_RQRD.value)

        if state == StateValue.PRESENT:
            if spec.upper_limit_for_iops and spec.upper_limit_for_transfer_rate_in_MBps:
                raise ValueError(VSPSpmValidateMsg.BOTH_LIMIT_NOT_ALLOWED.value)
            if (
                spec.upper_limit_for_iops is None
                and spec.upper_limit_for_transfer_rate_in_MBps is None
            ):
                raise ValueError(VSPSpmValidateMsg.ONE_LIMIT_RQRD.value)
            if spec.upper_limit_for_iops:
                if spec.upper_limit_for_iops < 1 or spec.upper_limit_for_iops > 65535:
                    raise ValueError(VSPSpmValidateMsg.IOPS_OUT_OF_RANGE.value)
            if spec.host_wwn:
                if len(spec.host_wwn) != 16:
                    raise ValueError(VSPSpmValidateMsg.HBA_WWN_16_CHARS.value)
            if spec.upper_limit_for_transfer_rate_in_MBps:
                if (
                    spec.upper_limit_for_transfer_rate_in_MBps < 1
                    or spec.upper_limit_for_transfer_rate_in_MBps > 31
                ):
                    raise ValueError(VSPSpmValidateMsg.TR_OUT_OF_RANGE.value)

    @staticmethod
    def validate_storage_pool_fact(input_spec: PoolFactSpec):
        pass
        # if input_spec.pool_id is None:
        #     raise ValueError(VSPStoragePoolValidateMsg.EMPTY_POOL_ID.value)

    @staticmethod
    def validate_storage_pool(input_spec: StoragePoolSpec, state: str):

        if state == StateValue.PRESENT:

            if input_spec.start_ldev_id:
                if (
                    input_spec.start_ldev_id < AutomationConstants.START_LDEV_ID_MIN
                    or input_spec.start_ldev_id > AutomationConstants.START_LDEV_ID_MAX
                ):
                    raise ValueError(VSPVolValidationMsg.INVALID_START_LDEV_ID.value)

                if input_spec.end_ldev_id is None:
                    raise ValueError(VSPVolValidationMsg.END_LDEV_ID_REQUIRED.value)
                else:
                    if (
                        input_spec.end_ldev_id < AutomationConstants.END_LDEV_ID_MIN
                        or input_spec.end_ldev_id > AutomationConstants.END_LDEV_ID_MAX
                    ):
                        raise ValueError(VSPVolValidationMsg.INVALID_END_LDEV_ID.value)
                    if input_spec.end_ldev_id < input_spec.start_ldev_id:
                        raise ValueError(
                            VSPVolValidationMsg.END_LDEV_LESS_START_LDEV.value
                        )
                    else:
                        if (
                            input_spec.end_ldev_id - input_spec.start_ldev_id + 1
                            > AutomationConstants.MAX_LDEVS_IN_DP
                        ):
                            raise ValueError(
                                VSPStoragePoolValidateMsg.NO_MORE_THAN_64_LDEVS.value
                            )

            else:
                if input_spec.end_ldev_id:
                    raise ValueError(VSPVolValidationMsg.START_LDEV_ID_REQUIRED.value)

            if input_spec.pool_volumes is not None:
                for pool_volume in input_spec.pool_volumes:
                    if (
                        pool_volume.parity_group_id is None
                        and pool_volume.capacity is None
                    ):
                        raise ValueError(VSPStoragePoolValidateMsg.PG_ID_CAPACITY.value)
                    if (
                        pool_volume.parity_group_id is not None
                        and pool_volume.capacity is None
                    ):
                        raise ValueError(
                            VSPStoragePoolValidateMsg.MISSING_CAPACITY.value.format(
                                pool_volume.parity_group_id
                            )
                        )
                    if (
                        pool_volume.parity_group_id is None
                        and pool_volume.capacity is not None
                    ):
                        raise ValueError(
                            VSPStoragePoolValidateMsg.MISSING_PG_ID.value.format(
                                pool_volume.capacity
                            )
                        )
                    size_in_bytes = convert_to_bytes(pool_volume.capacity)
                    if size_in_bytes < AutomationConstants.POOL_SIZE_MIN:
                        raise ValueError(VSPStoragePoolValidateMsg.POOL_SIZE_MIN.value)

    @staticmethod
    def validate_shadow_image_module(spec: ShadowImagePairSpec, conn: ConnectionInfo):

        if spec.copy_pace is not None:
            options = ["SLOW", "MEDIUM", "FAST"]
            if spec.copy_pace not in options:
                raise ValueError(VSPShadowImagePairValidateMsg.COPY_PACE_VALUE.value)

        if spec.copy_pace_track_size is not None:
            options = ["SLOW", "MEDIUM", "FAST"]
            if spec.copy_pace_track_size not in options:
                raise ValueError(
                    VSPShadowImagePairValidateMsg.COPY_PACE_TRACK_SIZE_VALUE.value
                )

    @staticmethod
    def validate_iscsi_target_spec(input_spec: IscsiTargetSpec):

        if input_spec.name:
            if (
                len(input_spec.name) < AutomationConstants.ISCSI_NAME_LEN_MIN
                or len(input_spec.name) > AutomationConstants.ISCSI_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPIscsiTargetValidationMsg.ISCSI_NAME_OUT_OF_RANGE.value
                )

        if input_spec.iqn_initiators:
            for iqn_initiator in input_spec.iqn_initiators:
                if (
                    len(iqn_initiator.iqn) < AutomationConstants.IQN_LEN_MIN
                    or len(iqn_initiator.iqn) > AutomationConstants.IQN_LEN_MAX
                ):
                    raise ValueError(VSPIscsiTargetValidationMsg.IQN_OUT_OF_RANGE.value)

        if input_spec.ldevs:
            for lun in input_spec.ldevs:
                if (
                    lun < AutomationConstants.LDEV_ID_MIN
                    or lun > AutomationConstants.LDEV_ID_MAX
                ):
                    raise ValueError(VSPIscsiTargetValidationMsg.LUN_OUT_OF_RANGE.value)

        if input_spec.chap_users:
            for chap_user in input_spec.chap_users:
                if chap_user.chap_user_name:
                    if (
                        len(chap_user.chap_user_name)
                        < AutomationConstants.CHAP_USER_NAME_LEN_MIN
                        or len(chap_user.chap_user_name)
                        > AutomationConstants.CHAP_USER_NAME_LEN_MAX
                    ):
                        raise ValueError(
                            VSPIscsiTargetValidationMsg.CHAP_USER_NAME_OUT_OF_RANGE.value
                        )
                if chap_user.chap_secret:
                    if (
                        len(chap_user.chap_secret)
                        < AutomationConstants.CHAP_SECRET_LEN_MIN
                        or len(chap_user.chap_secret)
                        > AutomationConstants.CHAP_SECRET_LEN_MAX
                    ):
                        raise ValueError(
                            VSPIscsiTargetValidationMsg.CHAP_SECRET_OUT_OF_RANGE.value
                        )

        if input_spec.port:
            if (
                len(input_spec.port) < AutomationConstants.NAME_PARAMS_MIN
                or len(input_spec.port) > AutomationConstants.NAME_PARAMS_MAX
            ):
                raise ValueError(VSPIscsiTargetValidationMsg.PORT_OUT_OF_RANGE.value)

        if input_spec.host_mode:
            if (
                len(input_spec.host_mode) < AutomationConstants.NAME_PARAMS_MIN
                or len(input_spec.host_mode) > AutomationConstants.NAME_PARAMS_MAX
            ):
                raise ValueError(
                    VSPIscsiTargetValidationMsg.HOST_MODE_OUT_OF_RANGE.value
                )

        if input_spec.host_mode_options:
            for hmo in input_spec.host_mode_options:
                if (
                    hmo < AutomationConstants.HOST_MODE_OPT_NUMBER_MIN
                    or hmo > AutomationConstants.HOST_MODE_OPT_NUMBER_MAX
                ):
                    raise ValueError(
                        VSPHostGroupValidationMsg.HOST_MODE_OPTION_OUT_OF_RANGE.value
                    )

    @staticmethod
    def validate_host_group_spec(input_spec: HostGroupSpec):

        logger = Log()

        if input_spec.name:
            if (
                len(input_spec.name) < AutomationConstants.HG_NAME_LEN_MIN
                or len(input_spec.name) > AutomationConstants.HG_NAME_LEN_MAX
            ):
                raise ValueError(VSPHostGroupValidationMsg.HG_NAME_OUT_OF_RANGE.value)

        if input_spec.ldevs:
            for lun in input_spec.ldevs:
                logger.writeDebug("1000 lun={}", lun)
                # 2.4 MT - for composite playbook, gateway returns a str, direct returns a int
                lun = int(lun)
                if not isinstance(lun, int):
                    raise ValueError(
                        VSPHostGroupValidationMsg.INVALID_PARAM_LDEVS.value
                    )

                if (
                    lun < AutomationConstants.LDEV_ID_MIN
                    or lun > AutomationConstants.LDEV_ID_MAX
                ):
                    raise ValueError(VSPHostGroupValidationMsg.LUN_OUT_OF_RANGE.value)

        if input_spec.wwns:
            for wwn in input_spec.wwns:
                if (
                    len(wwn.wwn) < AutomationConstants.NAME_PARAMS_MIN
                    or len(wwn.wwn) > AutomationConstants.NAME_PARAMS_MAX
                ):
                    raise ValueError(VSPHostGroupValidationMsg.WWN_OUT_OF_RANGE.value)

        if input_spec.port:
            if (
                len(input_spec.port) < AutomationConstants.NAME_PARAMS_MIN
                or len(input_spec.port) > AutomationConstants.NAME_PARAMS_MAX
            ):
                raise ValueError(VSPHostGroupValidationMsg.PORT_OUT_OF_RANGE.value)

        if input_spec.host_mode:
            if (
                len(input_spec.host_mode) < AutomationConstants.NAME_PARAMS_MIN
                or len(input_spec.host_mode) > AutomationConstants.NAME_PARAMS_MAX
            ):
                raise ValueError(VSPHostGroupValidationMsg.HOST_MODE_OUT_OF_RANGE.value)

        if input_spec.host_mode_options:
            for hmo in input_spec.host_mode_options:
                if (
                    hmo < AutomationConstants.HOST_MODE_OPT_NUMBER_MIN
                    or hmo > AutomationConstants.HOST_MODE_OPT_NUMBER_MAX
                ):
                    raise ValueError(
                        VSPHostGroupValidationMsg.HOST_MODE_OPTION_OUT_OF_RANGE.value
                    )

    @staticmethod
    def validate_port_module(input_spec):
        VALID_PORT_ATTRS = ["TAR", "ALL"]
        VALID_PORT_MODES = ["FC-NVME", "FCP-SCSI"]
        VALID_PORT_CONNECTIONS = ["FCAL", "PTOP", "P2P"]
        rest_port_connection_map = {"FCAL": "FCAL", "P2P": "PtoP", "PTOP": "PtoP"}

        if input_spec.port_attribute is not None:
            if (
                input_spec.port_mode is not None
                or input_spec.port_speed is not None
                or input_spec.port_speed is not None
                or input_spec.fabric_mode is not None
                or input_spec.port_connection is not None
                or input_spec.enable_port_security is not None
            ):
                raise ValueError(VSPStoragePortValidateMsg.PORT_ATTRIBUTE_ONLY.value)
            if input_spec.port_attribute.upper() not in VALID_PORT_ATTRS:
                raise ValueError(
                    VSPStoragePortValidateMsg.INVALID_PORT_ATTRIBUTE.value.format(
                        input_spec.port_attribute, VALID_PORT_ATTRS
                    )
                )
        if input_spec.port_mode is not None:
            if (
                input_spec.port_attribute is not None
                or input_spec.port_speed is not None
                or input_spec.port_speed is not None
                or input_spec.fabric_mode is not None
                or input_spec.port_connection is not None
                or input_spec.enable_port_security is not None
            ):
                raise ValueError(VSPStoragePortValidateMsg.PORT_MODE_ONLY.value)
            if input_spec.port_mode.upper() not in VALID_PORT_MODES:
                raise ValueError(
                    VSPStoragePortValidateMsg.INVALID_PORT_MODE.value.format(
                        input_spec.port_mode, VALID_PORT_MODES
                    )
                )
        if input_spec.fabric_mode is not None:
            if input_spec.port_connection is None:
                raise ValueError(
                    VSPStoragePortValidateMsg.FABRIC_MODE_PORT_CONN_TOGETHER.value
                )
        if input_spec.port_connection is not None:
            if input_spec.fabric_mode is None:
                raise ValueError(
                    VSPStoragePortValidateMsg.FABRIC_MODE_PORT_CONN_TOGETHER.value
                )
            if input_spec.port_connection.upper() not in VALID_PORT_CONNECTIONS:
                raise ValueError(
                    VSPStoragePortValidateMsg.INVALID_PORT_CONNECTIONS.value.format(
                        input_spec.port_connection, VALID_PORT_CONNECTIONS
                    )
                )
            rest_port_connection = rest_port_connection_map.get(
                input_spec.port_connection.upper(), input_spec.port_connection.upper()
            )
            input_spec.port_connection = rest_port_connection
        if input_spec.port_speed is not None:
            pattern = r"[1-9]([0-9])?([0-9])?(G)?"
            ps = input_spec.port_speed
            if ps.upper() != "AUT" and not re.fullmatch(pattern, ps.upper()):
                raise ValueError(
                    VSPStoragePortValidateMsg.INVALID_PORT_SPEED.value.format(ps)
                )
        if len(input_spec.port) < 1:
            raise ValueError(VSPStoragePortValidateMsg.VALID_PORT_ID.value)

    @staticmethod
    def validate_true_copy_module(input_spec):

        if input_spec.consistency_group_id:
            cg_id = input_spec.consistency_group_id
            if (
                cg_id < AutomationConstants.CONSISTENCY_GROUP_ID_MIN
                or cg_id > AutomationConstants.CONSISTENCY_GROUP_ID_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_CG_ID.value)

        if input_spec.secondary_hostgroups:
            for hg in input_spec.secondary_hostgroups:
                # if hg.id is None:
                #     raise ValueError(
                #         VSPTrueCopyValidateMsg.SECONDARY_HOSTGROUPS_ID.value
                #     )
                if hg.name is None:
                    raise ValueError(
                        VSPTrueCopyValidateMsg.SECONDARY_HOSTGROUPS_NAME.value
                    )
                if hg.port is None:
                    raise ValueError(
                        VSPTrueCopyValidateMsg.SECONDARY_HOSTGROUPS_PORT.value
                    )
        if input_spec.copy_group_name:
            if (
                len(input_spec.copy_group_name)
                < AutomationConstants.COPY_GROUP_NAME_LEN_MIN
                or len(input_spec.copy_group_name)
                > AutomationConstants.COPY_GROUP_NAME_LEN_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_COPY_GROUP_NAME.value)

        if input_spec.copy_pair_name:
            if (
                len(input_spec.copy_pair_name)
                < AutomationConstants.COPY_PAIR_NAME_LEN_MIN
                or len(input_spec.copy_pair_name)
                > AutomationConstants.COPY_PAIR_NAME_LEN_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_COPY_PAIR_NAME.value)

        if input_spec.path_group_id:
            cg_id = input_spec.path_group_id
            if (
                cg_id < AutomationConstants.PATH_GROUP_ID_MIN
                or cg_id > AutomationConstants.PATH_GROUP_ID_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_PG_ID.value)

        if input_spec.local_device_group_name:
            if (
                len(input_spec.local_device_group_name)
                < AutomationConstants.DEVICE_GROUP_NAME_LEN_MIN
                or len(input_spec.local_device_group_name)
                > AutomationConstants.DEVICE_GROUP_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPTrueCopyValidateMsg.INVALID_LOCAL_DEVICE_GROUP_NAME.value
                )

        if input_spec.remote_device_group_name:
            if (
                len(input_spec.remote_device_group_name)
                < AutomationConstants.DEVICE_GROUP_NAME_LEN_MIN
                or len(input_spec.remote_device_group_name)
                > AutomationConstants.DEVICE_GROUP_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPTrueCopyValidateMsg.INVALID_REMOTE_DEVICE_GROUP_NAME.value
                )

        if input_spec.copy_pace:
            c_p = input_spec.copy_pace
            valid_cp = ["SLOW", "MEDIUM", "FAST"]
            if c_p.upper() not in valid_cp:
                raise ValueError(
                    VSPTrueCopyValidateMsg.INVALID_CP_VALUE.value.format(valid_cp)
                )

        if input_spec.new_volume_size:
            if (
                len(input_spec.new_volume_size)
                < AutomationConstants.VOLUME_SIZE_LEN_MIN
                or len(input_spec.new_volume_size)
                > AutomationConstants.VOLUME_SIZE_LEN_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_VOLUME_SIZE.value)

    @staticmethod
    def validate_true_copy_fact(input_spec: TrueCopyFactSpec):
        # if input_spec.primary_volume_id is None and input_spec.secondary_volume_id is None:
        #     raise ValueError(VSPTrueCopyValidateMsg.PRIMARY_VOLUME_ID.value)
        pass

    @staticmethod
    def validate_copy_groups_fact(input_spec: CopyGroupsFactSpec):
        pass

    @staticmethod
    def validate_local_copy_groups_fact(input_spec: LocalCopyGroupFactSpec):
        if input_spec.primary_volume_device_group_name:
            if input_spec.name is None:
                raise ValueError(
                    VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_NAME_REQD.value
                )
            if input_spec.secondary_volume_device_group_name is None:
                raise ValueError(
                    VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_BOTH_PVOL_SVOL_DEVICE_REQD.value
                )
        if input_spec.secondary_volume_device_group_name:
            if input_spec.name is None:
                raise ValueError(
                    VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_NAME_REQD.value
                )
            if input_spec.primary_volume_device_group_name is None:
                raise ValueError(
                    VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_BOTH_PVOL_SVOL_DEVICE_REQD.value
                )

    @staticmethod
    def validate_nvme_subsystem_fact(input_spec: VSPNvmeSubsystemFactSpec):
        if input_spec.id:
            if isinstance(input_spec.id, int) and (
                int(input_spec.id) < AutomationConstants.NVM_SUBSYSTEM_MIN_ID
                or int(input_spec.id) > AutomationConstants.NVM_SUBSYSTEM_MAX_ID
            ):
                raise ValueError(VspNvmValidationMsg.NVM_ID_OUT_OF_RANGE.value)

    @staticmethod
    def validate_user_group_fact(input_spec: VSPUserGroupFactSpec):

        if input_spec.id and input_spec.name:
            raise ValueError(VSPUserGroupValidateMsg.NO_UG_ID_OR_UG_NAME.value)

        if input_spec.name:
            if (
                len(input_spec.name) < AutomationConstants.USER_NAME_LEN_MIN
                or len(input_spec.name) > AutomationConstants.USER_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPUserGroupValidateMsg.INVALID_UG_NAME.value.format(
                        AutomationConstants.USER_NAME_LEN_MIN,
                        AutomationConstants.USER_NAME_LEN_MAX,
                    )
                )

    @staticmethod
    def validate_user_fact(input_spec: VSPUserFactSpec):
        if input_spec.id and input_spec.name:
            raise ValueError(VSPUserValidateMsg.NO_USER_ID_OR_USER_NAME.value)

        if input_spec.name:
            if (
                len(input_spec.name) < AutomationConstants.USER_NAME_LEN_MIN
                or len(input_spec.name) > AutomationConstants.USER_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPUserValidateMsg.INVALID_USER_NAME.value.format(
                        AutomationConstants.USER_NAME_LEN_MIN,
                        AutomationConstants.USER_NAME_LEN_MAX,
                    )
                )

    @staticmethod
    def validate_user_group(input_spec: VSPUserGroupSpec):

        valid_role_names = [
            "AUDIT_LOG_ADMIN_VIEW_N_MODIFY",
            "AUDIT_LOG_ADMIN_VIEW_ONLY",
            "SECURITY_ADMIN_VIEW_N_MODIFY",
            "SECURITY_ADMIN_VIEW_ONLY",
            "STORAGE_ADMIN_INIT_CONFIG",
            "STORAGE_ADMIN_LOCAL_COPY",
            "STORAGE_ADMIN_PERF_MGMT",
            "STORAGE_ADMIN_PROVISION",
            "STORAGE_ADMIN_REMOTE_COPY",
            "STORAGE_ADMIN_SYS_RESOURCE_MGMT",
            "STORAGE_ADMIN_VIEW_ONLY",
            "SUPPORT_PERSONNEL",
            "USER_MAINTENANCE",
        ]

        if input_spec.id is None and input_spec.name is None:
            raise ValueError(VSPUserGroupValidateMsg.NO_UG_ID_OR_UG_NAME.value)

        if input_spec.name:
            if (
                len(input_spec.name) < AutomationConstants.USER_NAME_LEN_MIN
                or len(input_spec.name) > AutomationConstants.USER_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPUserGroupValidateMsg.INVALID_UG_NAME.value.format(
                        AutomationConstants.USER_NAME_LEN_MIN,
                        AutomationConstants.USER_NAME_LEN_MAX,
                    )
                )

        if input_spec.resource_group_ids:
            result = check_range(
                input_spec.resource_group_ids,
                AutomationConstants.RG_ID_MIN - 1,
                AutomationConstants.RG_ID_MAX,
            )
            if result is False:
                raise ValueError(VSPUserGroupValidateMsg.INVALID_RG_ID.value)

        if input_spec.role_names:
            for role in input_spec.role_names:
                if role.upper() not in valid_role_names:
                    raise ValueError(
                        VSPUserGroupValidateMsg.INVALID_ROLE_NAME.value.format(
                            valid_role_names
                        )
                    )

    @staticmethod
    def validate_user(input_spec: VSPUserSpec):
        if input_spec.id is None and input_spec.name is None:
            raise ValueError(VSPUserValidateMsg.NO_USER_ID_OR_USER_NAME.value)

        if input_spec.name:
            if (
                len(input_spec.name) < AutomationConstants.USER_NAME_LEN_MIN
                or len(input_spec.name) > AutomationConstants.USER_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPUserValidateMsg.INVALID_USER_NAME.value.format(
                        AutomationConstants.USER_NAME_LEN_MIN,
                        AutomationConstants.USER_NAME_LEN_MAX,
                    )
                )

        if input_spec.password:
            if (
                len(input_spec.password) < AutomationConstants.PASS_LEN_MIN
                or len(input_spec.password) > AutomationConstants.PASS_LEN_MAX
            ):
                raise ValueError(
                    VSPUserValidateMsg.INVALID_PASS_LEN.value.format(
                        AutomationConstants.PASS_LEN_MIN,
                        AutomationConstants.PASS_LEN_MAX,
                    )
                )

        if input_spec.group_names:
            if len(input_spec.group_names) > AutomationConstants.MAX_USER_GROUPS:
                raise ValueError(VSPUserValidateMsg.INVALID_USER_GROUPS.value)

    @staticmethod
    def validate_resource_group_fact(input_spec: VSPResourceGroupFactSpec):
        VALID_QUERY = [
            "ldevs",
            "host_groups",
            "ports",
            "parity_groups",
            "external_parity_groups",
            "storage_pool_ids",
            "iscsi_targets",
            "nvm_subsystem_ids",
        ]

        if input_spec is not None:
            if input_spec.id and input_spec.name:
                raise ValueError(VSPResourceGroupValidateMsg.NO_RG_ID_OR_RG_NAME.value)

            if (input_spec.id or input_spec.name) and input_spec.is_locked is not None:
                raise ValueError(
                    VSPResourceGroupValidateMsg.NO_LOCK_WITH_RG_ID_OR_RG_NAME.value
                )

            # if (input_spec.id or input_spec.name) and input_spec.query:
            #     raise ValueError(VSPResourceGroupValidateMsg.NO_QUERY_WITH_RG_ID_OR_RG_NAME.value)

            if input_spec.id or input_spec.id == 0:
                if (
                    input_spec.id < AutomationConstants.RG_ID_MIN
                    or input_spec.id > AutomationConstants.RG_ID_MAX
                ):
                    raise ValueError(VSPResourceGroupValidateMsg.INVALID_RG_ID.value)

            if input_spec.query:
                for query in input_spec.query:
                    x = query.lower()
                    if x not in VALID_QUERY:
                        raise ValueError(
                            VSPResourceGroupValidateMsg.INVALID_QUERY.value.format(
                                query, VALID_QUERY
                            )
                        )

                if (
                    "storage_pool_ids" in input_spec.query
                    and len(input_spec.query) == 1
                ):
                    raise ValueError(
                        VSPResourceGroupValidateMsg.STORAGE_POOL_IDS_ALONE_NOT_ALLOWED.value
                    )

    @staticmethod
    def validate_resource_group(input_spec: VSPResourceGroupSpec):

        if input_spec.id is None and input_spec.name is None:
            raise ValueError(VSPResourceGroupValidateMsg.NO_RG_ID_OR_RG_NAME.value)
        if input_spec.id is not None and input_spec.name:
            raise ValueError(VSPResourceGroupValidateMsg.BOTH_RG_ID_AND_RG_NAME.value)

        if input_spec.id or input_spec.id == 0:
            if (
                input_spec.id < AutomationConstants.RG_ID_MIN
                or input_spec.id > AutomationConstants.RG_ID_MAX
            ):
                raise ValueError(VSPResourceGroupValidateMsg.INVALID_RG_ID.value)
        if input_spec.name:
            if (
                len(input_spec.name) < AutomationConstants.RG_NAME_LEN_MIN
                or len(input_spec.name) > AutomationConstants.RG_NAME_LEN_MAX
            ):
                raise ValueError(VSPResourceGroupValidateMsg.INVALID_RG_NAME.value)

        # if input_spec.virtual_storage_device_id:
        #     if (
        #         len(input_spec.virtual_storage_device_id)
        #         < AutomationConstants.VIRTUAL_STORAGE_DEVICE_ID_LEN_MIN
        #     ):
        #         raise ValueError(VSPResourceGroupValidateMsg.INVALID_VIRTUAL_STORAGE_DEVICE_ID.value)

        if input_spec.ldevs and (input_spec.start_ldev or input_spec.end_ldev):
            raise ValueError(
                VSPResourceGroupValidateMsg.LDEVS_LIST_AND_RANGE_NOT_ALLOWED.value
            )

        if input_spec.start_ldev:
            if (
                input_spec.start_ldev < AutomationConstants.START_LDEV_ID_MIN
                or input_spec.start_ldev > AutomationConstants.START_LDEV_ID_MAX
            ):
                raise ValueError(
                    VSPResourceGroupValidateMsg.INVALID_START_LDEV_ID.value
                )

            if input_spec.end_ldev is None:
                raise ValueError(VSPResourceGroupValidateMsg.END_LDEV_ID_REQUIRED.value)
            else:
                if (
                    input_spec.end_ldev < AutomationConstants.END_LDEV_ID_MIN
                    or input_spec.end_ldev > AutomationConstants.END_LDEV_ID_MAX
                ):
                    raise ValueError(
                        VSPResourceGroupValidateMsg.INVALID_END_LDEV_ID.value
                    )
                if input_spec.end_ldev < input_spec.start_ldev:
                    raise ValueError(
                        VSPResourceGroupValidateMsg.END_LDEV_LESS_START_LDEV.value
                    )

            # if input_spec.ldevs:
            #     raise ValueError(VSPResourceGroupValidateMsg.NO_START_END_LDEV_AND_LDEV_IDS.value)
        else:
            if input_spec.end_ldev:
                raise ValueError(
                    VSPResourceGroupValidateMsg.START_LDEV_ID_REQUIRED.value
                )

        if input_spec.ldevs:
            for x in input_spec.ldevs:
                if (
                    x < AutomationConstants.LDEV_ID_MIN
                    or x > AutomationConstants.LDEV_ID_MAX
                ):
                    raise ValueError(VSPResourceGroupValidateMsg.INVALID_LDEV_ID.value)

        if input_spec.nvm_subsystem_ids:
            for x in input_spec.nvm_subsystem_ids:
                if (
                    x < AutomationConstants.NVM_SUBSYSTEM_MIN_ID
                    or x > AutomationConstants.NVM_SUBSYSTEM_MAX_ID
                ):
                    raise ValueError(
                        VSPResourceGroupValidateMsg.INVALID_NVM_SUBSYSTEM_ID.value
                    )

    @staticmethod
    def validate_nvme_subsystem(input_spec: VSPNvmeSubsystemSpec):
        VALID_HOST_MODE_VALUES = ["LINUX", "LINUX/IRIX", "VMWARE", "VMWARE_EX", "AIX"]
        if not input_spec.id and not input_spec.name:
            raise ValueError(VspNvmValidationMsg.NOT_NVM_ID_OR_NVM_NAME.value)
        if isinstance(input_spec.id, int) and (
            int(input_spec.id) < AutomationConstants.NVM_SUBSYSTEM_MIN_ID
            or int(input_spec.id) > AutomationConstants.NVM_SUBSYSTEM_MAX_ID
        ):
            raise ValueError(VspNvmValidationMsg.NVM_ID_OUT_OF_RANGE.value)
        if input_spec.host_mode:
            if input_spec.host_mode.upper() not in VALID_HOST_MODE_VALUES:
                raise ValueError(
                    VspNvmValidationMsg.INVALID_HOST_MODE.value.format(
                        VALID_HOST_MODE_VALUES
                    )
                )

    # 20240808 - validate_hur_module
    @staticmethod
    def validate_hur_module(input_spec, state):
        logger = Log()
        logger.writeDebug("state={}", state)
        state = state.lower()

        if input_spec.mirror_unit_id is not None:
            if state == "present":
                raise ValueError("For create, mirror_unit_id is not allowed.")

            #  all other operations, other params are ignored
            return

        # if input_spec.secondary_storage_serial_number is None:
        #     raise ValueError(VSPHurValidateMsg.SECONDARY_STORAGE_SN.value)
        if input_spec.secondary_pool_id is None:
            raise ValueError(VSPHurValidateMsg.SECONDARY_POOL_ID.value)

        # if input_spec.secondary_hostgroups is None:
        #     raise ValueError(VSPHurValidateMsg.SECONDARY_HOSTGROUPS.value)

        if input_spec.primary_volume_journal_id is None:
            raise ValueError(VSPHurValidateMsg.PRIMARY_JOURNAL_ID.value)
        if input_spec.secondary_volume_journal_id is None:
            raise ValueError(VSPHurValidateMsg.SECONDARY_JOURNAL_ID.value)

        if input_spec.consistency_group_id:
            cg_id = input_spec.consistency_group_id
            if (
                cg_id < AutomationConstants.CONSISTENCY_GROUP_ID_MIN
                or cg_id > AutomationConstants.CONSISTENCY_GROUP_ID_MAX
            ):
                raise ValueError(VSPHurValidateMsg.INVALID_CG_ID.value)
            if input_spec.allocate_new_consistency_group:
                raise ValueError(VSPHurValidateMsg.INVALID_CG_NEW.value)

        if input_spec.secondary_hostgroups:
            for hg in input_spec.secondary_hostgroups:
                # if hg.id is None:
                #     raise ValueError(VSPHurValidateMsg.SECONDARY_HOSTGROUPS_ID.value)
                if hg.name is None:
                    raise ValueError(VSPHurValidateMsg.SECONDARY_HOSTGROUPS_NAME.value)
                if hg.port is None:
                    raise ValueError(VSPHurValidateMsg.SECONDARY_HOSTGROUPS_PORT.value)

    @staticmethod
    def validate_gad_pair_spec(input_spec: VspGadPairSpec, state: str):

        if input_spec.consistency_group_id is not None:
            cg_id = input_spec.consistency_group_id
            if cg_id < str(AutomationConstants.CONSISTENCY_GROUP_ID_MIN) or cg_id > str(
                AutomationConstants.CONSISTENCY_GROUP_ID_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_CG_ID.value)

        if input_spec.secondary_hostgroups:
            for hg in input_spec.secondary_hostgroups:
                # if hg.id is None:
                #     raise ValueError(
                #         VSPTrueCopyValidateMsg.SECONDARY_HOSTGROUPS_ID.value
                #     )
                if hg.name is None:
                    raise ValueError(
                        VSPTrueCopyValidateMsg.SECONDARY_HOSTGROUPS_NAME.value
                    )
                if hg.port is None:
                    raise ValueError(
                        VSPTrueCopyValidateMsg.SECONDARY_HOSTGROUPS_PORT.value
                    )
        if input_spec.copy_group_name:
            if (
                len(input_spec.copy_group_name)
                < AutomationConstants.COPY_GROUP_NAME_LEN_MIN
                or len(input_spec.copy_group_name)
                > AutomationConstants.COPY_GROUP_NAME_LEN_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_COPY_GROUP_NAME.value)

        if input_spec.copy_pair_name:
            if (
                len(input_spec.copy_pair_name)
                < AutomationConstants.COPY_PAIR_NAME_LEN_MIN
                or len(input_spec.copy_pair_name)
                > AutomationConstants.COPY_PAIR_NAME_LEN_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_COPY_PAIR_NAME.value)

        if input_spec.path_group_id:
            cg_id = input_spec.path_group_id
            if (
                cg_id < AutomationConstants.PATH_GROUP_ID_MIN
                or cg_id > AutomationConstants.PATH_GROUP_ID_MAX
            ):
                raise ValueError(VSPTrueCopyValidateMsg.INVALID_PG_ID.value)

        if input_spec.local_device_group_name:
            if (
                len(input_spec.local_device_group_name)
                < AutomationConstants.DEVICE_GROUP_NAME_LEN_MIN
                or len(input_spec.local_device_group_name)
                > AutomationConstants.DEVICE_GROUP_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPTrueCopyValidateMsg.INVALID_LOCAL_DEVICE_GROUP_NAME.value
                )

        if input_spec.remote_device_group_name:
            if (
                len(input_spec.remote_device_group_name)
                < AutomationConstants.DEVICE_GROUP_NAME_LEN_MIN
                or len(input_spec.remote_device_group_name)
                > AutomationConstants.DEVICE_GROUP_NAME_LEN_MAX
            ):
                raise ValueError(
                    VSPTrueCopyValidateMsg.INVALID_REMOTE_DEVICE_GROUP_NAME.value
                )

        if input_spec.copy_pace:
            c_p = input_spec.copy_pace
            valid_cp = ["SLOW", "MEDIUM", "FAST"]
            if c_p.upper() not in valid_cp:
                raise ValueError(
                    VSPTrueCopyValidateMsg.INVALID_CP_VALUE.value.format(valid_cp)
                )

        def _validate_hostgroups(hostgroups, pos):
            for hg in hostgroups:

                if hg.name is None:
                    raise ValueError(
                        GADPairValidateMSG.HOSTGROUPS_NAME.value.format(pos)
                    )
                if hg.port is None:
                    raise ValueError(
                        GADPairValidateMSG.HOSTGROUPS_PORT.value.format(pos)
                    )

        if state.lower() == StateValue.PRESENT:
            # if input_spec.primary_storage_serial_number is None:
            #     raise ValueError(GADPairValidateMSG.PRIMARY_STORAGE_SN.value)
            # if input_spec.secondary_storage_serial_number is None:
            #     raise ValueError(GADPairValidateMSG.SECONDARY_STORAGE_SN.value)

            if input_spec.primary_volume_id is None:
                raise ValueError(GADPairValidateMSG.PRIMARY_VOLUME_ID.value)

            if (
                input_spec.secondary_pool_id is None
                and input_spec.provisioned_secondary_volume_id is None
            ):
                raise ValueError(GADPairValidateMSG.SECONDARY_POOL_ID.value)

            if input_spec.primary_hostgroups:
                _validate_hostgroups(input_spec.primary_hostgroups, "Primary")

            if (
                input_spec.secondary_hostgroups is None
                and input_spec.secondary_nvm_subsystem is None
                and input_spec.secondary_iscsi_targets is None
                and input_spec.provisioned_secondary_volume_id is None
            ):
                raise ValueError(GADPairValidateMSG.SECONDARY_HOSTGROUPS_OR_NVME.value)
            else:
                if input_spec.secondary_hostgroups:
                    _validate_hostgroups(input_spec.secondary_hostgroups, "Secondary")

            if (
                input_spec.consistency_group_id
                and input_spec.allocate_new_consistency_group
            ):
                raise ValueError(GADPairValidateMSG.INCONSISTENCY_GROUP.value)

    @staticmethod
    def validate_unsubscribe_module(input_spec):
        # valid_type = [ "port", "volume", "hostgroup", "shadowimage", "storagepool", "iscsi_target", "hurpair", "gadpair", "truecopypair"]
        valid_type = ["port", "volume", "hostgroup", "storagepool", "iscsitarget"]
        if input_spec.resources is None or len(input_spec.resources) < 1:
            raise ValueError("Provide proper type and values for resources.")

        if input_spec.resources is not None:
            for x in input_spec.resources:
                if x["type"].lower() not in valid_type:
                    raise ValueError(
                        GatewayValidationMsg.UNSUPPORTED_RESOURCE_TYPE.value.format(
                            x["type"], valid_type
                        )
                    )
                if x["values"] is None or x["values"] == "":
                    raise ValueError(GatewayValidationMsg.PROVIDE_RESOURCE_VALUE.value)

    @staticmethod
    def validate_cmd_dev(spec):
        pass

    @staticmethod
    def validate_rg_lock(spec):
        # if spec.is_resource_group_locked is None:
        #     raise ValueError(VSPResourceGroupValidateMsg.LOCK_REQUIRED.value)
        # if spec.is_resource_group_locked is False and spec.lock_token is None:
        #     raise ValueError(VSPResourceGroupValidateMsg.LOCK_TOKEN_REQUIRED.value)
        if spec.lock_timeout_sec:
            if (
                spec.lock_timeout_sec < AutomationConstants.RG_LOCK_TIMEOUT_MIN
                or spec.lock_timeout_sec > AutomationConstants.RG_LOCK_TIMEOUT_MAX
            ):
                raise ValueError(VSPResourceGroupValidateMsg.INVALID_RG_TIMEOUT.value)

    @staticmethod
    def validate_remote_storage_registration(spec):
        pass

    @staticmethod
    def validate_remote_storage_registration_fact(spec):
        pass

    @staticmethod
    def validate_dynamic_storage_pool_spec(spec):

        if spec.threshold_warning is not None and spec.threshold_depletion is None:
            raise ValueError(DynamicPoolValidationMsg.WARNING_THRESHOLD_REQUIRED.value)
        if spec.threshold_depletion is not None and spec.threshold_warning is None:
            raise ValueError(DynamicPoolValidationMsg.WARNING_THRESHOLD_REQUIRED.value)
        if spec.threshold_warning is not None and spec.threshold_depletion is not None:

            if spec.threshold_warning > spec.threshold_depletion:
                raise ValueError(
                    DynamicPoolValidationMsg.WARNING_THRESHOLD_GREATER.value
                )
            if not 1 <= spec.threshold_warning <= 100:
                raise ValueError(
                    DynamicPoolValidationMsg.WARNING_THRESHOLD_OUT_OF_RANGE.value
                )
            if not 1 <= spec.threshold_depletion <= 100:
                raise ValueError(
                    DynamicPoolValidationMsg.WARNING_THRESHOLD_OUT_OF_RANGE.value
                )


###############################################################
# Common functions ###
def camel_to_snake_case_dict_array(items):
    new_items = []
    if items:
        for item in items:
            new_dict = camel_to_snake_case_dict(item)
            new_items.append(new_dict)
    return new_items


def camel_to_snake_case_dict(response):
    logger = Log()
    new_dict = {}
    try:
        for key in response.keys():
            cased_key = camel_to_snake_case(key)
            new_dict[cased_key] = response[key]
    except Exception as e:
        logger.writeDebug(f"exception in camel_to_snake_case_dict {e}")

    return new_dict


class NAIDCalculator:
    array_family_map = {
        "ARRAY_FAMILY_DF": ["AMS", "HUS"],
        "ARRAY_FAMILY_R700": ["VSP"],
        "ARRAY_FAMILY_HM700": ["HUS-VM"],
        "ARRAY_FAMILY_R800": ["VSP G1000", "VSP G1500", "VSP F1500"],
        "ARRAY_FAMILY_HM800": [
            "VSP G200",
            "VSP G400",
            "VSP F400",
            "VSP N400",
            "VSP G600",
            "VSP F600",
            "VSP N600",
            "VSP G800",
            "VSP G130",
            "VSP G150",
            "VSP G350",
            "VSP G370",
            "VSP F350",
            "VSP F370",
            "VSP G700",
            "VSP F700",
            "VSP G900",
            "VSP F900",
        ],
        "ARRAY_FAMILY_R900": [
            "VSP 5000",
            "VSP 5000H",
            "VSP 5500",
            "VSP 5500H",
            "VSP 5200",
            "VSP 5200H",
            "VSP 5600",
            "VSP 5600H",
        ],
        "ARRAY_FAMILY_HM900": [
            "VSP E590",
            "VSP E790",
            "VSP E990",
            "VSP E1090",
            "VSP E1090H",
        ],
        "ARRAY_FAMILY_HM2000": [
            "VSP One B23",
            "VSP One B24",
            "VSP One B26",
            "VSP One B28",
        ],
    }

    def __init__(self, wwn_any_port=None, serial_number=None, device_type=None):
        # Convert WWN to integer if it's in hexadecimal string format
        if isinstance(wwn_any_port, str):
            wwn_any_port = int(wwn_any_port, 16)
        self.wwn_any_port = wwn_any_port
        self.serial_number = serial_number
        self.array_family = self.get_array_family(device_type)

        # Mask and adjustment based on array family
        self.wwn_mask_and = 0xFFFFFF00
        self.serial_number_mask_or = 0x00000000

        self._apply_array_family_adjustments()

        # Apply masks
        self.wwn_part = self.wwn_any_port & 0xFFFFFFFF
        self.wwn_part &= self.wwn_mask_and
        self.serial_number |= self.serial_number_mask_or

        # Precompute high bytes since they don't change with LUN
        self.high_bytes = self._compute_high_bytes()

    def get_array_family(self, device_type):
        for array_family, models in self.array_family_map.items():
            for model in models:
                if (
                    model.replace(" ", "").lower()
                    == device_type.replace(" ", "").lower()
                ):
                    return array_family
        return "Unknown array family"

    def _apply_array_family_adjustments(self):
        if self.array_family == "ARRAY_FAMILY_DF":
            self.wwn_mask_and = 0xFFFFFFF0
        elif self.array_family == "ARRAY_FAMILY_HM700":
            while self.serial_number > 99999:
                self.serial_number -= 100000
            self.serial_number_mask_or = 0x50200000
        elif self.array_family == "ARRAY_FAMILY_R800":
            self.serial_number_mask_or = 0x00300000
        elif self.array_family == "ARRAY_FAMILY_HM800":
            while self.serial_number > 99999:
                self.serial_number -= 100000
            self.serial_number_mask_or = 0x50400000
        elif self.array_family == "ARRAY_FAMILY_R900":
            self.serial_number_mask_or = 0x00500000
        elif self.array_family == "ARRAY_FAMILY_HM900":
            if 400000 <= self.serial_number < 500000:
                self.serial_number_mask_or = 0x50400000
            elif 700000 <= self.serial_number < 800000:
                self.serial_number_mask_or = 0x50700000
            else:
                self.serial_number_mask_or = 0x50600000
            while self.serial_number > 99999:
                self.serial_number -= 100000
        elif self.array_family == "ARRAY_FAMILY_HM2000":
            self.serial_number_mask_or = 0x50800000
            while self.serial_number > 99999:
                self.serial_number -= 100000
        else:
            raise ValueError(f"Unsupported array family: {self.array_family}")

    def _compute_high_bytes(self):
        return (
            (0x60 << 56)
            | (0x06 << 48)
            | (0x0E << 40)
            | (0x80 << 32)
            | ((self.wwn_part >> 24) & 0xFF) << 24
            | ((self.wwn_part >> 16) & 0xFF) << 16
            | ((self.wwn_part >> 8) & 0xFF) << 8
            | (self.wwn_part & 0xFF)
        )

    def calculate_naid(self, lun):
        # Compute low bytes with the given LUN
        low_bytes = (
            ((self.serial_number >> 24) & 0xFF) << 56
            | ((self.serial_number >> 16) & 0xFF) << 48
            | ((self.serial_number >> 8) & 0xFF) << 40
            | (self.serial_number & 0xFF) << 32
            | 0x00 << 24
            | 0x00 << 16
            | ((lun >> 8) & 0xFF) << 8
            | (lun & 0xFF)
        )

        # Format NAID
        naid = f"naa.{self.high_bytes:012x}{low_bytes:016x}"
        return naid
