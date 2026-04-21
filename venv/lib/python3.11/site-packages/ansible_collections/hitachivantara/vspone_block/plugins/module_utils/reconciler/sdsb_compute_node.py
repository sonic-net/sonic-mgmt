try:
    from ..provisioner.sdsb_compute_node_provisioner import SDSBComputeNodeProvisioner
    from ..provisioner.sdsb_volume_provisioner import SDSBVolumeProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.sdsb_compute_node_models import (
        VolumeSummaryInfo,
        SDSBComputeNodeAndVolumeInfo,
        SDSBComputeNodeAndVolumeList,
        HbaPortIdPair,
    )
    from ..message.sdsb_compute_node_msgs import SDSBComputeNodeValidationMsg
    from ..message.sdsb_vps_msgs import SDSBVpsValidationMsg
    from .sdsb_vps_helper import SDSBVpsHelper
except ImportError:
    from provisioner.sdsb_compute_node_provisioner import SDSBComputeNodeProvisioner
    from provisioner.sdsb_volume_provisioner import SDSBVolumeProvisioner
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.sdsb_compute_node_models import (
        VolumeSummaryInfo,
        SDSBComputeNodeAndVolumeInfo,
        SDSBComputeNodeAndVolumeList,
        HbaPortIdPair,
    )
    from message.sdsb_compute_node_msgs import SDSBComputeNodeValidationMsg
    from ..message.sdsb_vps_msgs import SDSBVpsValidationMsg
    from sdsb_vps_helper import SDSBVpsHelper

logger = Log()

os_type_dict = {"vmware": "VMware", "linux": "Linux", "windows": "Windows"}


class SDSBComputeNodeSubstates:
    """
    Enum class for SDSB Compute Node Substates
    """

    ADD_ISCSI_INITIATOR = "add_iscsi_initiator"
    REMOVE_ISCSI_INITIATOR = "remove_iscsi_initiator"
    ADD_HOST_NQN = "add_host_nqn"
    REMOVE_HOST_NQN = "remove_host_nqn"
    ATTACH_VOLUME = "attach_volume"
    DETACH_VOLUME = "detach_volume"


class SDSBComputeNodeReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBComputeNodeProvisioner(self.connection_info)
        self.vps_helper = SDSBVpsHelper(self.connection_info)

    @log_entry_exit
    def get_volume_summary(self, cn_id):
        vol_ids = self.get_compute_node_volume_ids(cn_id)
        vol_prov = SDSBVolumeProvisioner(self.connection_info)
        vol_summary_list = []
        for id in vol_ids:
            volume = vol_prov.get_volume_by_id(id)
            vsi = VolumeSummaryInfo(id, volume.name)
            vol_summary_list.append(vsi)
        return vol_summary_list

    @log_entry_exit
    def get_compute_nodes(self, spec=None):

        if spec is not None and spec.hba_name is not None:
            if "[" in spec.hba_name or "]" in spec.hba_name:
                raise ValueError(SDSBComputeNodeValidationMsg.STRING_VALUE_HBA.value)

        # if VPS information is given, populate the vps_id in the spec
        if spec.vps_id is None and spec.vps_name:
            spec.vps_id = self.get_vps_id_by_vps_name(spec.vps_name)
            if not spec.vps_id:
                raise ValueError(
                    SDSBVpsValidationMsg.VPS_NAME_ABSENT.value.format(spec.vps_name)
                )
        elif spec.vps_id:
            if not self.is_vps_exist(spec.vps_id):
                raise ValueError(
                    SDSBVpsValidationMsg.VPS_ID_ABSENT.value.format(spec.vps_id)
                )

        cnodes = self.provisioner.get_compute_nodes(spec)
        logger.writeDebug("RC:get_compute_nodes:cnodes={}", cnodes)

        cn_list = []
        cn_with_vol_list = []
        for cn in cnodes.data:
            cn_by_id = self.get_compute_node_details_by_id(cn.id)
            if cn_by_id.numberOfVolumes > 0:
                vol_summary = self.get_volume_summary(cn.id)
            else:
                vol_summary = []
            cn_with_vol = SDSBComputeNodeAndVolumeInfo(cn_by_id, vol_summary)
            cn_list.append(cn_by_id)
            cn_with_vol_list.append(cn_with_vol)

        # return cnodes
        # return SDSBComputeNodesInfo(data=cn_list)
        return SDSBComputeNodeAndVolumeList(data=cn_with_vol_list)

    @log_entry_exit
    def get_compute_node_by_id(self, id):
        compute_node = self.provisioner.get_compute_node_by_id(id)
        logger.writeDebug("RC:get_compute_node_by_id:compute_node={}", compute_node)
        return compute_node

    @log_entry_exit
    def get_compute_node_details_by_id(self, id):
        compute_node = self.provisioner.get_compute_node_details_by_id(id)
        logger.writeDebug(
            "RC:get_compute_node_details_by_id:compute_node={}", compute_node
        )
        return compute_node

    @log_entry_exit
    def delete_compute_node_by_id(self, id, vps_id=None):
        self.connection_info.changed = True
        return self.provisioner.delete_compute_node_by_id(id, vps_id)

    @log_entry_exit
    def get_compute_node_by_name(self, name):
        return self.provisioner.get_compute_node_by_name(name)

    @log_entry_exit
    def get_vps_id_by_vps_name(self, vps_name):
        return self.vps_helper.get_vps_id_by_vps_name(vps_name)

    @log_entry_exit
    def is_vps_exist(self, vps_id):
        return self.vps_helper.is_vps_exist(vps_id)

    @log_entry_exit
    def create_compute_node(self, name, os_type, vps_id=None):
        self.connection_info.changed = True
        return self.provisioner.create_compute_node(name, os_type, vps_id)

    @log_entry_exit
    def add_iqn_to_compute_node(self, compute_node_id, iqn, vps_id=None):
        # logger.writeDebug('RC:add_iqn_to_compute_node:iqn_id={}', self.provisioner.add_iqn_to_compute_node(compute_node_id, iqn))
        self.connection_info.changed = True
        return self.provisioner.add_iqn_to_compute_node(compute_node_id, iqn, vps_id)

    @log_entry_exit
    def add_nqn_to_compute_node(self, compute_node_id, nqn, vps_id=None):
        response = self.provisioner.add_nqn_to_compute_node(
            compute_node_id, nqn, vps_id
        )
        return response

    @log_entry_exit
    def get_iqn_ids_to_add(self, compute_node_id, iqns, vps_id=None):
        iqn_pairs = self.get_compute_node_iscsi_pairs(compute_node_id, vps_id)
        iqn_ids_to_add = []
        for iqn in iqns:
            if iqn_pairs[iqn]:
                iqn_ids_to_add.append(iqn_pairs[iqn])

        return iqn_ids_to_add

    @log_entry_exit
    def add_iqns_to_compute_node(self, compute_node_id, iqns, vps_id=None):

        for iqn in iqns:
            self.add_iqn_to_compute_node(compute_node_id, iqn, vps_id)

        logger.writeDebug("iqns={}", iqns)
        port_ids = self.get_compute_port_ids()
        # hba_ids = self.get_compute_node_hba_ids(compute_node_id)
        hba_ids = self.get_iqn_ids_to_add(compute_node_id, iqns, vps_id)

        for hba_id in hba_ids:
            for port_id in port_ids:
                self.add_compute_node_path(compute_node_id, hba_id, port_id, vps_id)

    @log_entry_exit
    def get_nqn_ids_to_add(self, compute_node_id, nqns):
        nqn_pairs = self.get_compute_node_nqn_pairs(compute_node_id)
        nqn_ids_to_add = []
        for nqn in nqns:
            if nqn_pairs[nqn]:
                nqn_ids_to_add.append(nqn_pairs[nqn])

        return nqn_ids_to_add

    @log_entry_exit
    def add_nqns_to_compute_node(self, compute_node_id, nqns, vps_id=None):

        for nqn in nqns:
            self.add_nqn_to_compute_node(compute_node_id, nqn, vps_id)

        logger.writeDebug("nqns={}", nqns)
        port_ids = self.get_compute_port_ids()
        # nqn_ids = self.get_compute_node_nqn_ids(compute_node_id)
        nqn_ids = self.get_nqn_ids_to_add(compute_node_id, nqns)
        logger.writeDebug("nqn_ids={}", nqn_ids)

        for nqn_id in nqn_ids:
            for port_id in port_ids:
                self.add_compute_node_path(compute_node_id, nqn_id, port_id)
        self.connection_info.changed = True

    @log_entry_exit
    def get_hba_paths(self, compute_node_id, vps_id=None):
        paths = self.provisioner.get_hba_paths(compute_node_id, vps_id)
        logger.writeDebug("RC:get_hba_paths:data={}", paths)
        return paths

    @log_entry_exit
    def remove_iqns_from_compute_node(
        self, compute_node_id, iqns_to_remove, vps_id=None
    ):
        logger.writeDebug(
            "RC:remove_iqns_from_compute_node:iqns_to_remove={}", iqns_to_remove
        )

        id_list = []
        hba_paths = self.get_hba_paths(compute_node_id)
        for x in iqns_to_remove:
            for p in hba_paths:
                if p.hbaName == x:
                    n = HbaPortIdPair(p.hbaId, p.portId)
                    id_list.append(n)

        for x in id_list:
            self.delete_hba_path(compute_node_id, x)

        pairs = self.get_compute_node_hba_name_id_pairs(compute_node_id, vps_id)
        for x in iqns_to_remove:
            for p in pairs:
                if p.name == x:
                    self.delete_hba(compute_node_id, p.id)

    @log_entry_exit
    def remove_nqns_from_compute_node(self, compute_node_id, nqns_to_remove):
        logger.writeDebug(
            "RC:remove_nqns_from_compute_node:nqns_to_remove={}", nqns_to_remove
        )

        id_list = []
        hba_paths = self.get_hba_paths(compute_node_id)
        for x in nqns_to_remove:
            for p in hba_paths:
                if p.hbaName == x:
                    n = HbaPortIdPair(p.hbaId, p.portId)
                    id_list.append(n)

        for x in id_list:
            self.delete_hba_path(compute_node_id, x)

        pairs = self.get_compute_node_nqn_name_id_pairs(compute_node_id)
        for x in nqns_to_remove:
            for p in pairs:
                if p.name == x:
                    self.delete_hba(compute_node_id, p.id)

    @log_entry_exit
    def detach_volume_from_compute_node(
        self, compute_node_id, vol_id_to_detach, vps_id=None
    ):
        self.connection_info.changed = True
        self.provisioner.detach_volume_from_compute_node(
            compute_node_id, vol_id_to_detach, vps_id
        )

    @log_entry_exit
    def delete_hba_path(self, compute_node_id, hba_port_id_pair):
        logger.writeDebug("RC:delete_hba_path:hba_port_id_pair={}", hba_port_id_pair)
        self.connection_info.changed = True
        self.provisioner.delete_hba_path(compute_node_id, hba_port_id_pair)

    @log_entry_exit
    def delete_hba(self, compute_node_id, hba_id, vps_id=None):
        logger.writeDebug("RC:delete_hba:hba_id={}", hba_id)
        self.connection_info.changed = True
        self.provisioner.delete_hba(compute_node_id, hba_id, vps_id)

    @log_entry_exit
    def add_compute_node_path(self, compute_node_id, iqn_id, port_id, vps_id=None):
        self.connection_info.changed = True
        self.provisioner.add_compute_node_path(compute_node_id, iqn_id, port_id, vps_id)

    @log_entry_exit
    def get_compute_port_ids(self):
        ports = self.provisioner.get_compute_port_ids()
        logger.writeDebug("RC:get_compute_port_ids:compute_port_ids={}", ports)
        return ports

    @log_entry_exit
    def get_compute_ports(self, spec=None):
        ports = self.provisioner.get_compute_ports(spec)
        logger.writeDebug("RC:get_compute_ports:ports={}", ports)
        return ports

    @log_entry_exit
    def get_compute_node_hba_ids(self, compute_node_id, vps_id=None):
        hba_ids = self.provisioner.get_compute_node_hba_ids(compute_node_id, vps_id)
        logger.writeDebug("compute_node_hba_ids={}", hba_ids)
        return hba_ids

    @log_entry_exit
    def get_compute_node_nqn_pairs(self, compute_node_id, vps_id=None):
        nqn_pairs = self.provisioner.get_compute_node_nqn_pairs(compute_node_id, vps_id)
        logger.writeDebug("RC:get_compute_node_nqn_pairs={}", nqn_pairs)
        return nqn_pairs

    @log_entry_exit
    def get_compute_node_iscsi_pairs(self, compute_node_id, vps_id=None):
        iscsi_pairs = self.provisioner.get_compute_node_iscsi_pairs(
            compute_node_id, vps_id
        )
        logger.writeDebug("RC:get_compute_node_iscsi_pairs={}", iscsi_pairs)
        return iscsi_pairs

    @log_entry_exit
    def get_compute_node_nqn_ids(self, compute_node_id, vps_id=None):
        nqn_ids = self.provisioner.get_compute_node_nqn_ids(compute_node_id, vps_id)
        logger.writeDebug("get_compute_node_nqn_ids={}", nqn_ids)
        return nqn_ids

    @log_entry_exit
    def get_compute_node_hba_name_id_pairs(self, compute_node_id, vps_id=None):
        pairs = self.provisioner.get_compute_node_hba_name_id_pairs(
            compute_node_id, vps_id
        )
        logger.writeDebug("compute_node_hba_ids={}", pairs)
        return pairs

    @log_entry_exit
    def get_compute_node_nqn_name_id_pairs(self, compute_node_id, vps_id=None):
        pairs = self.provisioner.get_compute_node_nqn_name_id_pairs(
            compute_node_id, vps_id
        )
        logger.writeDebug("compute_node_nqn_ids={}", pairs)
        return pairs

    @log_entry_exit
    def attach_volume_to_compute_node(self, compute_node_id, volume_id, vps_id=None):
        self.connection_info.changed = True
        return self.provisioner.attach_volume_to_compute_node(
            compute_node_id, volume_id, vps_id
        )

    @log_entry_exit
    def pre_check_volumes(self, volumes):
        volume_ids = self.get_volume_ids(volumes)
        if len(volume_ids) != len(volumes):
            raise ValueError(SDSBComputeNodeValidationMsg.VOLUMES_EXIST.value)
        return volume_ids

    @log_entry_exit
    def add_volumes_to_compute_node(self, compute_node_id, volume_ids, vps_id=None):

        for vid in volume_ids:
            self.attach_volume_to_compute_node(compute_node_id, vid, vps_id)

    @log_entry_exit
    def get_volume_ids(self, volumes):

        vol_ids = []
        for volume in volumes:
            logger.writeDebug("RC:get_volume_ids:volume={}", volume)
            v = SDSBVolumeProvisioner(self.connection_info).get_volume_by_name(volume)
            logger.writeDebug("RC:get_volume_ids:v={}", v)
            if v:
                vol_ids.append(v.id)

        logger.writeDebug("RC:get_volume_ids:vol_ids={}", vol_ids)
        return vol_ids

    @log_entry_exit
    def create_sdsb_compute_node(self, spec):
        # this is a create
        logger.writeDebug("RC:=== Create Compute Node ===")

        # if the os_type is not provided throw error
        if spec.os_type is None:
            raise ValueError(
                SDSBComputeNodeValidationMsg.OS_TYPE_REQUIRED.value.format(spec.os_type)
            )
        else:
            os_type = os_type_dict.get(spec.os_type.lower())
            if os_type is None:
                raise ValueError(
                    SDSBComputeNodeValidationMsg.INVALID_OS_TYPE.value.format(
                        spec.os_type
                    )
                )
            else:
                spec.os_type = os_type

        # if spec.state is None or empty during create, we will try to attach volumes and
        # add iSCSI initiators or host NQNs, based on the information provided in the spec.
        # Also note that either IQN or NQN will work depending on the compute port protocol setting.
        if spec.state is None or spec.state == "":
            if (
                spec.iscsi_initiators is not None
                and len(spec.iscsi_initiators) > 0
                and spec.host_nqns is not None
                and len(spec.host_nqns) > 0
            ):
                logger.writeDebug(
                    "RC:=== spec.state is None, and both iscsi_initiators and host nqns are provided ==="
                )
                raise ValueError(
                    SDSBComputeNodeValidationMsg.ADD_BOTH_IQN_NQN_ERR.value
                )
            vol_ids = []
            if spec.volumes is not None and len(spec.volumes) > 0:
                logger.writeDebug(
                    "RC:substate = {}  volumes={}", spec.state, spec.volumes
                )
                vol_ids = self.pre_check_volumes(spec.volumes)
            compute_node_id = self.create_compute_node(
                spec.name, spec.os_type, spec.vps_id
            )
            logger.writeDebug("RC:compute_node_id={}", compute_node_id)
            if spec.iscsi_initiators is not None and len(spec.iscsi_initiators) > 0:
                logger.writeDebug(
                    "RC:substate = None  iqns={}",
                    spec.iscsi_initiators,
                )
                self.add_iqns_to_compute_node(
                    compute_node_id, spec.iscsi_initiators, spec.vps_id
                )
            if spec.host_nqns is not None and len(spec.host_nqns) > 0:
                logger.writeDebug(
                    "RC:substate = None  nqns={}",
                    spec.host_nqns,
                )
                self.add_nqns_to_compute_node(
                    compute_node_id, spec.host_nqns, spec.vps_id
                )
            self.add_volumes_to_compute_node(compute_node_id, vol_ids, spec.vps_id)
        elif spec.state.lower() == SDSBComputeNodeSubstates.ADD_ISCSI_INITIATOR:
            if spec.iscsi_initiators is not None and len(spec.iscsi_initiators) > 0:
                compute_node_id = self.create_compute_node(
                    spec.name, spec.os_type, spec.vps_id
                )
                logger.writeDebug(
                    "RC:add_iscsi_initiator:compute_node_id={}", compute_node_id
                )
                # iqns are present in the spec, so add them to the newly created compute node
                logger.writeDebug(
                    "RC:substate = {}  iqns={}",
                    SDSBComputeNodeSubstates.ADD_ISCSI_INITIATOR,
                    spec.iscsi_initiators,
                )
                self.add_iqns_to_compute_node(
                    compute_node_id, spec.iscsi_initiators, spec.vps_id
                )
            else:
                logger.writeDebug(
                    "RC:=== spec.state is add_iscsi_initiator, but iscsi_initiators not provided ==="
                )
                raise ValueError(SDSBComputeNodeValidationMsg.ADD_ISCSI_ERR.value)

        elif spec.state.lower() == SDSBComputeNodeSubstates.ADD_HOST_NQN:
            if spec.host_nqns is not None and len(spec.host_nqns) > 0:
                compute_node_id = self.create_compute_node(
                    spec.name, spec.os_type, spec.vps_id
                )
                logger.writeDebug("RC:add_host_nqn:compute_node_id={}", compute_node_id)
                # nqns are present in the spec, so add them to the newly created compute node
                logger.writeDebug(
                    "RC:substate = {}  nqns={}",
                    SDSBComputeNodeSubstates.ADD_HOST_NQN,
                    spec.host_nqns,
                )
                self.add_nqns_to_compute_node(
                    compute_node_id, spec.host_nqns, spec.vps_id
                )
            else:
                logger.writeDebug(
                    "RC:=== spec.state is add_host_nqns, but host_nqns not provided ==="
                )
                raise ValueError(SDSBComputeNodeValidationMsg.ADD_NQNS_ERR.value)

        elif spec.state.lower() == SDSBComputeNodeSubstates.ATTACH_VOLUME:
            if spec.volumes is not None and len(spec.volumes) > 0:
                logger.writeDebug(
                    "RC:substate = {}  volumes={}", spec.state, spec.volumes
                )
                vol_ids = self.pre_check_volumes(spec.volumes)
                # All volumes are present in the spec, so add them to the newly created compute node
                compute_node_id = self.create_compute_node(
                    spec.name, spec.os_type, spec.vps_id
                )
                logger.writeDebug(
                    "RC:attach_volumes:compute_node_id={}", compute_node_id
                )
                self.add_volumes_to_compute_node(compute_node_id, vol_ids)
            else:
                logger.writeDebug(
                    "RC:=== spec.state is attach_volume, but volumes not provided ==="
                )
                raise ValueError(SDSBComputeNodeValidationMsg.ATTACH_VOLUME_ERR.value)

        vol_summary = self.get_volume_summary(compute_node_id)
        cn = self.get_compute_node_details_by_id(compute_node_id)
        cn_with_vol = SDSBComputeNodeAndVolumeInfo(cn, vol_summary)
        return cn_with_vol

    @log_entry_exit
    def get_compute_node_volume_ids(self, compute_node_id):
        return self.provisioner.get_compute_node_volume_ids(compute_node_id)

    @log_entry_exit
    def update_compute_node(self, compute_node_id, spec):
        self.connection_info.changed = True
        self.provisioner.update_compute_node(compute_node_id, spec)

    @log_entry_exit
    def update_add_iqns(self, compute_node_id, iscsi_initiators, vps_id=None):

        if iscsi_initiators is None:
            return

        iqn_names = self.provisioner.get_compute_node_hba_names(compute_node_id, vps_id)
        logger.writeDebug("RC:update_add_iqns:iqn_names={}", iqn_names)

        iqns_to_add = []
        for x in iscsi_initiators:
            if x not in iqn_names:
                iqns_to_add.append(x)

        self.add_iqns_to_compute_node(compute_node_id, iqns_to_add, vps_id)

    @log_entry_exit
    def update_add_nqns(self, compute_node_id, host_nqns, vps_id=None):

        if host_nqns is None:
            return

        nqn_names = self.provisioner.get_compute_node_nqn_names(compute_node_id, vps_id)
        logger.writeDebug("RC:update_add_nqns:nqn_names={}", nqn_names)

        nqns_to_add = [x for x in host_nqns if x not in nqn_names]
        logger.writeDebug("RC:update_add_nqns:nqn_to_add={}", nqns_to_add)
        self.add_nqns_to_compute_node(compute_node_id, nqns_to_add, vps_id)

    @log_entry_exit
    def get_compute_node_volume_names(self, vol_ids):
        volume_names = []
        vol_prov = SDSBVolumeProvisioner(self.connection_info)
        for id in vol_ids:
            v = vol_prov.get_volume_name_by_id(id)
            volume_names.append(v)

        return volume_names

    @log_entry_exit
    def get_compute_node_volume_name_id_pairs(self, vol_ids):
        volume_name_id_pairs = dict()
        vol_prov = SDSBVolumeProvisioner(self.connection_info)
        for id in vol_ids:
            v = vol_prov.get_volume_name_by_id(id)
            volume_name_id_pairs[v] = id

        return volume_name_id_pairs

    @log_entry_exit
    def update_attach_volumes(self, compute_node_id, volumes, vps_id=None):

        if volumes is None:
            return

        vol_prov = SDSBVolumeProvisioner(self.connection_info)
        # get all the volume names present in the system
        all_volume = vol_prov.get_volumes()
        logger.writeDebug("RC:update_attach_volumes:all_volume_names={}", all_volume)

        # valid volumes are the volumes which are common between all_volume_names and user supplied volume names
        valid_volume_ids = []
        for v in all_volume.data:
            if v.name in volumes:
                valid_volume_ids.append(v.id)
        logger.writeDebug(
            "RC:update_attach_volumes:valid_volume_ids={}", valid_volume_ids
        )

        # now find the volumes ids that are already attached to the compute node
        vol_ids = self.get_compute_node_volume_ids(compute_node_id)

        logger.writeDebug("RC:update_attach_volumes:vol_names_attached={}", vol_ids)

        # create a list of volume ids that need to be attached to a compute node.
        vol_to_attach = []
        for v in valid_volume_ids:
            if v not in vol_ids:
                vol_to_attach.append(v)
        logger.writeDebug("RC:update_attach_volumes:vol_to_attach={}", vol_to_attach)

        self.add_volumes_to_compute_node(compute_node_id, vol_to_attach, vps_id)

    @log_entry_exit
    def update_remove_iqns(self, compute_node_id, iscsi_initiators, vps_id=None):

        if iscsi_initiators is None:
            return

        iqn_names = self.provisioner.get_compute_node_hba_names(compute_node_id, vps_id)
        logger.writeDebug("RC:update_remove_iqns:iqn_names={}", iqn_names)

        iqns_to_remove = []
        for x in iscsi_initiators:
            if x in iqn_names:
                iqns_to_remove.append(x)

        self.remove_iqns_from_compute_node(compute_node_id, iqns_to_remove, vps_id)

    @log_entry_exit
    def update_remove_nqns(self, compute_node_id, host_nqns, vps_id=None):

        if host_nqns is None:
            return

        nqn_names = self.provisioner.get_compute_node_nqn_names(compute_node_id, vps_id)
        logger.writeDebug("RC:update_remove_nqns:nqn_names={}", nqn_names)

        nqns_to_remove = []
        for x in host_nqns:
            if x in nqn_names:
                nqns_to_remove.append(x)

        self.remove_nqns_from_compute_node(compute_node_id, nqns_to_remove)

    @log_entry_exit
    def update_detach_volumes(self, compute_node_id, volumes, vps_id=None):
        if volumes is None:
            return

        # now find the volumes names that are already attached to the compute node
        vol_ids = self.get_compute_node_volume_ids(compute_node_id)
        vol_attached = self.get_compute_node_volume_name_id_pairs(vol_ids)

        for x in volumes:
            vol_id_to_detach = vol_attached.get(x)
            if vol_id_to_detach is not None:
                self.detach_volume_from_compute_node(
                    compute_node_id, vol_id_to_detach, vps_id
                )

    @log_entry_exit
    def update_sdsb_compute_node(self, compute_node, spec):
        logger.writeDebug("RC:=== Update Compute Node ===")

        changed = False
        # if the name is not provided use the current name
        if spec.name is None:
            spec.name = compute_node.nickname

        # if the os_type is not provided use the current os_type
        if spec.os_type is None:
            spec.os_type = compute_node.osType
        else:
            os_type = os_type_dict.get(spec.os_type.lower())
            if os_type is None:
                raise ValueError(
                    SDSBComputeNodeValidationMsg.INVALID_OS_TYPE.value.format(
                        spec.os_type
                    )
                )
            else:
                spec.os_type = os_type

        if spec.name != compute_node.nickname:
            changed = True

        if spec.os_type != compute_node.osType:
            changed = True

        if changed:
            self.update_compute_node(compute_node.id, spec)

        if spec.state is not None:
            if spec.state.lower() == SDSBComputeNodeSubstates.ADD_ISCSI_INITIATOR:
                self.update_add_iqns(
                    compute_node.id, spec.iscsi_initiators, spec.vps_id
                )
            elif spec.state.lower() == SDSBComputeNodeSubstates.ADD_HOST_NQN:
                self.update_add_nqns(compute_node.id, spec.host_nqns, spec.vps_id)
            elif spec.state.lower() == SDSBComputeNodeSubstates.REMOVE_ISCSI_INITIATOR:
                self.update_remove_iqns(
                    compute_node.id, spec.iscsi_initiators, spec.vps_id
                )
            elif spec.state.lower() == SDSBComputeNodeSubstates.REMOVE_HOST_NQN:
                self.update_remove_nqns(compute_node.id, spec.host_nqns, spec.vps_id)
            elif spec.state.lower() == SDSBComputeNodeSubstates.ATTACH_VOLUME:
                self.update_attach_volumes(compute_node.id, spec.volumes, spec.vps_id)
            elif spec.state.lower() == SDSBComputeNodeSubstates.DETACH_VOLUME:
                self.update_detach_volumes(compute_node.id, spec.volumes, spec.vps_id)
            else:
                raise ValueError(
                    SDSBComputeNodeValidationMsg.INVALID_SPEC_STATE.value.format(
                        SDSBComputeNodeSubstates.ADD_ISCSI_INITIATOR,
                        SDSBComputeNodeSubstates.REMOVE_ISCSI_INITIATOR,
                        SDSBComputeNodeSubstates.ATTACH_VOLUME,
                        SDSBComputeNodeSubstates.DETACH_VOLUME,
                        SDSBComputeNodeSubstates.ADD_HOST_NQN,
                        SDSBComputeNodeSubstates.REMOVE_HOST_NQN,
                    )
                )

        compute_node_id = compute_node.id
        vol_summary = self.get_volume_summary(compute_node_id)
        cn = self.get_compute_node_details_by_id(compute_node_id)
        cn_with_vol = SDSBComputeNodeAndVolumeInfo(cn, vol_summary)
        return cn_with_vol

    @log_entry_exit
    def reconcile_compute_node(self, state, spec):
        logger.writeDebug("RC:=== reconcile_compute_node ===")

        if spec is None:
            raise ValueError(SDSBComputeNodeValidationMsg.NO_SPEC.value)

        # if VPS information is given, populate the vps_id in the spec
        if spec.vps_id is None and spec.vps_name:
            spec.vps_id = self.get_vps_id_by_vps_name(spec.vps_name)
            if not spec.vps_id:
                raise ValueError(
                    SDSBVpsValidationMsg.VPS_NAME_ABSENT.value.format(spec.vps_name)
                )
        elif spec.vps_id:
            if not self.is_vps_exist(spec.vps_id):
                raise ValueError(
                    SDSBVpsValidationMsg.VPS_ID_ABSENT.value.format(spec.vps_id)
                )

        if state.lower() == StateValue.PRESENT:
            if spec.id is not None:
                logger.writeDebug("RC:=== spec.id is not None ===")
                # user provided an id of the compute node, so this must be an update
                compute_node = self.get_compute_node_by_id(spec.id)
                if compute_node is not None:
                    cn = compute_node
                    logger.writeDebug("RC:compute_node={}", cn)
                    return self.update_sdsb_compute_node(cn, spec)
                else:
                    logger.writeDebug(
                        "RC:=== spec.id is not None + compute_node is None ==="
                    )
                    raise ValueError(
                        SDSBComputeNodeValidationMsg.COMPUTE_NODE_ID_ABSENT.value.format(
                            spec.id
                        )
                    )

            else:
                # this could be a create or an update
                if spec.name is not None:
                    logger.writeDebug("RC:=== spec.name is not None ===")
                    compute_node = self.get_compute_node_by_name(spec.name)

                    if compute_node is not None:
                        # this is an update
                        cn = compute_node
                        logger.writeDebug("RC:compute_node={}", cn)
                        return self.update_sdsb_compute_node(cn, spec)
                    else:
                        # this is a create
                        return self.create_sdsb_compute_node(spec)
                else:
                    raise ValueError(SDSBComputeNodeValidationMsg.NO_NAME_ID.value)

        if state.lower() == StateValue.ABSENT:
            logger.writeDebug("RC:=== Delete Compute Node ===")
            logger.writeDebug("RC:state = {}", state)
            logger.writeDebug("RC:spec = {}", spec)
            if spec.id is not None:
                compute_node_id = spec.id
            elif spec.name is not None:
                # user provided an compute node name, so this must be a delete
                compute_node = self.get_compute_node_by_name(spec.name)
                logger.writeDebug("RC:compute_node={}", compute_node)
                if compute_node is None:
                    raise ValueError(
                        SDSBComputeNodeValidationMsg.CN_NAME_NOT_FOUND.value.format(
                            spec.name
                        )
                    )
                compute_node_id = compute_node.id
                # compue_node_id = self.delete_compute_node_by_id(compute_node.id)
                # return compute_node.nickname
            else:
                raise ValueError(SDSBComputeNodeValidationMsg.NO_NAME_ID.value)

            if spec.should_delete_all_volumes:
                self.delete_volumes_with_no_server_connection(
                    compute_node_id, spec.vps_id
                )

            cn_id = self.delete_compute_node_by_id(compute_node_id, spec.vps_id)
            if cn_id is not None:
                return "Compute node has been deleted successfully."
            else:
                return "Could not delete compute node."

    @log_entry_exit
    def delete_volumes_with_no_server_connection(self, compute_node_id, vps_id=None):

        vol_ids = self.get_compute_node_volume_ids(compute_node_id)
        vol_prov = SDSBVolumeProvisioner(self.connection_info)
        for vol_id in vol_ids:
            logger.writeDebug(
                "RC:delete_volumes_with_no_server_connection:vol_id={}", vol_id
            )
            # first detach the volume from the compute node
            self.detach_volume_from_compute_node(compute_node_id, vol_id, vps_id)

            # get the volume information
            vol = vol_prov.get_volume_by_id(vol_id)
            logger.writeDebug("RC:delete_volumes_with_no_server_connection:vol={}", vol)
            # if the volume is not attached to any compute node, delete the volume
            if vol.numberOfConnectingServers == 0:
                response = vol_prov.delete_volume(vol_id)
                logger.writeDebug(
                    "RC:delete_volumes_with_no_server_connection:response={}", response
                )
