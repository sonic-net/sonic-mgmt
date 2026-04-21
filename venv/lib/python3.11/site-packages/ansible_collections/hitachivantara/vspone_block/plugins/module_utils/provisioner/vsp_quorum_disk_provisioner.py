try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..common.hv_log import Log
    from ..model.vsp_volume_models import CreateVolumeSpec
    from ..model.vsp_quorum_disk_models import QuorumDiskSpec
    from ..common.ansible_common import (
        log_entry_exit,
        volume_id_to_hex_format,
    )

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from common.hv_log import Log
    from model.vsp_volume_models import CreateVolumeSpec
    from model.vsp_quorum_disk_models import QuorumDiskSpec
    from common.ansible_common import (
        log_entry_exit,
        volume_id_to_hex_format,
    )

logger = Log()


class VSPQuorumDiskProvisioner:

    def __init__(self, connection_info, serial):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_QUORUM_DISK
        )
        self.pg_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_PARITY_GROUP
        )
        self.vol_gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )

        self.storage_prov = VSPStorageSystemProvisioner(connection_info)
        self.connection_info = connection_info
        self.connection_type = connection_info.connection_type
        self.serial = serial

        if self.serial is None:
            self.serial = self.get_storage_serial_number()
        self.gateway.set_storage_serial_number(serial)

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def get_external_path_groups(self):
        resp = self.gateway.get_external_path_groups()
        return resp

    @log_entry_exit
    def delete_quorum_disk(self, id):
        item = self.gateway.get_quorum_disk_by_id(id)
        if item is None:
            return [], "id is not found, may have been deregistered."
        resp = self.gateway.delete_quorum_disk(id)
        self.connection_info.changed = True
        logger.writeDebug(resp)
        return [], None

    @log_entry_exit
    def quorum_disk_facts(self, spec):
        if spec and spec.id is not None:
            items = self.gateway.get_quorum_disk_by_id(spec.id)
            logger.writeDebug(f"PV:20250303 get_quorum_disk_by_id =  {items}")
            if items:
                return self.inject_ldev_hex(items.camel_to_snake_dict())
        else:
            items = self.gateway.get_all_quorum_disks().data_to_snake_case_list()
        return None if not items else self.inject_ldev_list_hex(items)

    @log_entry_exit
    def inject_ldev_hex(self, qd_dict):
        ldev_id = qd_dict.get("ldev_id", None)
        if ldev_id:
            qd_dict["ldev_id_hex"] = volume_id_to_hex_format(ldev_id)
        else:
            qd_dict["duplication_ldev_id_hex"] = ""
        return qd_dict

    @log_entry_exit
    def inject_ldev_list_hex(self, qd_list):
        ldev_list = []
        for qd in qd_list:
            ldev_list.append(self.inject_ldev_hex(qd))
        return ldev_list

    @log_entry_exit
    def get_free_ldev_from_meta(self):
        items = self.vol_gateway.get_free_ldev_from_meta()
        for item in items.data:
            return item.ldevId

    @log_entry_exit
    def get_next_quorum_disk(self):
        epgs = self.gateway.get_all_quorum_disks()
        pgids = []
        for epg in epgs.data:
            pgids.append(epg.quorumDiskId)

        id = 0
        while id in pgids:
            id += 1

        return id

    @log_entry_exit
    def get_next_external_parity_group(self, get_external_path_group):
        epgs = self.pg_gateway.get_all_external_parity_groups()
        pgids = []
        for epg in epgs.data:
            pgids.append(epg.externalParityGroupId)

        ii = 1
        pgid = "1-" + str(ii)
        while pgid in pgids:
            ii += 1
            pgid = "1-" + str(ii)

        return pgid

    @log_entry_exit
    def get_external_volumes(self):
        resp = self.gateway.get_external_volumes()
        return resp

    @log_entry_exit
    def select_external_path_group(self, extvol):
        portId = extvol.portId
        externalWwn = extvol.externalWwn
        logger.writeDebug("20250228 portId={}", portId)
        logger.writeDebug("20250228 externalWwn={}", externalWwn)

        external_path_groups = self.gateway.get_external_path_groups()
        if external_path_groups is None:
            return

        for external_path_group in external_path_groups.data:
            externalPaths = external_path_group.externalPaths
            logger.writeDebug("20250228 externalPaths={}", externalPaths)
            if externalPaths is None:
                continue
            for externalPath in externalPaths.data:
                if portId != externalPath.portId:
                    continue
                if externalWwn != externalPath.externalWwn:
                    continue
                return external_path_group

    @log_entry_exit
    def select_external_volume(self, ext_serial, ext_ldev_id):

        if ext_serial is None:
            # we are not supporting this yet,
            # just a place holder for now
            ext_serial = "410109"

        # get the hex format of the volume
        # 1345 -> 0541
        hex_ldev = format(ext_ldev_id, "04x")
        hex_ldev = hex_ldev.upper()
        # get the storage serial encoding
        # 410109 -> 40277D
        model = ext_serial[0]
        serial = ext_serial[-5:]
        hex_serial = format(int(serial), "04x")
        hex_serial = hex_serial.upper()
        hex_serial = model + "0" + hex_serial
        logger.writeDebug("20250228 hex_ldev={}", hex_ldev)
        logger.writeDebug("20250228 hex_serial={}", hex_serial)

        extvols = self.get_external_volumes()
        for extvol in extvols.data:
            externalVolumeInfo = extvol.externalVolumeInfo
            ldev = externalVolumeInfo[-4:]
            serialInfo = externalVolumeInfo[-10:-4]
            logger.writeDebug("20250228 externalVolumeInfo={}", externalVolumeInfo)
            if hex_ldev != ldev:
                continue
            # assume the same external ldev will not appear in two external storages
            # if hex_serial != serialInfo :
            #     continue
            return extvol

    # def undo(self):
    #     # unpresent lun from the two hgs
    #     rsp = gateway.delete_volume(1345, False)

    @log_entry_exit
    def create_volume_ext(self, ext_connection_info, parity_group, size):
        gateway = GatewayFactory.get_gateway(
            ext_connection_info, GatewayClassTypes.VSP_VOLUME
        )

        vol_spec = CreateVolumeSpec()
        vol_spec.parity_group = parity_group
        vol_spec.size = size

        ldev = gateway.create_volume(vol_spec)
        return ldev

    @log_entry_exit
    def delete_volume(self, connection_info, ldev):
        gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )

        gateway.delete_volume(ldev, False)
        return

    @log_entry_exit
    def format_volume(self, connection_info, ldev):
        gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )

        gateway.format_volume(ldev_id=ldev, force_format=False)
        return

    @log_entry_exit
    def present_ldev(self, connection_info, ldev_id, hgport, hgname):

        # VSPHostGroupDirectGateway
        gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_HOST_GROUP
        )

        # host_group = VSPHostGroupInfo()
        # host_group.port = hgport
        # host_group.hostGroupId = hgname

        hg = gateway.get_one_host_group(hgport, hgname)
        gateway.add_luns_to_host_group(hg.data, [ldev_id])
        return hg

    @log_entry_exit
    def unpresent_ldev(self, connection_info, ldev_id, hgport, hgname):

        # VSPHostGroupDirectGateway
        gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_HOST_GROUP
        )

        # host_group = VSPHostGroupInfo()
        # host_group.port = hgport
        # host_group.hostGroupId = hgname

        hg = gateway.get_one_host_group(hgport, hgname)
        gateway.delete_one_lun_from_host_group(hg.data, ldev_id)
        return ldev_id

    @log_entry_exit
    def register_quorum_disk(self, spec: QuorumDiskSpec):

        quorum_disk_id = None
        if spec.id is not None:
            quorum_disk_id = spec.id

            if quorum_disk_id < 0 or quorum_disk_id > 31:
                # Failed to register quorum disk,
                # invalid quorum_disk_id (ran out of quorum disks)
                return None, "The quorum disk id must be a value from 0 to 31"

            rsp = self.gateway.get_quorum_disk_by_id(quorum_disk_id)
            if rsp:
                return (
                    self.inject_ldev_hex(rsp.camel_to_snake_dict()),
                    "The Quorum disk {0} is already registered.".format(quorum_disk_id),
                )
        elif spec.ldev_id is not None:
            # auto select with ldev_id
            # see if ldev_id is already registered
            rsp = self.gateway.get_quorum_disk_by_ldev_id(spec.ldev_id)
            if rsp:
                return (
                    self.inject_ldev_hex(rsp.camel_to_snake_dict()),
                    "The Quorum disk with ldev_id {0} is already registered.".format(
                        spec.ldev_id
                    ),
                )

        # allow ldev-less QRD
        # if spec.ldev_id is None:
        #     return None, "The local volume ldev_id must be specified."

        if spec.remote_storage_serial_number is None:
            return None, "The remote_storage_serial_number must be specified."

        if spec.remote_storage_type is None:
            return None, "The remote_storage_type must be specified."

        # register the remote storage system
        rsp = self.create_quorum_disk(
            spec.ldev_id,
            spec.remote_storage_serial_number,
            spec.remote_storage_type,
            quorum_disk_id,
        )

        if rsp is None:
            return None, "Failed to register Quorum Disk."

        self.connection_info.changed = True
        return rsp, None

    @log_entry_exit
    def create_quorum_disk(
        self,
        ldev_id,
        remote_storage_serial_number,
        remote_storage_type,
        quorum_disk_id,
    ):

        if quorum_disk_id is None:
            quorum_disk_id = self.get_next_quorum_disk()

        logger.writeDebug(f"PV:20250303 quorum_disk_id =  {quorum_disk_id}")
        logger.writeDebug(
            f"PV:20250303 remote_storage_serial_number =  {remote_storage_serial_number}"
        )
        logger.writeDebug(f"PV:20250303 remote_storage_type =  {remote_storage_type}")
        logger.writeDebug(f"PV:20250303 ldev_id =  {ldev_id}")

        # register quorum_disks
        # ldev_id can be None for ldev-less QRD
        rsp = self.gateway.create_quorum_disk(
            quorum_disk_id,
            remote_storage_serial_number,
            remote_storage_type,
            ldev_id,
        )

        rsp = self.gateway.get_quorum_disk_by_id(quorum_disk_id)
        if rsp:
            rsp = self.inject_ldev_hex(rsp.camel_to_snake_dict())
            return rsp
