try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..common.hv_log import Log
    from ..model.vsp_volume_models import VSPVolumesInfo
    from ..model.vsp_external_volume_models import ExternalVolumeSpec
    from ..common.ansible_common import (
        log_entry_exit,
        volume_id_to_hex_format,
    )
    from ..message.vsp_external_volume_msgs import VSPSExternalVolumeValidateMsg

except ImportError:
    from message.vsp_external_volume_msgs import VSPSExternalVolumeValidateMsg
    from model.vsp_external_volume_models import ExternalVolumeSpec
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from provisioner.vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from common.hv_log import Log
    from model.vsp_volume_models import VSPVolumesInfo
    from common.ansible_common import (
        log_entry_exit,
        volume_id_to_hex_format,
    )

logger = Log()


class VSPExternalVolumeProvisioner:

    def __init__(self, connection_info, serial):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_EXT_VOLUME
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
    def get_one_external_path_group(self, ext_path_group_id, is_salamander=False):
        resp = self.gateway.get_one_external_path_group(
            ext_path_group_id, is_salamander
        )
        if resp is None:
            return
        return resp

    @log_entry_exit
    def get_all_external_parity_groups(self):
        return self.pg_gateway.get_all_external_parity_groups()

    @log_entry_exit
    def get_free_ldev_from_meta(self):
        items = self.vol_gateway.get_free_ldev_from_meta()
        for item in items.data:
            return item.ldevId

    @log_entry_exit
    def get_one_external_parity_group(self, external_parity_group):
        epg = self.pg_gateway.get_external_parity_group(external_parity_group)
        logger.writeDebug("20250528 epg={}", epg)
        return epg

    @log_entry_exit
    def get_next_external_parity_group(self):
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
    def select_external_path_groups(self, extvol):
        portId = extvol.portId
        externalWwn = extvol.externalWwn
        logger.writeDebug("20250228 portId={}", portId)
        logger.writeDebug("20250228 externalWwn={}", externalWwn)

        external_path_groups = self.gateway.get_external_path_groups()
        if external_path_groups is None:
            return

        result = []
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
                result.append(external_path_group)

        return result

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
    # find the external_parity_group in the external_path_group, then get the ldevids from it
    def get_ldev_ids_in_external_path_group(
        self, external_path_groups, externalLun, portId, externalWwn
    ):
        for external_path_group in external_path_groups:
            for epg in external_path_group.externalParityGroups:
                externalLuns = epg.get("externalLuns")
                if externalLuns is None:
                    continue
                for extlun in externalLuns:
                    if extlun is None:
                        continue
                    pid = extlun.get("portId")
                    wwn = extlun.get("externalWwn")
                    lun = extlun.get("externalLun")
                    if pid is None or pid != portId:
                        continue
                    if wwn is None or wwn != externalWwn:
                        continue
                    if lun is None or lun != externalLun:
                        continue
                    externalParityGroupId = epg.get("externalParityGroupId")
                    if externalParityGroupId is None:
                        continue
                    eprg = self.pg_gateway.get_external_parity_group(
                        externalParityGroupId
                    )
                    ldevIds = []
                    for space in eprg.spaces:
                        ldevId = space.ldevId
                        if ldevId is not None:
                            ldevIds.append(ldevId)
                    return ldevIds
        return []

    @log_entry_exit
    # find the external_parity_group in the external_path_group
    def get_external_parity_group(
        self, external_path_group, externalLun, portId, externalWwn
    ):
        for epg in external_path_group.externalParityGroups:
            externalLuns = epg.get("externalLuns")
            if externalLuns is None:
                continue
            for extlun in externalLuns:
                if extlun is None:
                    continue
                pid = extlun.get("portId")
                wwn = extlun.get("externalWwn")
                lun = extlun.get("externalLun")
                if pid is None or pid != portId:
                    continue
                if wwn is None or wwn != externalWwn:
                    continue
                if lun is None or lun != externalLun:
                    continue
                return epg

        return

    @log_entry_exit
    def get_all_external_volumes(self):
        allExtvols = []
        allExtvolsObj = []
        external_path_groups = self.gateway.get_external_path_groups()
        if external_path_groups is None:
            return None, None

        for external_path_group in external_path_groups.data:
            externalPaths = external_path_group.externalPaths
            logger.writeDebug("20250228 externalPaths={}", externalPaths)
            if externalPaths is None:
                continue
            for externalPath in externalPaths.data:
                extvols = self.gateway.get_external_volumes_with_extpath(
                    externalPath.portId, externalPath.externalWwn
                )
                # get the external volumes for the externalPath
                # ( filter by externalPath.portId, externalPath.externalWwn )
                for extvol in extvols.data:
                    externalVolumeInfo = extvol.externalVolumeInfo
                    extvol.externalLdevId = int(externalVolumeInfo[-4:], 16)
                    extvol.externalVolumeCapacityInMb = (
                        extvol.externalVolumeCapacity * 512
                    ) / (1024 * 1024)
                    extvol.externalProductId = external_path_group.externalProductId
                    extvol.externalSerialNumber = (
                        external_path_group.externalSerialNumber
                    )
                    extvol.externalPathGroupId = external_path_group.externalPathGroupId

                    # look for the external volume from the external_parity_group in the external_path_group
                    extvol.ldevIds = self.get_ldev_ids_in_external_path_group(
                        external_path_groups.data,
                        extvol.externalLun,
                        extvol.portId,
                        extvol.externalWwn,
                    )
                    logger.writeDebug("20250228 extvol.ldevIds={}", extvol.ldevIds)
                    logger.writeDebug(
                        "20250228 extvol.externalLdevId={}", extvol.externalLdevId
                    )

                    item = extvol.camel_to_snake_dict()
                    item["external_ldev_id_hex"] = volume_id_to_hex_format(
                        item.get("external_ldev_id")
                    )
                    allExtvols.append(item)
                    allExtvolsObj.append(extvol)

        # logger.writeDebug("20250228 extvols={}", allExtvols)
        return allExtvols, allExtvolsObj

    def get_one_external_volume(
        self, all_external_volumes, external_storage_serial, external_ldev_id
    ):

        if all_external_volumes is None:
            return None, None

        logger.writeDebug("20250228 ext_serial={}", external_storage_serial)
        logger.writeDebug("20250228 external_ldev_id={}", external_ldev_id)

        for extvol in all_external_volumes:
            if extvol.externalSerialNumber == external_storage_serial:
                if extvol.externalLdevId == external_ldev_id:
                    return extvol.camel_to_snake_dict(), extvol

        return None, None

    @log_entry_exit
    def external_volume_facts(self, spec):

        rsp, objs = self.get_all_external_volumes()
        if spec is None:
            return None if not rsp else rsp

        ext_serial = spec.external_storage_serial
        external_ldev_id = spec.external_ldev_id

        rsp_dict, notused = self.get_one_external_volume(
            objs,
            ext_serial,
            external_ldev_id,
        )
        logger.writeDebug("20250228 notused obj={}", notused)
        if rsp_dict is None:
            return None

        rsp_dict["external_ldev_id_hex"] = (
            volume_id_to_hex_format(rsp_dict.get("external_ldev_id"))
            if rsp_dict
            else ""
        )
        return rsp_dict

    @log_entry_exit
    def find_ext_volume_by_external_ldev_id(
        self, hex_ldev, externalPathsList, epg=None
    ):
        # for eplist in externalPathsList:
        for ep in externalPathsList.data:
            extvols = self.gateway.get_external_volumes_with_extpath(
                ep.portId, ep.externalWwn
            )
            for extvol in extvols.data:
                externalVolumeInfo = extvol.externalVolumeInfo
                ldev = externalVolumeInfo[-4:]
                logger.writeDebug("20250228 externalVolumeInfo={}", externalVolumeInfo)
                if hex_ldev != ldev:
                    continue
                extvol.externalLdevId = int(externalVolumeInfo[-4:], 16)
                extvol.externalVolumeCapacityInMb = (
                    extvol.externalVolumeCapacity * 512
                ) / (1024 * 1024)
                extvol.externalProductId = epg.externalProductId
                extvol.externalSerialNumber = epg.externalSerialNumber
                extvol.externalPathGroupId = epg.externalPathGroupId
                return extvol

    @log_entry_exit
    def get_extern_path_groups(self, ext_serial):
        resp = self.gateway.get_external_path_groups()
        if resp is None:
            return

        extern_path_groups = []
        for epg in resp.data:
            if epg.externalSerialNumber != ext_serial:
                continue
            extern_path_groups.append(epg)

        logger.writeDebug("20250228 extern_path_groups={}", extern_path_groups)
        return extern_path_groups

    @log_entry_exit
    def select_external_volume(self, ext_serial, ext_ldev_id):

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
        logger.writeDebug("20250228 ext_serial={}", ext_serial)
        externalPathGroups = self.get_extern_path_groups(ext_serial)
        if externalPathGroups is None:
            return None

        rsp = None
        for externalPathGroup in externalPathGroups:
            rsp = self.find_ext_volume_by_external_ldev_id(
                hex_ldev, externalPathGroup.externalPaths, externalPathGroup
            )
            if rsp is None:
                continue

        return rsp

    @log_entry_exit
    def delete_volume(self, connection_info, ldev):
        gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )

        gateway.delete_volume(ldev, False)
        return

    @log_entry_exit
    def create_external_volume_by_spec(self, spec: ExternalVolumeSpec):
        return self.create_external_volume(
            spec.ldev_id,
            spec.external_storage_serial,
            spec.external_ldev_id,
        )

    @log_entry_exit
    def delete_external_volume_by_spec(self, spec: ExternalVolumeSpec):
        external_storage_serial, external_ldev_id = (
            self.get_external_volume_info_by_ldev_id(spec.ldev_id)
        )
        return self.delete_external_volume(
            spec.ldev_id,
            str(external_storage_serial),
            external_ldev_id,
        )

    @log_entry_exit
    def get_external_volume_info_by_ldev_id(self, ldev_id):
        if ldev_id is None:
            return None, VSPSExternalVolumeValidateMsg.LDEV_REQUIRED.value

        vol = self.vol_gateway.get_volume_by_id_external_volume(ldev_id)
        external_vol_info = vol.externalVolumeIdString
        if external_vol_info is None:
            raise ValueError(
                VSPSExternalVolumeValidateMsg.EXTERNAL_VOLUME_NOT_FOUND.value.format(
                    ldev_id
                )
            )
        external_vol_info = external_vol_info.replace(".", "")
        external_vol_info = external_vol_info.split(" ")[1]
        external_ldev_id = int(external_vol_info[-4:], 16)
        serial = int(external_vol_info[2], 16) * 100000 + int(
            external_vol_info[4:8], 16
        )
        return serial, external_ldev_id

    @log_entry_exit
    def delete_external_volume(self, ldev_id, ext_serial, external_ldev_id):
        # the external volume to delete
        if ldev_id is None:
            return None, VSPSExternalVolumeValidateMsg.LDEV_REQUIRED.value

        rsp = self.gateway.get_external_volumes()
        if rsp is None:
            return None, VSPSExternalVolumeValidateMsg.NO_EXT_VOL.value
            # return None, "No External Storage Volumes in the system."
        # logger.writeDebug("20250228 rsp={}", rsp)

        for ext_vol in rsp.data:
            if ext_vol.ldevId is None:
                continue
            if ext_vol.externalParityGroupId is None:
                continue
            if ldev_id != ext_vol.ldevId:
                continue
            self.pg_gateway.delete_external_parity_group_force(
                ext_vol.externalParityGroupId
            )
            return [], None

        return [], VSPSExternalVolumeValidateMsg.NO_PARITYGRP.value

    @log_entry_exit
    def ldev_in_external_ports(self, external_ports, portId, externalWwn, lunId):
        logger.writeDebug("20250228 external_ports={}", external_ports)
        logger.writeDebug("20250228 lunId={}", lunId)
        logger.writeDebug("20250228 portId={}", portId)
        logger.writeDebug("20250228 externalWwn={}", externalWwn)

        if not external_ports:
            return False
        for ep in external_ports:
            logger.writeDebug("20250228 ep={}", ep)
            pid = ep.get("portId")
            wwn = ep.get("wwn")
            lun = ep.get("lun")
            if not pid or pid != portId:
                continue
            if not wwn or wwn != externalWwn:
                continue
            if lun is None or lun != lunId:
                continue
            return True

        return False

    @log_entry_exit
    def find_external_parity_group(
        self, external_path_groups, portId, externalWwn, lunId
    ):

        for external_path_group in external_path_groups:
            externalPathGroupId = external_path_group.externalPathGroupId
            epgs = external_path_group.externalParityGroups
            if epgs is None:
                continue
            for epg in epgs:
                logger.writeDebug("20250228 epg={}", epg)
                for externalLun in epg["externalLuns"]:
                    logger.writeDebug("20250228 externalLun={}", externalLun)
                    if portId != externalLun["portId"]:
                        continue
                    if externalWwn != externalLun["externalWwn"]:
                        continue
                    if (
                        externalLun.get("externalLun")
                        and lunId == externalLun["externalLun"]
                    ):
                        return (
                            external_path_group.externalPathGroupId,
                            epg["externalParityGroupId"],
                            epg,
                        )

        return externalPathGroupId, None, None

    @log_entry_exit
    def create_external_volume(self, ldev_id, ext_serial, external_ldev_id):

        # 20250303 creates an external volume from external parity group
        ldev = external_ldev_id

        # select ext-volume by ldev and serial
        rsp = self.select_external_volume(ext_serial, ldev)
        if rsp is None:
            return None, "Unable to find the external volume."

        externalVolumeCapacity = rsp.externalVolumeCapacity
        # you need these 3 params to find or create the external_parity_group
        portId = rsp.portId
        externalWwn = rsp.externalWwn
        lunId = rsp.externalLun

        if ldev_id:
            vol = self.vol_gateway.get_volume_by_id_external_volume(ldev_id)
            logger.writeDebug("20250228 vol={}", vol)
            if vol and vol.emulationType != "NOT DEFINED":
                external_ports = vol.externalPorts
                if external_ports:
                    if self.ldev_in_external_ports(
                        external_ports, portId, externalWwn, lunId
                    ):
                        # vol = vol.camel_to_snake_dict()
                        vol = VSPVolumesInfo(data=[vol])
                        return (
                            vol,
                            "ldev_id is already associated with the external volume.",
                        )
                    else:
                        # vol = vol.camel_to_snake_dict()
                        vol = VSPVolumesInfo(data=[vol])
                        return (
                            vol,
                            "ldev_id is already associated with another external volume.",
                        )
                else:
                    return None, "ldev_id is already provisioned with an internal ldev."

        rsp = self.select_external_path_groups(rsp)
        if rsp is None:
            return None, "Unable to find any external path group."

        # walk thru the external_path_groups
        # see if the external_parity_group is already created
        externalPathGroupId, externalParityGroupId, epg = (
            self.find_external_parity_group(rsp, portId, externalWwn, lunId)
        )
        logger.writeDebug("20250228 epg={}", epg)

        if externalParityGroupId is None:
            # we need to create the external_parity_group
            rsp = self.get_next_external_parity_group()
            logger.writeDebug("20250228 next_external_parity_group={}", rsp)
            externalParityGroupId = rsp

            logger.writeDebug("20250228 externalPathGroupId={}", externalPathGroupId)
            logger.writeDebug(
                "20250228 externalParityGroupId={}", externalParityGroupId
            )
            logger.writeDebug("20250228 lunId={}", lunId)
            logger.writeDebug("20250228 portId={}", portId)
            logger.writeDebug("20250228 externalWwn={}", externalWwn)
            rsp = self.pg_gateway.create_external_parity_group(
                externalPathGroupId,
                externalParityGroupId,
                portId,
                externalWwn,
                lunId,
            )

            # if it fails, check the lunId, which is the externalLun
            # loop thru the externalParityGroups in the externalPathGroups
            # get the externalParityGroupId which has this externalLun
            # and report it (or offer to delete it)
            # this can be a pre-check
            logger.writeDebug("20250228 rsp={}", rsp)

        # map ext volume: create volume by parity group
        if not ldev_id:
            ldev_id = self.get_free_ldev_from_meta()
        logger.writeDebug("20250228 ldev_id={}", ldev_id)
        logger.writeDebug("20250228 externalVolumeCapacity={}", externalVolumeCapacity)
        rsp = self.vol_gateway.map_ext_volume(
            ldev_id, externalParityGroupId, externalVolumeCapacity
        )

        if rsp:
            vol = self.vol_gateway.get_volume_by_id_external_volume(rsp)
            # return vol.camel_to_snake_dict(), None
            return VSPVolumesInfo(data=[vol]), None

        return None, "Failed to create external volume."
