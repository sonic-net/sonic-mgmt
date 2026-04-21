import concurrent.futures

try:
    from ..common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        dicts_to_dataclass_list,
    )
    from ..model.vsp_iscsi_target_models import (
        VSPIscsiTargetsInfo,
        VSPIscsiTargetInfo,
        VSPIqnInitiatorDirectGw,
        VSPChapUserDirectGw,
        VSPPortsInfo,
        VSPPortInfo,
        VSPOneIscsiTargetInfo,
        IscsiTargetPayLoad,
    )
    from ..model.vsp_host_group_models import VSPLunResponses
    from ..common.hv_constants import VSPIscsiTargetConstant
    from ..message.vsp_iscsi_target_msgs import VSPIscsiTargetMessage
except ImportError:
    from common.vsp_constants import Endpoints

    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import (
        dicts_to_dataclass_list,
    )
    from model.vsp_iscsi_target_models import (
        VSPIscsiTargetsInfo,
        VSPIscsiTargetInfo,
        VSPIqnInitiatorDirectGw,
        VSPChapUserDirectGw,
        VSPPortsInfo,
        VSPPortInfo,
        VSPOneIscsiTargetInfo,
        IscsiTargetPayLoad,
    )
    from model.vsp_host_group_models import VSPLunResponses
    from common.hv_constants import VSPIscsiTargetConstant
    from message.vsp_iscsi_target_msgs import VSPIscsiTargetMessage

g_raidHostModeOptions = {
    2: "VERITAS_DB_EDITION_ADV_CLUSTER",
    6: "TPRLO",
    7: "AUTO_LUN_RECOGNITION",
    12: "NO_DISPLAY_FOR_GHOST_LUN",
    13: "SIM_REPORT_AT_LINK_FAILURE",
    14: "HP_TRUCLUSTER_WITH_TRUECOPY",
    15: "HACMP",
    22: "VERITAS_CLUSTER_SERVER",
    23: "REC_COMMAND_SUPPORT",
    33: "SET_REPORT_DEVICE_ID_ENABLE",
    39: "CHANGE_NEXUS_SPECIFIED_IN_SCSI_TARGET_RESET",
    40: "VVOL_EXPANSION",
    41: "PRIORITIZED_DEVICE_RECOGNITION",
    42: "PREVENT_OHUB_PCI_RETRY",
    43: "QUEUE_FULL_RESPONSE",
    48: "HAM_SVOL_READ",
    49: "BB_CREDIT_SETUP_1",
    50: "BB_CREDIT_SETUP_2",
    51: "ROUND_TRIP_SETUP",
    52: "HAM_AND_CLUSTER_SW_FOR_SCSI_2",
    54: "EXTENDED_COPY",
    57: "HAM_RESPONSE_CHANGE",
    60: "LUN0_CHANGE_GUARD",
    61: "EXPANDED_PERSISTENT_RESERVE_KEY",
    63: "VSTORAGE_APIS_ON_T10_STANDARDS",
    65: "ROUND_TRIP_EXTENDED_SETUP",
    67: "CHANGE_OF_ED_TOV_VALUE",
    68: "PAGE_RECLAMATION_LINUX",
    69: "ONLINE_LUSE_EXPANSION",
    71: "CHANGE_UNIT_ATTENTION_FOR_BLOCKED_POOL_VOLS",
    72: "AIX_GPFS",
    73: "WS2012",
    78: "NON_PREFERRED_PATH",
    80: "MULTITEXT_OFF",
    81: "NOP_IN_SUPPRESS",
    82: "DISCOVERY_CHAP",
    83: "REPORT_ISCSI_FULL_PORTAL_LIST",
    88: "PORT_CONSOLIDATION",
    95: "CHANGE_SCSI_LU_RESET_NEXUS_VSP_HUS_VM",
    96: "CHANGE_SCSI_LU_RESET_NEXUS",
    97: "PROPRIETARY_ANCHOR_COMMAND_SUPPORT",
    100: "HITACHI_HBA_EMULATION_CONNECTION_OPTION",
    102: "GAD_STANDARD_INQUIRY_EXPANSION_HCS",
    105: "TASK_SET_FULL_RESPONSE_FOR_IO_OVERLOAD",
    110: "ODX_SUPPORT_WIN2012",
    113: "ISCSI_CHAP_AUTH_LOG",
    114: "AUTO_ASYNC_RECLAMATION_ESXI_6_5",
}

gHostMode = {
    "LINUX": "LINUX/IRIX",
    "VMWARE": "VMWARE",
    "HP": "HP-UX",
    "OPEN_VMS": "OVMS",
    "TRU64": "TRU64",
    "SOLARIS": "SOLARIS",
    "NETWARE": "NETWARE",
    "WINDOWS": "WIN",
    "AIX": "AIX",
    "VMWARE_EXTENSION": "VMWARE_EX",
    "WINDOWS_EXTENSION": "WIN_EX",
}


class VSPIscsiTargetDirectGateway:
    def __init__(self, connection_info):
        self.connectionManager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )

    def get_ports(self, serial=None):
        Log()
        end_point = Endpoints.GET_PORTS
        resp = self.connectionManager.get(end_point)
        return VSPPortsInfo(dicts_to_dataclass_list(resp["data"], VSPPortInfo))

    def get_one_port(self, port_id):
        Log()
        end_point = Endpoints.GET_ONE_PORT.format(port_id)
        resp = self.connectionManager.read(end_point)
        return VSPPortInfo(**resp)

    def check_valid_port(self, port_id):
        is_valid = True
        port = self.get_one_port(port_id)
        port_type = port.portType
        if port_type != VSPIscsiTargetConstant.PORT_TYPE_ISCSI:
            is_valid = False
        return is_valid

    def get_iqn_initiators(self, port_id, iscsi_target_number):
        end_point = "{}?portId={}&hostGroupNumber={}".format(
            Endpoints.GET_WWNS, port_id, iscsi_target_number
        )
        end_point = Endpoints.GET_HOST_ISCSISS.format(
            "?portId={}&hostGroupNumber={}".format(port_id, iscsi_target_number)
        )
        resp = self.connectionManager.get(end_point)
        return dicts_to_dataclass_list(resp["data"], VSPIqnInitiatorDirectGw)

    def get_luns(self, port_id, iscsi_target_number):
        end_point = Endpoints.GET_LUNS.format(
            "?portId={}&hostGroupNumber={}".format(port_id, iscsi_target_number)
        )
        resp = self.connectionManager.get(end_point)
        return VSPLunResponses().dump_to_object(resp)

    def get_chap_users(self, port_id, iscsi_target_number):
        end_point = Endpoints.GET_CHAP_USERS.format(
            "?portId={}&hostGroupNumber={}".format(port_id, iscsi_target_number)
        )
        resp = self.connectionManager.get(end_point)
        return dicts_to_dataclass_list(resp["data"], VSPChapUserDirectGw)

    def parse_iscsi_target(self, iscsi_target, is_get_details=True, lun_id=None):
        tmp_iscsi_target = {}
        port_id = iscsi_target["portId"]
        iscsi_target_name = iscsi_target["hostGroupName"]
        tmp_iscsi_target["iscsiName"] = iscsi_target_name
        iscsi_target_number = iscsi_target["hostGroupNumber"]
        tmp_iscsi_target["iscsiId"] = iscsi_target_number
        tmp_iscsi_target["resourceGroupId"] = iscsi_target.get("resourceGroupId", "")
        tmp_iscsi_target["portId"] = iscsi_target["portId"]
        tmp_iscsi_target["iqn"] = iscsi_target["iscsiName"]

        tmp_iscsi_target["iqnInitiators"] = []
        tmp_iscsi_target["logicalUnits"] = []
        tmp_iscsi_target["chapUsers"] = []
        if is_get_details:
            iqn_initiators = self.get_iqn_initiators(port_id, iscsi_target_number)
            for iqn_initiator in iqn_initiators:
                tmp_iscsi_target["iqnInitiators"].append(
                    {
                        "iqn": iqn_initiator.iscsiName,
                        "nick_name": iqn_initiator.iscsiNickname,
                    }
                )

            luns = self.get_luns(port_id, iscsi_target_number)
            if not lun_id:
                for lun in luns.data:
                    tmp_iscsi_target["logicalUnits"].append(
                        {"hostLun": lun.lun, "logicalUnitId": lun.ldevId}
                    )
            else:
                for lun in luns.data:
                    if lun_id > 0 and lun.lun != lun_id:
                        continue
                    new_lun = {
                        "hostLun": lun.lun,
                        "logicalUnitId": lun.ldevId,
                        "isCommandDevice": lun.isCommandDevice,
                        "hostGroupNumber": lun.hostGroupNumber,
                        "portId": lun.portId,
                        "hostMode": lun.hostMode,
                        "lunId": lun.lunId,
                        "luHostReserve": {
                            "openSystem": lun.luHostReserve.openSystem,
                            "persistent": lun.luHostReserve.persistent,
                            "pgrKey": lun.luHostReserve.pgrKey,
                            "mainframe": lun.luHostReserve.mainframe,
                            "acaReserve": lun.luHostReserve.acaReserve,
                        },
                    }
                    tmp_iscsi_target["logicalUnits"].append(new_lun)

            chap_users = self.get_chap_users(port_id, iscsi_target_number)
            for chap_user in chap_users:
                tmp_iscsi_target["chapUsers"].append(chap_user.chapUserName)

        host_mode_options = iscsi_target.get("hostModeOptions", None)
        tmp_iscsi_target["hostMode"] = {}
        for hm in gHostMode:
            if gHostMode[hm] == iscsi_target["hostMode"]:
                tmp_iscsi_target["hostMode"]["hostMode"] = hm
                break
        tmp_iscsi_target["hostMode"]["hostModeOptions"] = []
        if host_mode_options:
            for option in host_mode_options:

                option_txt = ""
                if option in g_raidHostModeOptions:
                    option_txt = g_raidHostModeOptions[option]

                tmp_iscsi_target["hostMode"]["hostModeOptions"].append(
                    {
                        "raidOption": option_txt,
                        "raidOptionNumber": option,
                    }
                )

        tmp_iscsi_target["authParam"] = {}
        tmp_iscsi_target["authParam"]["authenticationMode"] = iscsi_target[
            "authenticationMode"
        ]
        tmp_iscsi_target["authParam"]["isChapEnabled"] = False
        tmp_iscsi_target["authParam"]["isChapRequired"] = False
        tmp_iscsi_target["authParam"]["isMutualAuth"] = False
        if (
            iscsi_target["authenticationMode"] == VSPIscsiTargetConstant.AUTH_MODE_CHAP
            or iscsi_target["authenticationMode"]
            == VSPIscsiTargetConstant.AUTH_MODE_BOTH
        ):
            tmp_iscsi_target["authParam"]["isChapEnabled"] = True
        if iscsi_target["authenticationMode"] == VSPIscsiTargetConstant.AUTH_MODE_CHAP:
            tmp_iscsi_target["authParam"]["isChapRequired"] = True
        if (
            iscsi_target["iscsiTargetDirection"]
            == VSPIscsiTargetConstant.AUTH_DIRECTION_MUTUAL
        ):
            tmp_iscsi_target["authParam"]["isMutualAuth"] = True
        return tmp_iscsi_target

    def worker_get_iscsi_target(self, port_id, name_input):
        lst_iscsi_target = []
        end_point = Endpoints.GET_HOST_GROUPS.format(
            "?portId={}&detailInfoType=resourceGroup&isSimpleMode=false".format(port_id)
        )
        resp = self.connectionManager.get(end_point)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
            for iscsi_target in resp["data"]:
                if (
                    name_input is not None
                    and name_input != iscsi_target["hostGroupName"]
                ):
                    continue
                futures.append(
                    executor.submit(self.parse_iscsi_target, iscsi_target=iscsi_target)
                )
            for future in concurrent.futures.as_completed(futures):
                lst_iscsi_target.append(future.result())
        return lst_iscsi_target

    def get_iscsi_targets_bk(self, spec, serial=None):
        logger = Log()
        lst_iscsi_target = []
        ports_input = spec.ports
        name_input = None
        if hasattr(spec, "name"):
            name_input = spec.name
        port_set = None
        if ports_input:
            port_set = set(ports_input)
        logger.writeInfo("port_set={0}".format(port_set))
        ports = self.get_ports()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for port in ports.data:
                port_id = port.portId
                if port_set and port_id not in port_set:
                    continue

                port_type = port.portType
                logger.writeInfo("port_type = {}", port_type)
                if port_type != VSPIscsiTargetConstant.PORT_TYPE_ISCSI:
                    continue
                futures.append(
                    executor.submit(self.worker_get_iscsi_target, port_id, name_input)
                )
            for future in concurrent.futures.as_completed(futures):
                lst_iscsi_target = lst_iscsi_target + future.result()

        lst_iscsi_target = sorted(
            lst_iscsi_target, key=lambda x: (x["portId"], x["iscsiId"])
        )
        return VSPIscsiTargetsInfo(
            dicts_to_dataclass_list(lst_iscsi_target, VSPIscsiTargetInfo)
        )

    def get_iscsi_targets(self, spec, serial=None):
        logger = Log()
        lst_iscsi_target = []
        ports_input = spec.ports
        name_input = None
        iscsi_id = None
        if hasattr(spec, "iscsi_id"):
            iscsi_id = spec.iscsi_id
        if hasattr(spec, "name"):
            name_input = spec.name
        port_set = None
        if ports_input:
            port_set = set(ports_input)
        logger.writeInfo("port_set={0}".format(port_set))
        ports = self.get_ports()
        for port in ports.data:
            port_id = port.portId
            if port_set and port_id not in port_set:
                continue

            port_type = port.portType
            logger.writeInfo("port_type = {}", port_type)
            if port_type != VSPIscsiTargetConstant.PORT_TYPE_ISCSI:
                continue
            end_point = Endpoints.GET_HOST_GROUPS.format(
                "?portId={}&detailInfoType=resourceGroup&isSimpleMode=false".format(
                    port_id
                )
            )
            resp = self.connectionManager.get(end_point)
            for iscsi_target in resp["data"]:

                if iscsi_id is not None and iscsi_id != iscsi_target["hostGroupNumber"]:
                    continue
                elif (
                    name_input is not None
                    and iscsi_id is None
                    and name_input != iscsi_target["hostGroupName"]
                ):
                    continue

                is_get_details = False
                if (
                    port_set is not None
                    and name_input is not None
                    or iscsi_id is not None
                ):
                    is_get_details = True
                    spec.lun = float("-inf")

                tmp_iscsi_target = self.parse_iscsi_target(
                    iscsi_target, is_get_details, spec.lun
                )
                lst_iscsi_target.append(tmp_iscsi_target)

        return VSPIscsiTargetsInfo(
            dicts_to_dataclass_list(lst_iscsi_target, VSPIscsiTargetInfo)
        )

    def get_one_iscsi_target(self, port_id, name, serial=None, iscsi_id=None):
        if not self.check_valid_port(port_id):
            return VSPOneIscsiTargetInfo(**{"data": None})
        ret_iscsi_target = {}
        end_point = Endpoints.GET_HOST_GROUPS.format(
            "?portId={}&detailInfoType=resourceGroup".format(port_id)
        )
        resp = self.connectionManager.get(end_point)

        for iscsi_target in resp["data"]:
            if (
                name == iscsi_target["hostGroupName"]
                or iscsi_id == iscsi_target["hostGroupNumber"]
            ):
                ret_iscsi_target = self.parse_iscsi_target(
                    iscsi_target, lun_id=float("-inf")
                )
                return VSPOneIscsiTargetInfo(VSPIscsiTargetInfo(**ret_iscsi_target))
        return VSPOneIscsiTargetInfo(**{"data": None})

    def create_one_iscsi_target(
        self, iscsi_target_payload: IscsiTargetPayLoad, serial=None
    ):
        if not self.check_valid_port(iscsi_target_payload.port):
            raise Exception(VSPIscsiTargetMessage.PORT_TYPE_INVALID.value)
        logger = Log()
        end_point = Endpoints.POST_HOST_GROUPS
        data = {}
        data["portId"] = iscsi_target_payload.port
        data["hostGroupName"] = iscsi_target_payload.name
        if iscsi_target_payload.host_mode:
            host_mode = (
                gHostMode.get(iscsi_target_payload.host_mode)
                or iscsi_target_payload.host_mode
            )
            data["hostMode"] = host_mode
        if (
            iscsi_target_payload.host_mode_options
            and len(iscsi_target_payload.host_mode_options) > 0
        ):
            data["hostModeOptions"] = iscsi_target_payload.host_mode_options
        if iscsi_target_payload.iscsi_id is not None:
            data["hostGroupNumber"] = iscsi_target_payload.iscsi_id
        logger.writeInfo(data)
        resp = self.connectionManager.post(end_point, data)
        logger.writeInfo(resp)
        if resp is not None:
            number = None
            split_arr = resp.split(",")
            if len(split_arr) > 1:
                port = split_arr[0]
                number = split_arr[1]
            end_point = Endpoints.GET_HOST_GROUP_ONE.format(port, number)
            read_resp = self.connectionManager.get(end_point)
            logger.writeInfo(read_resp)
            ret_iscsi_target = self.parse_iscsi_target(
                read_resp, False, lun_id=float("-inf")
            )
            iscsi_target_info = VSPIscsiTargetInfo(**ret_iscsi_target)
            if iscsi_target_payload.luns is not None:
                self.add_luns_to_iscsi_target(
                    iscsi_target_info, iscsi_target_payload.luns
                )
            if iscsi_target_payload.iqn_initiators is not None:
                self.add_iqn_initiators_to_iscsi_target(
                    iscsi_target_info, iscsi_target_payload.iqn_initiators
                )
            if iscsi_target_payload.chap_users is not None:
                self.add_chap_users_to_iscsi_target(
                    iscsi_target_info, iscsi_target_payload.chap_users
                )

    def create_iscsi_targets(self, spec, serial=None):
        logger = Log()
        ports_input = spec.ports
        spec.name
        port_set = None
        if ports_input:
            port_set = set(ports_input)
        logger.writeInfo("port_set={0}".format(port_set))
        ports = self.get_ports()
        for port in ports.data:
            port_id = port.portId
            if port_set and port_id not in port_set:
                continue

            port_type = port.portType
            logger.writeInfo("port_type = {}", port_type)
            if port_type != VSPIscsiTargetConstant.PORT_TYPE_ISCSI:
                raise Exception("The port type is not valid for this operation.")
            self.create_one_iscsi_target(
                IscsiTargetPayLoad(
                    name=spec.name,
                    port=port_id,
                    host_mode=spec.host_mode,
                    host_mode_options=spec.host_mode_options,
                    luns=spec.ldevs,
                    iqn_initiators=spec.iqn_initiators,
                    chap_users=spec.chap_users,
                )
            )

    def add_luns_to_iscsi_target(
        self, iscsi_target: VSPIscsiTargetInfo, luns, serial=None, lun_id=None
    ):
        logger = Log()
        errors = []
        for lun in luns:
            end_point = Endpoints.POST_LUNS
            data = {}
            data["ldevId"] = lun
            data["portId"] = iscsi_target.portId
            data["hostGroupNumber"] = iscsi_target.iscsiId
            if lun_id is not None:
                data["lun"] = lun_id
            # resp = self.connectionManager.post(end_point, data)
            try:
                resp = self.connectionManager.post(end_point, data)
                logger.writeInfo(resp)
            except Exception as e:
                logger.writeError(
                    VSPIscsiTargetMessage.ADD_LUN_FAILED.value.format(lun, str(e))
                )
                errors.append(
                    VSPIscsiTargetMessage.ADD_LUN_FAILED.value.format(lun, str(e))
                )
                raise ValueError(errors)
            logger.writeInfo(resp)

    def add_iqn_initiators_to_iscsi_target(
        self, iscsi_target: VSPIscsiTargetInfo, iqn_initiators, serial=None
    ):
        logger = Log()
        for iqn_initiator in iqn_initiators:
            end_point = Endpoints.POST_HOST_ISCSIS
            data = {}
            data["iscsiName"] = iqn_initiator.iqn
            data["portId"] = iscsi_target.portId
            data["hostGroupNumber"] = iscsi_target.iscsiId
            resp = self.connectionManager.post(end_point, data)
            logger.writeInfo(resp)
            if iqn_initiator.nick_name is not None:
                try:
                    self.set_nickname_of_iqn(iscsi_target, iqn_initiator)
                except Exception as e:
                    logger.writeError(
                        "Failed to set nickname for IQN {}: {}".format(
                            iqn_initiator.iqn, str(e)
                        )
                    )
                    pass

    def set_nickname_of_iqn(self, iscsi_target, iqn):
        logger = Log()
        end_point = Endpoints.PATCH_IQN_NICK_NAME.format(
            iscsi_target.portId, iscsi_target.iscsiId, iqn.iqn
        )
        data = {}
        data["iscsiNickname"] = iqn.nick_name if iqn.nick_name is not None else ""
        resp = self.connectionManager.patch(end_point, data)
        logger.writeInfo(resp)
        return resp

    def add_chap_users_to_iscsi_target(
        self, iscsi_target: VSPIscsiTargetInfo, chap_users, serial=None
    ):
        logger = Log()
        for chap_user in chap_users:
            logger.writeInfo(chap_user)
            end_point = Endpoints.POST_CHAP_USERS
            data = {}
            data["chapUserName"] = chap_user.chap_user_name
            data["wayOfChapUser"] = VSPIscsiTargetConstant.WAY_OF_CHAP_USER
            data["portId"] = iscsi_target.portId
            data["hostGroupNumber"] = iscsi_target.iscsiId
            resp = self.connectionManager.post(end_point, data)
            logger.writeInfo(resp)
            if chap_user.chap_secret is not None:
                end_point = Endpoints.PATCH_CHAP_USERS.format(resp)
                data = {}
                data["chapPassword"] = chap_user.chap_secret
                resp = self.connectionManager.patch(end_point, data)
                logger.writeInfo(resp)

    def set_host_mode(
        self,
        iscsi_target: VSPIscsiTargetInfo,
        host_mode,
        host_mode_options,
        serial=None,
    ):
        logger = Log()
        end_point = Endpoints.PATCH_HOST_GROUPS.format(
            iscsi_target.portId, iscsi_target.iscsiId
        )
        data = {}
        if host_mode and host_mode in gHostMode:
            data["hostMode"] = gHostMode[host_mode]
        else:
            data["hostMode"] = host_mode

        if host_mode_options is not None:
            if len(host_mode_options) > 0:
                data["hostModeOptions"] = host_mode_options
            else:
                data["hostModeOptions"] = [-1]
        resp = self.connectionManager.patch(end_point, data)
        logger.writeInfo(resp)

    def delete_iqn_initiators_from_iscsi_target(
        self, iscsi_target: VSPIscsiTargetInfo, iqn_initiators, serial=None
    ):
        logger = Log()
        for iqn_initiator in iqn_initiators:
            end_point = Endpoints.DELETE_HOST_ISCSIS.format(
                iscsi_target.portId, iscsi_target.iscsiId, iqn_initiator
            )
            resp = self.connectionManager.delete(end_point)
            logger.writeInfo(resp)

    def delete_luns_from_iscsi_target(
        self, iscsi_target: VSPIscsiTargetInfo, luns, serial=None
    ):
        logger = Log()
        for lun in luns:
            logger.writeDebug("lun = {}", lun)
            for logical_unit in iscsi_target.logicalUnits:
                logger.writeDebug(
                    "logical_unit.logicalUnitId = {}",
                    logical_unit.logicalUnitId,
                )
                if lun == logical_unit.logicalUnitId:
                    lun_id = logical_unit.hostLun
                    end_point = Endpoints.DELETE_LUNS.format(
                        iscsi_target.portId, iscsi_target.iscsiId, lun_id
                    )
                    logger.writeDebug("end_point = {}", end_point)
                    resp = self.connectionManager.delete(end_point)
                    logger.writeInfo(resp)

    def delete_chap_users_from_iscsi_target(
        self, iscsi_target: VSPIscsiTargetInfo, chap_users, serial=None
    ):
        logger = Log()
        for chap_user in chap_users:
            end_point = Endpoints.DELETE_CHAP_USERS.format(
                iscsi_target.portId,
                iscsi_target.iscsiId,
                VSPIscsiTargetConstant.WAY_OF_CHAP_USER,
                chap_user,
            )
            resp = self.connectionManager.delete(end_point)
            logger.writeInfo(resp)

    def delete_one_lun_from_iscsi_target(
        self, iscsi_target: VSPIscsiTargetInfo, lun_id
    ):
        logger = Log()
        end_point = Endpoints.DELETE_LUNS.format(
            iscsi_target.portId, iscsi_target.iscsiId, lun_id
        )
        resp = self.connectionManager.delete(end_point)
        logger.writeInfo(resp)

    def is_volume_empty(self, ldev_id):
        logger = Log()
        end_point = Endpoints.LDEVS_ONE.format(ldev_id)
        resp = self.connectionManager.get(end_point)
        logger.writeInfo("resp = {}", resp)
        if "numOfPorts" not in resp or resp["numOfPorts"] == 0:
            return True
        return False

    def delete_one_volume(self, ldev_id):
        logger = Log()
        end_point = Endpoints.DELETE_LDEVS.format(ldev_id)
        resp = self.connectionManager.delete(end_point)
        logger.writeInfo(resp)

    def delete_iscsi_target(
        self, iscsi_target: VSPIscsiTargetInfo, is_delete_all_luns, serial=None
    ):
        logger = Log()
        if is_delete_all_luns:
            for logical_unit in iscsi_target.logicalUnits:
                self.delete_one_lun_from_iscsi_target(
                    iscsi_target, logical_unit.hostLun
                )
                if self.is_volume_empty(logical_unit.logicalUnitId):
                    self.delete_one_volume(logical_unit.logicalUnitId)

        end_point = Endpoints.DELETE_HOST_GROUPS.format(
            iscsi_target.portId, iscsi_target.iscsiId
        )
        resp = self.connectionManager.delete(end_point)
        logger.writeInfo(resp)

    def release_host_reservation_status(self, port_id, iscsi_id, lun=None):
        end_point = Endpoints.RELEASE_HOST_RES_STATUS.format(port_id, iscsi_id)
        if lun is not None:
            end_point = Endpoints.RELEASE_HOST_RES_STATUS_LU.format(
                port_id, iscsi_id, lun
            )
        try:
            resp = self.connectionManager.post(end_point, None)
            return resp
        except Exception as e:
            if "affectedResources" in str(e):
                pass
            else:
                raise e
