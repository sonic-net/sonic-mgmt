import concurrent.futures

try:
    from ..common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..model.vsp_host_group_models import (
        VSPOneHostGroupInfo,
        VSPHostGroupInfo,
        VSPHostGroupsInfo,
        VSPLunResponse,
        VSPPortResponse,
        VSPWwnResponse,
        VSPLunResponses,
    )
    from ..common.hv_constants import VSPHostGroupConstant
    from ..message.vsp_host_group_msgs import VSPHostGroupMessage
except ImportError:
    from common.vsp_constants import Endpoints
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.ansible_common import dicts_to_dataclass_list
    from model.vsp_host_group_models import (
        VSPOneHostGroupInfo,
        VSPHostGroupInfo,
        VSPHostGroupsInfo,
        VSPLunResponse,
        VSPPortResponse,
        VSPWwnResponse,
        VSPLunResponses,
    )
    from common.hv_constants import VSPHostGroupConstant
    from message.vsp_host_group_msgs import VSPHostGroupMessage

logger = Log()

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
    25: "SUPPORT_SPC_3_PERSISTENT_RESERVATION",
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
    91: "DISABLE_IO_WAIT_FOR_OPEN_STACK",
    95: "CHANGE_SCSI_LU_RESET_NEXUS_VSP_HUS_VM",
    96: "CHANGE_SCSI_LU_RESET_NEXUS",
    97: "PROPRIETARY_ANCHOR_COMMAND_SUPPORT",
    100: "HITACHI_HBA_EMULATION_CONNECTION_OPTION",
    102: "GAD_STANDARD_INQUIRY_EXPANSION_HCS",
    105: "TASK_SET_FULL_RESPONSE_FOR_IO_OVERLOAD",
    110: "ODX_SUPPORT_WIN2012",
    113: "ISCSI_CHAP_AUTH_LOG",
    114: "AUTO_ASYNC_RECLAMATION_ESXI_6_5",
    122: "TASK_SET_FULL_RESPONSE_AFTER_QOS_UPPER_LIMIT",
    124: "GUARANTEED_RESPONSE_DURING_CONTROLLER_FAILURE",
    131: "WCE_BIT_OFF_MODE",
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


class VSPHostGroupDirectGateway:
    def __init__(self, connection_info):
        self.rest_api = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.end_points = Endpoints
        self.serial = None

    @log_entry_exit
    def set_serial(self, serial):
        self.serial = serial

    @log_entry_exit
    def get_ports(self):
        Log()
        end_point = self.end_points.GET_PORTS
        resp = self.rest_api.read(end_point)
        return dicts_to_dataclass_list(resp["data"], VSPPortResponse)

    @log_entry_exit
    def get_one_port(self, port_id):
        Log()
        end_point = self.end_points.GET_ONE_PORT.format(port_id)
        resp = self.rest_api.read(end_point)
        return VSPPortResponse(**resp)

    @log_entry_exit
    def check_valid_port(self, port_id):
        logger = Log()
        is_valid = True
        port = self.get_one_port(port_id)
        port_type = port.portType
        logger.writeDebug(f"20250324 port_type: {port_type}")
        if (
            port_type != VSPHostGroupConstant.PORT_TYPE_FIBRE
            and port_type != VSPHostGroupConstant.PORT_TYPE_ISCSI
            and port_type != VSPHostGroupConstant.PORT_TYPE_FCOE
            and port_type != VSPHostGroupConstant.PORT_TYPE_HNASS
            and port_type != VSPHostGroupConstant.PORT_TYPE_HNASU
        ):
            is_valid = False
        return is_valid

    @log_entry_exit
    def get_wwns(self, port_id, hg_number):
        end_point = "{}?portId={}&hostGroupNumber={}".format(
            self.end_points.GET_WWNS, port_id, hg_number
        )
        end_point = self.end_points.GET_WWNS.format(
            "?portId={}&hostGroupNumber={}".format(port_id, hg_number)
        )
        resp = self.rest_api.read(end_point)
        return dicts_to_dataclass_list(resp["data"], VSPWwnResponse)

    @log_entry_exit
    def get_luns(self, port_id, hg_number):
        end_point = self.end_points.GET_LUNS.format(
            "?portId={}&hostGroupNumber={}&lunOption=ALUA".format(port_id, hg_number)
        )
        resp = self.rest_api.read(end_point)
        return VSPLunResponses().dump_to_object(resp)

    @log_entry_exit
    def parse_host_group(self, hg, is_get_wwns, is_get_luns, is_ldev_detail):
        tmpHg = {}
        port_id = hg["portId"]
        hg_name = hg["hostGroupName"]
        tmpHg["hostGroupName"] = hg_name
        hg_number = hg["hostGroupNumber"]
        tmpHg["hostGroupId"] = hg["hostGroupId"]
        tmpHg["hostGroupNumber"] = hg_number
        for hm in gHostMode:
            if gHostMode[hm] == hg["hostMode"]:
                tmpHg["hostMode"] = hm
                break
        tmpHg["resourceGroupId"] = hg.get("resourceGroupId", "")
        tmpHg["port"] = hg["portId"]

        if is_get_wwns:
            wwns = self.get_wwns(port_id, hg_number)
            tmpHg["wwns"] = []
            for wwn in wwns:
                tmpHg["wwns"].append(
                    {"id": wwn.hostWwn.upper(), "nick_name": wwn.wwnNickname}
                )

        if is_ldev_detail:
            luns = self.get_luns(port_id, hg_number)
            tmpHg["lunPaths"] = []
            logger.writeDebug(f"Inside the luns {luns}")
            for lun in luns.data:
                tmpHg["lunPaths"].append({"lun": lun.lun, "ldevId": lun.ldevId})
            # logger.writeDebug(f"Inside the ldev_details {tmpHg["lunPaths"]}")
        elif is_get_luns:
            luns = self.get_luns(port_id, hg_number)
            tmpHg["lunPaths"] = []
            for lun in luns.data:
                new_lun = {
                    "lun": lun.lun,
                    "ldevId": lun.ldevId,
                    "isCommandDevice": lun.isCommandDevice,
                    "hostGroupNumber": lun.hostGroupNumber,
                    "portId": lun.portId,
                    "hostMode": lun.hostMode,
                    "lunId": lun.lunId,
                    "isAluaEnabled": lun.isAluaEnabled,
                    "asymmetricAccessState": lun.asymmetricAccessState,
                    "hostModeOptions": lun.hostModeOptions,
                    "luHostReserve": {
                        "openSystem": lun.luHostReserve.openSystem,
                        "persistent": lun.luHostReserve.persistent,
                        "pgrKey": lun.luHostReserve.pgrKey,
                        "mainframe": lun.luHostReserve.mainframe,
                        "acaReserve": lun.luHostReserve.acaReserve,
                    },
                }
                tmpHg["lunPaths"].append(new_lun)

        host_mode_options = hg.get("hostModeOptions", None)
        tmpHg["hostModeOptions"] = []
        if host_mode_options:
            for option in host_mode_options:

                option_txt = ""
                if option in g_raidHostModeOptions:
                    option_txt = g_raidHostModeOptions[option]

                tmpHg["hostModeOptions"].append(
                    {
                        "hostModeOption": option_txt,
                        "hostModeOptionNumber": option,
                    }
                )

        return tmpHg

    @log_entry_exit
    def get_all_hgs(self):
        logger = Log()

        end_points = self.end_points.POST_HOST_GROUPS
        retry = 0
        resp = None
        max_retry = 20
        while retry < max_retry:
            try:
                resp = self.rest_api.read(end_points)
                if resp:
                    return VSPHostGroupsInfo(
                        dicts_to_dataclass_list(resp["data"], VSPHostGroupInfo)
                    )
            except Exception as e:
                if retry == max_retry - 1:
                    logger.writeError(f"Failed to get all host groups: {e}")
            finally:
                retry += 1
        return

    @log_entry_exit
    def get_host_groups(
        self,
        ports_input,
        name_input,
        hg_number,
        is_get_wwns,
        is_get_luns,
        is_ldev_detail,
    ):
        logger = Log()
        lstHg = []
        port_set = None
        if ports_input:
            port_set = set(ports_input)
        logger.writeInfo("port_set={0}".format(port_set))
        ports = self.get_ports()
        for port in ports:
            port_id = port.portId
            if port_set and port_id not in port_set:
                continue

            port_type = port.portType
            logger.writeInfo("port_type = {}", port_type)
            if (
                port_type != VSPHostGroupConstant.PORT_TYPE_FIBRE
                and port_type != VSPHostGroupConstant.PORT_TYPE_FCOE
                and port_type != VSPHostGroupConstant.PORT_TYPE_HNASS
                and port_type != VSPHostGroupConstant.PORT_TYPE_HNASU
            ):
                continue

            end_point = self.end_points.GET_HOST_GROUPS.format(
                "?portId={}&detailInfoType=resourceGroup".format(port_id)
            )
            resp = self.rest_api.read(end_point)
            for hg in resp["data"]:
                if hg_number is not None and hg["hostGroupNumber"] != hg_number:
                    continue
                elif name_input and hg["hostGroupName"] != name_input:
                    continue

                tmpHg = self.parse_host_group(
                    hg, is_get_wwns, is_get_luns, is_ldev_detail
                )
                lstHg.append(tmpHg)

        return VSPHostGroupsInfo(dicts_to_dataclass_list(lstHg, VSPHostGroupInfo))

    @log_entry_exit
    def get_host_groups_from_meta_resource(self, port):
        logger = Log()
        freeHgNumlst = []

        end_point = self.end_points.GET_HOST_GROUPS.format(
            "?portId={}&isUndefined=true&detailInfoType=resourceGroup".format(port)
        )
        resp = self.rest_api.read(end_point)

        for hg in resp["data"]:
            if hg["resourceGroupId"] == 0 and hg["isDefined"] is False:
                freeHgNumlst.append(hg["hostGroupNumber"])
        logger.writeDebug("free Hostgroup list = {}", freeHgNumlst)
        return freeHgNumlst

    @log_entry_exit
    def get_host_groups_of_a_port(self, port_id):
        Log()
        lstHg = []
        end_point = self.end_points.GET_HOST_GROUPS.format(
            "?portId={}&detailInfoType=resourceGroup".format(port_id)
        )
        resp = self.rest_api.read(end_point)
        for hg in resp["data"]:
            tmpHg = self.parse_host_group(hg, None, None, None)
            lstHg.append(tmpHg)

            return VSPHostGroupsInfo(dicts_to_dataclass_list(lstHg, VSPHostGroupInfo))
        return None

    @log_entry_exit
    def get_specific_lun_details(self, port_id, hg_id, lun_id):
        end_point = self.end_points.GET_SPECIFIC_LUN.format(port_id, hg_id, lun_id)
        resp = self.rest_api.read(end_point)
        return VSPLunResponse(**resp)

    @log_entry_exit
    def get_hg_by_id(self, object_id):
        Log()
        end_point = self.end_points.GET_HOST_GROUP_BY_ID.format(object_id)
        resp = self.rest_api.read(end_point)
        return resp
        # retHg = self.parse_host_group(resp, True, True)
        # return VSPOneHostGroupInfo(VSPHostGroupInfo(**retHg))

    @log_entry_exit
    def get_one_host_group(self, port_id, name):
        if not self.check_valid_port(port_id):
            return VSPOneHostGroupInfo(**{"data": None})

        retHg = {}
        end_point = self.end_points.GET_HOST_GROUPS.format(
            "?portId={}&detailInfoType=resourceGroup&isSimpleMode=false".format(port_id)
        )
        resp = self.rest_api.read(end_point)

        logger = Log()
        for hg in resp["data"]:
            logger.writeDebug("20250324 hg = {}", hg)
            if name == hg["hostGroupName"]:
                retHg = self.parse_host_group(hg, True, True, False)
                return VSPOneHostGroupInfo(VSPHostGroupInfo(**retHg))

        return VSPOneHostGroupInfo(**{"data": None})

    @log_entry_exit
    def create_host_group(
        self, port, name, wwns, luns, host_mode, host_mode_options, hg_number=None
    ):

        errors, comments = [], []
        if not self.check_valid_port(port):
            raise Exception(VSPHostGroupMessage.PORT_TYPE_INVALID.value)

        logger = Log()
        hostGroupNumber = self.get_host_groups_from_meta_resource(port)
        logger.writeDebug("HostGroup List = {}", hostGroupNumber)
        if len(hostGroupNumber) == 0:
            raise Exception(VSPHostGroupMessage.HG_IN_META_NOT_AVAILABLE.value)

        end_point = self.end_points.POST_HOST_GROUPS
        data = {}
        data["hostGroupNumber"] = hostGroupNumber[0]
        data["portId"] = port
        data["hostGroupName"] = name
        if host_mode in gHostMode:
            data["hostMode"] = gHostMode[host_mode]
        if len(host_mode_options) > 0:
            data["hostModeOptions"] = host_mode_options
        if hg_number is not None:
            data["hostGroupNumber"] = hg_number
        logger.writeInfo(data)
        resp = self.rest_api.post(end_point, data)
        logger.writeInfo(resp)
        if resp is not None:
            number = 0
            split_arr = resp.split(",")
            if len(split_arr) > 1:
                port = split_arr[0]
                number = split_arr[1]
            end_point = self.end_points.GET_HOST_GROUP_ONE.format(port, number)
            read_resp = self.rest_api.read(end_point)
            logger.writeInfo(read_resp)
            ret_hg = self.parse_host_group(read_resp, False, False, False)
            hg_info = VSPHostGroupInfo(**ret_hg)
            if wwns:
                error, comment = self.add_wwns_to_host_group(hg_info, wwns)
                errors.extend(error)
                comments.extend(comment)
            if luns:
                error, comment = self.add_luns_to_host_group(hg_info, luns)
                errors.extend(error)
                comments.extend(comment)
        return errors, comments

    @log_entry_exit
    def add_wwns_to_host_group(self, hg, wwns):
        errors = []
        comments = []
        for host_wwn in wwns:
            end_point = self.end_points.POST_WWNS
            data = {}
            data["hostWwn"] = host_wwn.wwn
            data["portId"] = hg.port
            actual_hg_number = None
            if isinstance(hg.hostGroupNumber, int):
                actual_hg_number = hg.hostGroupNumber
            elif isinstance(hg.hostGroupNumber, str) and "," in hg.hostGroupNumber:
                actual_hg_number = hg.hostGroupNumber.split(",")[-1]
            else:
                raise ValueError(f"Invalid host group number {hg.hostGroupNumber}.")
            data["hostGroupNumber"] = actual_hg_number
            unused = self.rest_api.post(end_point, data)
            if host_wwn.nick_name:
                try:
                    self.set_nickname_of_wwn(hg, host_wwn)

                except Exception as e:
                    errors.append(
                        VSPHostGroupMessage.WWN_NICKNAME_SET_FAILED.value.format(
                            hg.hostGroupName, host_wwn.wwn, str(e)
                        )
                    )
                    pass
            comments.append(
                VSPHostGroupMessage.ADD_WWN_SUCCESS.value.format(
                    host_wwn.wwn, hg.hostGroupName
                )
            )
        return comments, errors

    @log_entry_exit
    def set_nickname_of_wwn(self, hg, wwn):
        logger = Log()
        end_point = self.end_points.PATCH_WWNS.format(
            hg.port, hg.hostGroupNumber, wwn.wwn
        )
        data = {}
        data["wwnNickname"] = wwn.nick_name if wwn.nick_name else ""
        resp = self.rest_api.patch(end_point, data)
        logger.writeInfo(resp)
        return resp

    @log_entry_exit
    def add_luns_to_host_group(self, hg, luns, lun_id=None):
        logger = Log()
        errors = []
        comments = []
        for lun in luns:
            end_point = self.end_points.POST_LUNS
            data = {}
            data["ldevId"] = lun
            data["portId"] = hg.port
            data["hostGroupNumber"] = hg.hostGroupNumber
            if lun_id is not None:
                data["lun"] = lun_id
            try:
                resp = self.rest_api.post(end_point, data)
                logger.writeInfo(resp)
                comments.append(
                    VSPHostGroupMessage.ADD_LUN_SUCCESS.value.format(
                        lun, hg.hostGroupName
                    )
                )
            except Exception as e:
                logger.writeError(
                    VSPHostGroupMessage.ADD_LUN_FAILED.value.format(
                        lun, hg.hostGroupName, str(e)
                    )
                )
                errors.append(
                    VSPHostGroupMessage.ADD_LUN_FAILED.value.format(
                        lun, hg.hostGroupName, str(e)
                    )
                )
                raise ValueError(errors)
        return comments, errors

    @log_entry_exit
    def delete_one_lun_from_host_group(self, host_group: VSPHostGroupInfo, lun_id):
        logger = Log()
        end_point = self.end_points.DELETE_LUNS.format(
            host_group.port, host_group.hostGroupNumber, lun_id
        )
        resp = self.rest_api.delete(end_point)
        logger.writeInfo(resp)

    @log_entry_exit
    def is_volume_not_associated_with_hgs(self, ldev_id):
        logger = Log()
        end_point = self.end_points.LDEVS_ONE.format(ldev_id)
        resp = self.rest_api.get(end_point)
        logger.writeInfo("resp = {}", resp)
        if "numOfPorts" not in resp or resp["numOfPorts"] == 0:
            return True
        return False

    @log_entry_exit
    def delete_one_volume(self, ldev_id):
        logger = Log()
        end_point = self.end_points.DELETE_LDEVS.format(ldev_id)
        resp = self.rest_api.delete(end_point)
        logger.writeInfo(resp)

    @log_entry_exit
    def unpresent_lun_from_hg_and_delete_lun(self, hg, lun):
        self.delete_one_lun_from_host_group(hg, lun.lun)
        if self.is_volume_not_associated_with_hgs(lun.ldevId):
            self.delete_one_volume(lun.ldevId)

    @log_entry_exit
    def delete_host_group(self, hg, is_delete_all_luns):
        logger = Log()
        if is_delete_all_luns:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                future_tasks = [
                    executor.submit(
                        self.unpresent_lun_from_hg_and_delete_lun, hg, logical_unit
                    )
                    for logical_unit in hg.lunPaths
                ]
            # Re-raise exceptions if they occurred in the threads
            for future in concurrent.futures.as_completed(future_tasks):
                future.result()

        end_point = self.end_points.DELETE_HOST_GROUPS.format(
            hg.port, hg.hostGroupNumber
        )
        resp = self.rest_api.delete(end_point)
        logger.writeInfo(resp)

    @log_entry_exit
    def delete_wwns_from_host_group(self, hg, wwns):
        logger = Log()
        errors = []
        comments = []
        for wwn in wwns:
            end_point = self.end_points.DELETE_WWNS.format(
                hg.port, hg.hostGroupNumber, wwn
            )
            try:
                resp = self.rest_api.delete(end_point)
                logger.writeInfo(resp)
                comments.append(
                    VSPHostGroupMessage.REMOVE_WWN_SUCCESS.value.format(
                        wwn, hg.hostGroupName
                    )
                )
            except Exception as e:
                logger.writeError(
                    VSPHostGroupMessage.REMOVE_WWN_FAILED.value.format(
                        wwn, hg.hostGroupName, str(e)
                    )
                )
                errors.append(
                    VSPHostGroupMessage.REMOVE_WWN_FAILED.value.format(
                        wwn, hg.hostGroupName, str(e)
                    )
                )
        return comments, errors

    @log_entry_exit
    def delete_luns_from_host_group(self, hg, luns):
        logger = Log()
        errors = []
        comments = []
        for lun in luns:
            try:
                for lunPath in hg.lunPaths:
                    if lun == lunPath.ldevId:
                        lunId = lunPath.lun
                        end_point = self.end_points.DELETE_LUNS.format(
                            hg.port, hg.hostGroupNumber, lunId
                        )
                        logger.writeInfo(f"{lunId}, {hg.port}, {hg.hostGroupNumber}")
                        resp = self.rest_api.delete(end_point)
                        logger.writeInfo(resp)
                        break
                comments.append(
                    VSPHostGroupMessage.REMOVE_LUN_SUCCESS.value.format(
                        lun, hg.hostGroupName
                    )
                )
            except Exception as e:
                logger.writeError(
                    VSPHostGroupMessage.REMOVE_LUN_FAILED.value.format(
                        lun, hg.hostGroupName, str(e)
                    )
                )
                errors.append(
                    VSPHostGroupMessage.REMOVE_LUN_FAILED.value.format(
                        lun, hg.hostGroupName, str(e)
                    )
                )
        return comments, errors

    @log_entry_exit
    def set_host_mode(self, hg, host_mode, host_mode_options):
        logger = Log()
        end_point = self.end_points.PATCH_HOST_GROUPS.format(
            hg.port, hg.hostGroupNumber
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
        resp = self.rest_api.patch(end_point, data)
        logger.writeInfo(resp)

    @log_entry_exit
    def set_prirotiy_level_of_alua_path(self, port_id, hg_number, access_state):
        logger = Log()
        end_point = self.end_points.SET_ALUA_PRIORITY
        access_state = (
            "Active/Optimized" if access_state == "high" else "Active/Non-Optimized"
        )
        data = {
            "parameters": {
                "portId": port_id,
                "hostGroupNumber": hg_number,
                "asymmetricAccessState": access_state,
            }
        }

        resp = self.rest_api.post(end_point, data)
        logger.writeInfo(resp)

    @log_entry_exit
    def release_host_reservation_status(self, port_id, hg_number, lun=None):
        end_point = self.end_points.RELEASE_HOST_RES_STATUS.format(port_id, hg_number)
        if lun is not None:
            end_point = self.end_points.RELEASE_HOST_RES_STATUS_LU.format(
                port_id, hg_number, lun
            )
        try:
            resp = self.rest_api.post(end_point, None)
            return resp
        except Exception as e:
            if "affectedResources" in str(e):
                pass
            else:
                raise e
