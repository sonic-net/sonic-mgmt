import re

try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.sdsb_journal_model import SDSBJournalList, SDSBJournalResponse
    from ..message.sdsb_journal_msgs import SDSBJournalValidationMsg


except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from message.sdsb_journal_msgs import SDSBJournalValidationMsg


logger = Log()


class SDSBBlockJournalDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_journals(self, spec=None):
        """
        Fetch journals from API.
        Validates spec fields if provided.
        """
        # Build endpoint and query params
        end_point = SDSBlockEndpoints.GET_JOURNAL
        params = {}

        if spec:
            if spec.vps_id:
                params["vpsId"] = spec.vps_id
            if spec.number:
                params["journalNumber"] = spec.number
            if spec.storage_controller_id:
                params["storageControllerId"] = spec.storage_controller_id

        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            end_point = end_point + "?" + "&".join(query_parts)

        logger.writeDebug("GW:get_journals:end_point={}", end_point)
        journals = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_journals:data={}", journals)

        # Convert and load data
        journal_list_obj = SDSBJournalList().dump_to_object(journals)
        # If no spec provided → return all journals
        if not spec:
            # return journal_list_obj.data_to_snake_case_list()
            return journal_list_obj

        # If vps_name provided → filter
        if spec.vps_name is not None:
            filtered = self.apply_vsp_name_filter(
                journal_list_obj.data_to_snake_case_list(), spec.vps_name
            )
            return filtered

        # return journal_list_obj.data_to_snake_case_list()
        return journal_list_obj

    def apply_vsp_name_filter(self, journals, vps_name):
        """
        Filter journal list  by vsp_name
        """
        if not journals:
            return []

        normalized_target = vps_name.lower().strip("() ")
        filtered = [
            j
            for j in journals
            if j.get("vps_name", "").lower().strip("() ") == normalized_target
        ]
        return filtered

    @log_entry_exit
    def create_journal(self, spec=None):

        logger.writeDebug("GW:create_journal:spec={}", spec)
        end_point = SDSBlockEndpoints.GET_JOURNAL
        # payload = {}
        if spec.data_overflow_watch_in_sec is None:
            spec.data_overflow_watch_in_sec = 60
        if spec.enable_inflow_control is None:
            spec.enable_inflow_control = False
        if spec.enable_cache_mode is None:
            spec.enable_cache_mode = False

        # Build payload
        payload = {
            "journalNumber": spec.number,
            "volumeIds": spec.volume_ids,
            "dataOverflowWatchInSeconds": spec.data_overflow_watch_in_sec,
            "isInflowControlEnabled": spec.enable_inflow_control,
            "isCacheModeEnabled": spec.enable_cache_mode,
        }

        if spec.vps_id:
            payload["vpsId"] = spec.vps_id
        logger.writeDebug("GW:create_journals:end_point={}", end_point)
        journals = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:get_journals:data={}", journals)
        return journals

    @log_entry_exit
    def get_journal_by_number(self, number):
        end_point = SDSBlockEndpoints.GET_JOURNAL
        params = {}
        if number and number is not None:
            params["journalNumber"] = number

        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            end_point = end_point + "?" + "&".join(query_parts)

        logger.writeDebug("GW:get_journals:end_point={}", end_point)
        journals = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_journals:data={}", journals)
        response = SDSBJournalList(
            dicts_to_dataclass_list(journals["data"], SDSBJournalResponse)
        )
        return response

    @log_entry_exit
    def get_journal_by_id(self, id):
        end_point = SDSBlockEndpoints.GET_JOURNAL_BY_ID.format(id)
        logger.writeDebug(f"GW:get_journal_by_id:end_point={end_point}")
        journals = self.connection_manager.get(end_point)
        logger.writeDebug(f"GW:get_journal_by_id:response={journals}")
        return SDSBJournalResponse(**journals)

    @log_entry_exit
    def delete_journal(self, journal_id):
        end_point = SDSBlockEndpoints.GET_JOURNAL_BY_ID.format(journal_id)
        journals = self.connection_manager.delete(end_point)
        return journals

    @log_entry_exit
    def update_journal(self, journal_id, spec=None):
        if spec is None:
            raise ValueError("Spec must be provided for updating a journal.")

        end_point = SDSBlockEndpoints.GET_JOURNAL_BY_ID.format(journal_id)
        payload = {}
        if spec.data_overflow_watch_in_sec is not None:
            if not (0 <= spec.data_overflow_watch_in_sec <= 600):
                raise ValueError(
                    SDSBJournalValidationMsg.DATA_OVERFLOW_OUT_OF_RANGE.value
                )
            payload["dataOverflowWatchInSeconds"] = spec.data_overflow_watch_in_sec

        if spec.enable_inflow_control is not None:
            payload["isInflowControlEnabled"] = spec.enable_inflow_control

        if spec.enable_cache_mode is not None:
            payload["isCacheModeEnabled"] = spec.enable_cache_mode

        # vpsId
        if spec.vps_id:
            vps_id = spec.vps_id
            if not re.match(
                r"^(system|[A-Fa-f0-9]{8}(-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12})$", vps_id
            ):
                raise ValueError(SDSBJournalValidationMsg.VPS_ID_INVALID.value)
            payload["vpsId"] = vps_id

        # mirrorUnit
        mirror_unit = spec.mirror_unit or {}
        if mirror_unit:
            if "number" in mirror_unit and mirror_unit["number"] is not None:
                if not (0 <= mirror_unit["number"] <= 3):
                    raise ValueError("mirrorUnit.muNumber must be between 0 and 3")
                mirror_unit_payload = {"muNumber": mirror_unit["number"]}
            else:
                mirror_unit_payload = {}

            if "copy_pace" in mirror_unit and mirror_unit["copy_pace"] is not None:
                if mirror_unit["copy_pace"] not in {"L", "M", "H"}:
                    raise ValueError("copyPace must be one of 'L', 'M', 'H'")
                mirror_unit_payload["copyPace"] = mirror_unit["copy_pace"]

            if (
                "data_transfer_speed_bps" in mirror_unit
                and mirror_unit["data_transfer_speed_bps"] is not None
            ):
                if mirror_unit["data_transfer_speed_bps"] not in {
                    "3M",
                    "10M",
                    "100M",
                    "256M",
                }:
                    raise ValueError(
                        "copySpeed must be one of '3M', '10M', '100M', '256M'"
                    )
                mirror_unit_payload["copySpeed"] = mirror_unit[
                    "data_transfer_speed_bps"
                ]

            if mirror_unit_payload:
                payload["mirrorUnit"] = mirror_unit_payload

        # Logging & API call
        logger.writeDebug(f"GW:update_journal:end_point={end_point}")
        logger.writeDebug(f"GW:update_journal:payload={payload}")

        response = self.connection_manager.patch(end_point, payload)
        logger.writeDebug(f"GW:update_journal:response={response}")

    @log_entry_exit
    def shrink_journal_by_id(self, journal_id, spec):
        endpoint = SDSBlockEndpoints.SHRINK_JOURNAL.format(journal_id)
        if len(spec.volume_ids) != 1:
            raise ValueError(SDSBJournalValidationMsg.ONLY_ONE_VOLUME_ID.value)
        payload = {"volumeIds": spec.volume_ids}
        # Include optional VPS parameters if present
        if getattr(spec, "vps_id", None):
            payload["vpsId"] = spec.vps_id
        shrink_journal = self.connection_manager.post(endpoint, payload)
        return shrink_journal

    @log_entry_exit
    def expand_journal_by_id(self, journal_id, spec):
        endpoint = SDSBlockEndpoints.EXPAND_JOURNAL.format(journal_id)
        if len(spec.volume_ids) != 1:
            raise ValueError(SDSBJournalValidationMsg.ONLY_ONE_VOLUME_ID.value)
        payload = {"volumeIds": spec.volume_ids}
        # Include optional VPS parameters if present
        if getattr(spec, "vps_id", None):
            payload["vpsId"] = spec.vps_id
        expand_journal = self.connection_manager.post(endpoint, payload)
        return expand_journal
