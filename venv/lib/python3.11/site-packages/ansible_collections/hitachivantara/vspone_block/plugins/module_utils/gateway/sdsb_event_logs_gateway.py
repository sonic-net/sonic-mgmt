try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_utils import convert_keys_to_snake_case, replace_nulls

except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.sdsb_utils import convert_keys_to_snake_case, replace_nulls

GET_EVENT_LOGS = "v1/objects/event-logs"
GET_EVENT_LOGS_QUERY = "v1/objects/event-logs{}"

logger = Log()


class SDSBEventLogsDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_query_parameters(
        self,
        spec,
    ):
        params = {}
        if spec.start_time:
            params["startTime"] = spec.start_time
        if spec.end_time:
            params["endTime"] = spec.end_time
        if spec.severity:
            params["severity"] = spec.severity
        if spec.severity_ge:
            params["severityGe"] = spec.severity_ge
        if spec.max_events:
            params["maxEvents"] = spec.max_events

        query = ""
        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            query = "?" + "&".join(query_parts)

        return query

    @log_entry_exit
    def get_event_logs(self, spec=None):

        end_point = GET_EVENT_LOGS

        if spec is not None:
            query = self.get_query_parameters(spec)
            end_point = GET_EVENT_LOGS_QUERY.format(query)
            logger.writeDebug("GW:get_event_logs:end_point={}", end_point)

        event_logs = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_event_logs:data={}", event_logs)

        converted = convert_keys_to_snake_case(event_logs)
        cleaned_data = replace_nulls(converted)
        return cleaned_data
