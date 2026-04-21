try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.sdsb_job_models import (
        SDSBJobInfo,
        SDSBJobInfoList,
    )
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.sdsb_job_models import (
        SDSBJobInfo,
        SDSBJobInfoList,
    )

GET_JOBS = "v1/objects/jobs"
GET_JOBS_WITH_QUERY = "v1/objects/jobs{}"
GET_JOB_BY_ID = "v1/objects/jobs/{}"

logger = Log()


class SDSBJobGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_jobs(self, count=None):
        end_point = GET_JOBS
        if count is not None:
            query = f"?count={count}"
            end_point = GET_JOBS_WITH_QUERY.format(query)

        data = self.connection_manager.get(end_point)

        return SDSBJobInfoList(dicts_to_dataclass_list(data["data"], SDSBJobInfo))

    @log_entry_exit
    def get_job_by_id(self, id):
        end_point = GET_JOB_BY_ID.format(id)
        job_data = self.connection_manager.get(end_point)
        return SDSBJobInfo(**job_data)
