from .gateway_oo import (
    OOGateway
)
from ..common.hv_log import (
    Log
)
from ..common.ansible_common_constants import (
    MAPI_FULL_URL_TEMPLATE_HTTPS
)
from ..common.hv_utilities import (
    DictUtilities,
)
from .jobs import (
    JobsResource
)


class JobResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def create_job(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name
        )

        additional_params = self.param.json_spec.get("job_parameters", {})

        additional_params = DictUtilities.snake_to_camel(additional_params)

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)
        json_data["jobParams"] = additional_params
        json_data.pop("jobParameters", None)  # Ensure jobParameters is not included in the request
        json_data.pop("jobId", None)  # Ensure jobId is not included in the request

        url = f"{mapi_full_url}/mapi/v1/jobs/create"

        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_data
        )

    def cancel_job(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name
        )

        job_id = self.param.json_spec.get("job_id", 0)

        json_data = {
            "jobId": {
                "id": job_id,
            }
        }

        existing_job = None
        try:
            jobs_resource = JobsResource(self.param, self.token)
            existing_job = jobs_resource.query_status_by_id(job_id)
        except Exception as err:
            logger.writeDebug(f"Error querying job status: {err}")

        if existing_job is not None:
            existing_job_status = existing_job.get("status", None)
            if existing_job_status is not None:
                job_state = existing_job_status.get("job_state", "")
                if "CANCEL" in job_state:
                    logger.writeDebug("Job is already canceled.")
                    existing_job["changed"] = False
                    return existing_job

        logger.writeDebug("existing_job: {}".format(existing_job))

        logger.writeDebug("json_data for job cancel: {}".format(json_data))

        url = f"{mapi_full_url}/mapi/v1/jobs/cancel"

        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_data
        )
