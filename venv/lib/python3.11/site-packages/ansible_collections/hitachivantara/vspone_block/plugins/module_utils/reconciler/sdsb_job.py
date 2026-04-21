try:
    from ..provisioner.sdsb_job_provisioner import SDSBJobProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from ..message.sdsb_storage_node_msgs import SDSBStorageNodeValidationMsg
except ImportError:
    from provisioner.sdsb_job_provisioner import SDSBJobProvisioner
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from message.sdsb_storage_node_msgs import SDSBStorageNodeValidationMsg

logger = Log()


class SDSBJobReconciler:

    def __init__(self, connection_info, state=None):
        self.connection_info = connection_info
        self.provisioner = SDSBJobProvisioner(self.connection_info)
        self.state = state

    @log_entry_exit
    def get_jobs(self, spec=None):

        try:
            if spec is not None and spec.id:
                job = self.provisioner.get_job_by_id(spec.id)
                extracted_data = SDSBJobExtractor().extract([job.to_dict()])
                return extracted_data

            jobs = self.provisioner.get_jobs(spec)
            # logger.writeDebug("RC:get_jobs:jobs={}", jobs)
            extracted_data = SDSBJobExtractor().extract(jobs.data_to_list())
            return extracted_data

        except Exception as e:
            if "HTTP Error 400: Bad Request" in str(e):
                raise ValueError(SDSBStorageNodeValidationMsg.BAD_ENTRY.value)


class SDSBJobExtractor:
    def __init__(self):
        self.common_properties = {
            "jobId": str,
            "self": str,
            "userId": str,
            "status": str,
            "state": str,
            "createdTime": str,
            "updatedTime": str,
            "completedTime": str,
            "request": dict,
            "affectedResources": list,
            "error": dict,
        }
        self.parameter_mapping = {
            "memory": "memory_mb",
        }

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []
        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)

                if value is None:
                    # default_value = get_default_value(value_type)
                    # value = default_value
                    continue
                new_dict[key] = value
            new_items.append(new_dict)

        return new_items

    def process_dict(self, response_key):

        if response_key is None:
            return {}

        new_dict = {}
        for key in response_key.keys():
            value = response_key.get(key, None)
            key = camel_to_snake_case(key)

            if value is None:
                # default_value = get_default_value(value_type)
                # value = default_value
                continue
            new_dict[key] = value

        return new_dict

    def extract(self, responses):
        new_items = []

        for response in responses:
            new_dict = {}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # logger.writeDebug("RC:extract:value_type={}", value_type)
                if value_type == list[dict]:
                    response_key = self.process_list(response_key)
                if value_type == dict:
                    response_key = self.process_dict(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if cased_key in self.parameter_mapping.keys():
                    cased_key = self.parameter_mapping[cased_key]
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    pass
                    # DO NOT HANDLE MISSING KEYS
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items
