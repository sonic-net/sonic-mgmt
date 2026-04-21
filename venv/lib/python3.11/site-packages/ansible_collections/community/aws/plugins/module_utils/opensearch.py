# -*- coding: utf-8 -*-

# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import datetime
import functools
import time
from copy import deepcopy

try:
    import botocore
except ImportError:
    pass  # caught by AnsibleAWSModule

from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict
from ansible.module_utils.six import string_types

from ansible_collections.amazon.aws.plugins.module_utils.botocore import is_boto3_error_code
from ansible_collections.amazon.aws.plugins.module_utils.tagging import ansible_dict_to_boto3_tag_list
from ansible_collections.amazon.aws.plugins.module_utils.tagging import boto3_tag_list_to_ansible_dict
from ansible_collections.amazon.aws.plugins.module_utils.tagging import compare_aws_tags


def get_domain_status(client, module, domain_name):
    """
    Get the status of an existing OpenSearch cluster.
    """
    try:
        response = client.describe_domain(DomainName=domain_name)
    except is_boto3_error_code("ResourceNotFoundException"):
        return None
    except (
        botocore.exceptions.BotoCoreError,
        botocore.exceptions.ClientError,
    ) as e:  # pylint: disable=duplicate-except
        module.fail_json_aws(e, msg=f"Couldn't get domain {domain_name}")
    return response["DomainStatus"]


def get_domain_config(client, module, domain_name):
    """
    Get the configuration of an existing OpenSearch cluster, convert the data
    such that it can be used as input parameter to client.update_domain().
    The status info is removed.
    The returned config includes the 'EngineVersion' property, it needs to be removed
    from the dict before invoking client.update_domain().

    Return (domain_config, domain_arn) or (None, None) if the domain does not exist.
    """
    try:
        response = client.describe_domain_config(DomainName=domain_name)
    except is_boto3_error_code("ResourceNotFoundException"):
        return (None, None)
    except (
        botocore.exceptions.BotoCoreError,
        botocore.exceptions.ClientError,
    ) as e:  # pylint: disable=duplicate-except
        module.fail_json_aws(e, msg=f"Couldn't get domain {domain_name}")
    domain_config = {}
    arn = None
    if response is not None:
        for k in response["DomainConfig"]:
            if "Options" in response["DomainConfig"][k]:
                domain_config[k] = response["DomainConfig"][k]["Options"]
        domain_config["DomainName"] = domain_name
        # If ES cluster is attached to the Internet, the "VPCOptions" property is not present.
        if "VPCOptions" in domain_config:
            # The "VPCOptions" returned by the describe_domain_config API has
            # additional attributes that would cause an error if sent in the HTTP POST body.
            dc = {}
            if "SubnetIds" in domain_config["VPCOptions"]:
                dc["SubnetIds"] = deepcopy(domain_config["VPCOptions"]["SubnetIds"])
            if "SecurityGroupIds" in domain_config["VPCOptions"]:
                dc["SecurityGroupIds"] = deepcopy(domain_config["VPCOptions"]["SecurityGroupIds"])
            domain_config["VPCOptions"] = dc
        # The "StartAt" property is converted to datetime, but when doing comparisons it should
        # be in the string format "YYYY-MM-DD".
        for s in domain_config["AutoTuneOptions"]["MaintenanceSchedules"]:
            if isinstance(s["StartAt"], datetime.datetime):
                s["StartAt"] = s["StartAt"].strftime("%Y-%m-%d")
        # Provisioning of "AdvancedOptions" is not supported by this module yet.
        domain_config.pop("AdvancedOptions", None)

        # Get the ARN of the OpenSearch cluster.
        domain = get_domain_status(client, module, domain_name)
        if domain is not None:
            arn = domain["ARN"]
    return (domain_config, arn)


def normalize_opensearch(client, module, domain):
    """
    Merge the input domain object with tags associated with the domain,
    convert the attributes from camel case to snake case, and return the object.
    """
    try:
        domain["Tags"] = boto3_tag_list_to_ansible_dict(client.list_tags(ARN=domain["ARN"], aws_retry=True)["TagList"])
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
        module.fail_json_aws(e, f"Couldn't get tags for domain {domain['domain_name']}")
    except KeyError:
        module.fail_json(msg=str(domain))

    return camel_dict_to_snake_dict(domain, ignore_list=["Tags"])


def wait_for_domain_status(client, module, domain_name, waiter_name):
    if not module.params["wait"]:
        return
    timeout = module.params["wait_timeout"]
    deadline = time.time() + timeout
    status_msg = ""
    while time.time() < deadline:
        status = get_domain_status(client, module, domain_name)
        if status is None:
            status_msg = "Not Found"
            if waiter_name == "domain_deleted":
                return
        else:
            status_msg = "Created: {0}. Processing: {1}. UpgradeProcessing: {2}".format(
                status["Created"],
                status["Processing"],
                status["UpgradeProcessing"],
            )
            if (
                waiter_name == "domain_available"
                and status["Created"]
                and not status["Processing"]
                and not status["UpgradeProcessing"]
            ):
                return
        time.sleep(15)
    # Timeout occured.
    module.fail_json(msg=f"Timeout waiting for wait state '{waiter_name}'. {status_msg}")


def parse_version(engine_version):
    """
    Parse the engine version, which should be Elasticsearch_X.Y or OpenSearch_X.Y
    Return dict { 'engine_type': engine_type, 'major': major, 'minor': minor }
    """
    version = engine_version.split("_")
    if len(version) != 2:
        return None
    semver = version[1].split(".")
    if len(semver) != 2:
        return None
    engine_type = version[0]
    if engine_type not in ["Elasticsearch", "OpenSearch"]:
        return None
    if not (semver[0].isdigit() and semver[1].isdigit()):
        return None
    major = int(semver[0])
    minor = int(semver[1])
    return {"engine_type": engine_type, "major": major, "minor": minor}


def compare_domain_versions(version1, version2):
    supported_engines = {
        "Elasticsearch": 1,
        "OpenSearch": 2,
    }
    if isinstance(version1, string_types):
        version1 = parse_version(version1)
    if isinstance(version2, string_types):
        version2 = parse_version(version2)
    if version1 is None and version2 is not None:
        return -1
    elif version1 is not None and version2 is None:
        return 1
    elif version1 is None and version2 is None:
        return 0
    e1 = supported_engines.get(version1.get("engine_type"))
    e2 = supported_engines.get(version2.get("engine_type"))
    if e1 < e2:
        return -1
    elif e1 > e2:
        return 1
    else:
        if version1.get("major") < version2.get("major"):
            return -1
        elif version1.get("major") > version2.get("major"):
            return 1
        else:
            if version1.get("minor") < version2.get("minor"):
                return -1
            elif version1.get("minor") > version2.get("minor"):
                return 1
            else:
                return 0


def get_target_increment_version(client, module, domain_name, target_version):
    """
    Returns the highest compatible version which is less than or equal to target_version.
    When upgrading a domain from version V1 to V2, it may not be possible to upgrade
    directly from V1 to V2. The domain may have to be upgraded through intermediate versions.
    Return None if there is no such version.
    For example, it's not possible to upgrade directly from Elasticsearch 5.5 to 7.10.
    """
    api_compatible_versions = None
    try:
        api_compatible_versions = client.get_compatible_versions(DomainName=domain_name)
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        module.fail_json_aws(
            e,
            msg=f"Couldn't get compatible versions for domain {domain_name}",
        )
    compat = api_compatible_versions.get("CompatibleVersions")
    if compat is None:
        module.fail_json("Unable to determine list of compatible versions", compatible_versions=api_compatible_versions)
    if len(compat) == 0:
        module.fail_json("Unable to determine list of compatible versions", compatible_versions=api_compatible_versions)
    if compat[0].get("TargetVersions") is None:
        module.fail_json("No compatible versions found", compatible_versions=api_compatible_versions)
    compatible_versions = []
    for v in compat[0].get("TargetVersions"):
        if target_version == v:
            # It's possible to upgrade directly to the target version.
            return target_version
        semver = parse_version(v)
        if semver is not None:
            compatible_versions.append(semver)
    # No direct upgrade is possible. Upgrade to the highest version available.
    compatible_versions = sorted(compatible_versions, key=functools.cmp_to_key(compare_domain_versions))
    # Return the highest compatible version which is lower than target_version
    for v in reversed(compatible_versions):
        if compare_domain_versions(v, target_version) <= 0:
            return v
    return None


def ensure_tags(client, module, resource_arn, existing_tags, tags, purge_tags):
    if tags is None:
        return False
    tags_to_add, tags_to_remove = compare_aws_tags(existing_tags, tags, purge_tags)
    changed = bool(tags_to_add or tags_to_remove)
    if tags_to_add:
        if module.check_mode:
            module.exit_json(changed=True, msg="Would have added tags to domain if not in check mode")
        try:
            client.add_tags(
                ARN=resource_arn,
                TagList=ansible_dict_to_boto3_tag_list(tags_to_add),
            )
        except (
            botocore.exceptions.ClientError,
            botocore.exceptions.BotoCoreError,
        ) as e:
            module.fail_json_aws(e, f"Couldn't add tags to domain {resource_arn}")
    if tags_to_remove:
        if module.check_mode:
            module.exit_json(changed=True, msg="Would have removed tags if not in check mode")
        try:
            client.remove_tags(ARN=resource_arn, TagKeys=tags_to_remove)
        except (
            botocore.exceptions.ClientError,
            botocore.exceptions.BotoCoreError,
        ) as e:
            module.fail_json_aws(e, f"Couldn't remove tags from domain {resource_arn}")
    return changed
