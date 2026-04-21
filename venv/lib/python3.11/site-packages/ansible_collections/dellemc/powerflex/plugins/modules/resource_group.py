#!/usr/bin/python

# Copyright: (c) 2024, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing resource group deployments on Dell Technologies (Dell) PowerFlex"""
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: resource_group
version_added: '2.3.0'
short_description: Manage resource group deployments on Dell PowerFlex.
description:
- Managing resource group deployments on PowerFlex storage system includes deploying,
  editing, adding nodes and deleting a resource group deployment.
author:
- Jennifer John (@johnj9) <ansible.team@dell.com>
- Trisha Datta (@trisha-dell) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  resource_group_name:
    description:
    - The name of the resource group.
    - This is a required field to deploy a resource group.
    - Either I(resource_group_id) or I(resource_group_name) must be specified to perform resource group operations.
    - Mutually exclusive with I(resource_group_id).
    type: str
  resource_group_id:
    description:
    - The ID of the resource group.
    - Either I(resource_group_id) or I(resource_group_name) must be specified to perform resource group operations.
    - Mutually exclusive with I(resource_group_name).
    type: str
  template_name:
    description:
    - The name of the published template.
    - Either I(template_id) or I(template_name) must be specified to deploy a resource group.
    - Mutually exclusive with I(template_id).
    type: str
  template_id:
    description:
    - The ID of the published template.
    - Either I(template_id) or I(template_name) must be specified to deploy a resource group.
    - Mutually exclusive with I(template_name).
    type: str
  firmware_repository_id:
    description:
    - The ID of the firmware repository if not using the appliance default catalog.
    - Mutually exclusive with I(firmware_repository_name).
    type: str
  firmware_repository_name:
    description:
    - The name of the firmware repository if not using the appliance default catalog.
    - Mutually exclusive with I(firmware_repository_id).
    type: str
  new_resource_group_name:
    description:
    - New name of the resource group to rename to.
    type: str
  description:
    description:
    - The description of the resource group.
    type: str
  scaleup:
    description:
    - Whether to scale up the resource group. Specify as true to add nodes to the resource group.
    type: bool
    default: false
  clone_node:
    description:
    - Resource to duplicate during scaleup, if more than one nodes are available in the resource group.
    type: str
  node_count:
    description:
    - Number of nodes to clone during scaleup.
    type: int
    default: 1
  validate:
    description:
    - Specify as true to validate the deployment of resource group.
    type: bool
    default: false
  schedule_date:
    description:
    - Scheduled date for the resource group deployment.
    - Specify in YYYY-MM-DD HH:MM:SS.sss or YYYY-MM-DD format.
    type: str
  state:
    description:
    - The state of the resource group.
    type: str
    choices: ['absent', 'present']
    default: 'present'
notes:
- The I(check_mode) is supported.
- Resource group scale up can be done only when deployment is complete.
'''

EXAMPLES = r'''
- name: Validate deployment of a resource group
  dellemc.powerflex.resource_group:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    port: "{{ port }}"
    resource_group_name: "{{ resource_group_name_1 }}"
    description: ans_rg
    template_id: c65d0172-8666-48ab-935e-9a0bf69ed66d
    firmware_repository_id: 8aaa80788b5755d1018b576126d51ba3
    validate: true

- name: Deploy a resource group
  dellemc.powerflex.resource_group:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    port: "{{ port }}"
    resource_group_name: "{{ resource_group_name_1 }}"
    description: ans_rg
    template_id: c65d0172-8666-48ab-935e-9a0bf69ed66d
    firmware_repository_id: 8aaa80788b5755d1018b576126d51ba3

- name: Add a node to a resource group
  dellemc.powerflex.resource_group:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    resource_group_name: "{{ resource_group_name_1 }}"
    scaleup: true
    clone_node: "{{ node_1 }}"
    node_count: "{{ node_count }}"

- name: Modify a resource group
  dellemc.powerflex.resource_group:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    resource_group_name: "{{ resource_group_name_1 }}"
    new_resource_group_name: "{{ new_resource_group_name }}"
    description: "description new"

- name: Delete a resource group
  dellemc.powerflex.resource_group:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    validate_certs: "{{ validate_certs }}"
    port: "{{ port }}"
    resource_group_name: ans_rg
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
resource_group_details:
    description: Details of the resource group deployment.
    returned: When resource group exists.
    type: dict
    contains:
        id:
            description: The ID of the deployed resource group.
            type: str
        deploymentName:
            description: The name of the resource group deployment.
            type: str
        deploymentDescription:
            description: The description of the resource group deployment.
            type: str
        serviceTemplate:
            description: The service template of the resource group.
            type: dict
            contains:
                id:
                    description: The ID of the service template.
                    type: str
                templateName:
                    description: The name of the service template.
                    type: str
        status:
            description: The status of the deployment of the resource group.
            type: str
        firmwareRepositoryId:
            description: The ID of the firmware repository of the resource group.
            type: str
    sample: {
        "id": "8aaa03a88de961fa018de96a88d80008",
        "deploymentName": "dep-ans-test-rg1",
        "deploymentDescription": "ans test rg",
        "retry": true,
        "teardown": false,
        "serviceTemplate": {
            "id": "8aaa03a88de961fa018de96a88d80008",
            "templateName": "update-template (8aaa03a88de961fa018de96a88d80008)"
        },
        "scheduleDate": null,
        "status": "error",
        "compliant": true,
        "deploymentDevice": [
            {
                "refId": "scaleio-block-legacy-gateway",
                "refType": "SCALEIO",
                "deviceHealth": "GREEN",
                "compliantState": "COMPLIANT",
                "deviceType": "scaleio",
                "currentIpAddress": "1.3.9.2",
                "componentId": "910bf934-d45a-4fe3-8ea2-dc481e063a81",
                "statusMessage": "The processing of PowerFlex is unsuccessful.",
                "model": "PowerFlex Gateway",
                "brownfield": false
            }
          ],
          "updateServerFirmware": true,
          "useDefaultCatalog": true,
          "firmwareRepository": {
              "id": "8aaa80788b5755d1018b576126d51ba3",
              "name": "PowerFlex 4.5.0.0",
              "rcmapproved": false
          },
          "firmwareRepositoryId": "8aaa80788b5755d1018b576126d51ba3",
          "deploymentHealthStatusType": "red",
          "allUsersAllowed": false,
          "owner": "admin",
          "numberOfDeployments": 0,
          "lifecycleMode": false,
          "vds": false,
          "scaleUp": false,
          "brownfield": false,
          "templateValid": true,
          "configurationChange": false
      }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils
import json
import copy

LOG = utils.get_logger('resource_group')


class PowerFlexResourceGroup:
    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_resource_group_parameters())
        mut_ex_args = [['resource_group_name', 'resource_group_id'],
                       ['template_name', 'template_id'],
                       ['firmware_repository_id', 'firmware_repository_name']]

        required_one_of_args = [['resource_group_name', 'resource_group_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            mutually_exclusive=mut_ex_args,
            required_one_of=required_one_of_args,
            supports_check_mode=True)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_service_template(self, template_id=None, template_name=None, for_deployment=True):
        """
        Retrieves a service template based on the provided parameters.

        Args:
            template_id (str, optional): The ID of the service template. Defaults to None.
            template_name (str, optional): The name of the service template. Defaults to None.
            for_deployment (bool, optional): Indicates whether the template is for deployment. Defaults to True.

        Returns:
            ServiceTemplate: The retrieved service template.

        Raises:
            AnsibleFailJson: If either `template_id` or `template_name` is not specified for resource group deployment.
            AnsibleFailJson: If the service template with the specified `template_name` is not found.
            AnsibleFailJson: If the service template with the specified `template_id` is not found.
        """
        if not (template_id or template_name):
            self.module.fail_json(msg="Either template_id or template_name must be specified for resource group deployment")
        if template_name:
            filter_query = utils.get_filter(template_name)
            template = self.powerflex_conn.service_template.get(filters=[filter_query])
            if not template:
                error_msg = f"Service template {template_name} is not found"
                self.module.fail_json(msg=error_msg)

        template_id = template_id or template[0]['id']
        return self.powerflex_conn.service_template.get_by_id(template_id, for_deployment)

    def get_firmware_repo(self, firmware_repo_id=None, firmware_repo_name=None):
        """
        Retrieves the firmware repository ID based on the provided firmware repository name or ID.

        Args:
            firmware_repo_id (str, optional): The ID of the firmware repository. Defaults to None.
            firmware_repo_name (str, optional): The name of the firmware repository. Defaults to None.

        Returns:
            str: The ID of the firmware repository.

        Raises:
            ValueError: If the firmware repository is not found.
        """
        firmware_repos = self.powerflex_conn.firmware_repository.get()
        if firmware_repo_id:
            firmware_repo = next((repo for repo in firmware_repos if repo.get('id') == firmware_repo_id), None)
        else:
            firmware_repo = next((repo for repo in firmware_repos if repo.get('name') == firmware_repo_name), None)
        if not firmware_repo:
            self.module.fail_json(msg=f"Firmware repository {firmware_repo_id or firmware_repo_name} is not found")
        return firmware_repo['id']

    def get_resource_group_name(self):
        """ Retrieves the name of the resource group. """
        resource_group_name = self.module.params['resource_group_name']
        if not resource_group_name:
            self.module.fail_json(msg="Specify resource_group_name for resource group deployment.")
        return resource_group_name

    def is_modify_needed(self, deployment_data):

        modify_dict = False
        if self.module.params["new_resource_group_name"] is not None and \
                deployment_data["deploymentName"] != self.module.params["new_resource_group_name"]:
            modify_dict = True
        if self.module.params["description"] is not None and \
                deployment_data["deploymentDescription"] != self.module.params["description"]:
            modify_dict = True
        if self.module.params["scaleup"]:
            modify_dict = True

        return modify_dict

    def clone_component(self, deploy_data):
        new_component = None
        count_server = 0
        server_name = []
        for component in range(len(deploy_data["serviceTemplate"]["components"])):
            if deploy_data["serviceTemplate"]["components"][component]["type"] == "SERVER":
                count_server = count_server + 1
                server_name.append(deploy_data["serviceTemplate"]["components"][component]["name"])
        for component in range(len(deploy_data["serviceTemplate"]["components"])):
            if self.module.params["clone_node"] is None:
                if count_server == 1 and deploy_data["serviceTemplate"]["components"][component]["name"] == server_name[0]:
                    new_component = deploy_data["serviceTemplate"]["components"][component]
                elif count_server != 1:
                    self.module.fail_json(msg="More than 1 server components exist. Provide the clone_node.")
            else:
                if deploy_data["serviceTemplate"]["components"][component]["name"] == self.module.params["clone_node"]:
                    new_component = deploy_data["serviceTemplate"]["components"][component]

        return new_component

    def prepare_add_node_payload(self, deploy_data):

        new_component = self.clone_component(deploy_data=deploy_data)
        if new_component is not None:
            uuid = utils.random_uuid_generation()
            new_component.update({
                "identifier": None,
                "asmGUID": None,
                "puppetCertName": None,
                "osPuppetCertName": None,
                "managementIpAddress": None,
                "brownfield": False,
                "id": uuid,
                "name": uuid})
            resource_params = ["razor_image", "scaleio_enabled", "scaleio_role",
                               "compression_enabled", "replication_enabled"]

            for resource in range(len(new_component["resources"])):
                if new_component["resources"][resource]["id"] == "asm::server":
                    for param in range(len(new_component["resources"][resource]["parameters"])):
                        if new_component["resources"][resource]["parameters"][param]["id"] \
                                not in resource_params:
                            new_component["resources"][resource]["parameters"][param]["guid"] = None
                            new_component["resources"][resource]["parameters"][param]["value"] = None
        return new_component

    def modify_resource_group_details(self, deployment_data):
        new_deployment_data = copy.deepcopy(deployment_data)

        # edit resource group

        if self.module.params["new_resource_group_name"]:
            new_deployment_data["deploymentName"] = self.module.params["new_resource_group_name"]
        if self.module.params["description"]:
            new_deployment_data["deploymentDescription"] = self.module.params["description"]

        # Add nodes

        if self.module.params["scaleup"]:
            new_deployment_data["scaleup"] = True
            new_deployment_data["retry"] = True
            node = 0
            while node < self.module.params["node_count"]:
                new_deployment_data1 = copy.deepcopy(deployment_data)
                new_component = self.prepare_add_node_payload(deploy_data=new_deployment_data1)
                if new_component:
                    new_deployment_data["serviceTemplate"]["components"].append(new_component)
                node = node + 1

        try:
            if not self.module.check_mode:
                self.powerflex_conn.deployment.edit(deployment_id=deployment_data["id"],
                                                    rg_data=new_deployment_data)

        except Exception as e:
            errmsg = f'Modifying a resource group deployment failed with error {utils.get_display_message(str(e))}'
            self.module.fail_json(msg=errmsg)

    def get_deployment_data(self):
        """
        Retrieves deployment data based on the provided parameters.

        :return: A JSON string representing the deployment data.
        """
        template_id = self.module.params['template_id']
        template_name = self.module.params['template_name']
        resource_group_name = self.get_resource_group_name()
        description = self.module.params['description']
        firmware_repo_id = self.module.params['firmware_repository_id']
        firmware_repo_name = self.module.params['firmware_repository_name']
        schedule_date = self.module.params['schedule_date']
        service_template = self.get_service_template(template_id, template_name, for_deployment=True)
        deployment_data = {
            "deploymentName": resource_group_name,
            "deploymentDescription": description,
            "serviceTemplate": service_template,
            "updateServerFirmware": True,
            "useDefaultCatalog": True
        }

        if firmware_repo_id or firmware_repo_name:
            firmware_repository_id = self.get_firmware_repo(firmware_repo_id, firmware_repo_name)
            deployment_data["firmwareRepositoryId"] = firmware_repository_id
            deployment_data["useDefaultCatalog"] = False
        if schedule_date:
            if not utils.validate_date(schedule_date):
                self.module.fail_json(msg="Invalid schedule_date format. Specify the date in the format 'YYYY-MM-DDTHH:MM:SS.sss'")
            deployment_data["scheduleDate"] = schedule_date

        return json.dumps(deployment_data)

    def get_deployment_details(self, deployment_name=None, deployment_id=None):
        """
        Retrieves deployment details based on the provided deployment name or deployment ID.

        Args:
            deployment_name (str, optional): The name of the deployment. Defaults to None.
            deployment_id (str, optional): The ID of the deployment. Defaults to None.

        Returns:
            list: A list of deployment details if the deployment name is provided and a matching deployment is found.
            None: if the deployment ID is provided and no deployment is found with that ID.
        """
        try:
            if deployment_name:
                filter_query = utils.get_filter(deployment_name)
                resp = self.powerflex_conn.deployment.get(filters=[filter_query])
                if len(resp) > 0:
                    deployment_id = resp[0]["id"]
                else:
                    return None
            return self.powerflex_conn.deployment.get_by_id(deployment_id)

        except Exception as e:
            if hasattr(e, 'status') and str(e.status) == '404':
                return None
            else:
                self.module.fail_json(msg=utils.get_display_message(str(e)))

    def get_operation_mapping(self):
        """
        Get the operation mapping based on the deployment details and module parameters.

        :return: The operation mapping for the given state, validate, and check_mode.
        """
        if not self.deployment_details:
            operation_mapping = {
                ('present', True, True): ValidateDeploy,
                ('present', True, False): ValidateDeploy,
                ('present', False, True): ValidateDeploy,
                ('present', False, False): Deploy
            }
        else:
            operation_mapping = {
                ('absent', True, True): DeleteDeploy,
                ('absent', True, False): DeleteDeploy,
                ('absent', False, True): DeleteDeploy,
                ('absent', False, False): DeleteDeploy,
                ('present', True, True): ModifyResourceGroup,
                ('present', True, False): ModifyResourceGroup,
                ('present', False, True): ModifyResourceGroup,
                ('present', False, False): ModifyResourceGroup
            }

        state = self.module.params['state']
        validate = self.module.params['validate']
        check_mode = self.module.check_mode

        return operation_mapping.get((state, validate, check_mode))

    def perform_module_operation(self):
        """
        Perform the module operation.

        :return: A dictionary containing the result of the module operation.
        """
        result = dict(
            changed=False,
            resource_group_details=[]
        )

        self.deployment_details = self.get_deployment_details(
            deployment_name=self.module.params['resource_group_name'],
            deployment_id=self.module.params['resource_group_id'])
        resource_group_operation = self.get_operation_mapping()
        if resource_group_operation:
            changed, resource_group_details = resource_group_operation.execute(self)
            result['resource_group_details'] = resource_group_details
            result['changed'] = changed

        self.module.exit_json(**result)


class Deploy:
    def execute(self):
        try:
            rg_data = self.get_deployment_data()
            response = self.powerflex_conn.deployment.create(rg_data)
            return True, response
        except Exception as e:
            errmsg = f'Deploying a resource group failed with error {utils.get_display_message(str(e))}'
            self.module.fail_json(msg=errmsg)


class ValidateDeploy:
    def execute(self):
        try:
            rg_data = self.get_deployment_data()
            response = self.powerflex_conn.deployment.validate(rg_data)
            return False, response
        except Exception as e:
            errmsg = f'Validating a resource group deployment failed with error {utils.get_display_message(str(e))}'
            self.module.fail_json(msg=errmsg)


class ModifyResourceGroup:
    def execute(self):
        try:
            changed = False
            rg_data = self.deployment_details
            if self.is_modify_needed(deployment_data=rg_data):
                self.modify_resource_group_details(deployment_data=rg_data)
                changed = True

            response = self.get_deployment_details(deployment_id=rg_data['id'])
            return changed, response
        except Exception as e:
            errmsg = f'Editing a resource group failed with error {utils.get_display_message(str(e))}'
            self.module.fail_json(msg=errmsg)


class DeleteDeploy:
    def execute(self):
        try:
            changed = False
            if self.deployment_details:
                if not self.module.check_mode:
                    self.powerflex_conn.deployment.delete(self.deployment_details['id'])
                    self.deployment_details = \
                        self.get_deployment_details(deployment_name=self.deployment_details['deploymentName'])
                changed = True
            return changed, self.deployment_details
        except Exception as e:
            errmsg = f'Deleting a resource group deployment failed with error {utils.get_display_message(str(e))}'
            self.module.fail_json(msg=errmsg)


def main():
    """ Create PowerFlex resource group object and perform actions on it
        based on user input from playbook"""
    obj = PowerFlexResourceGroup()
    obj.perform_module_operation()


def get_powerflex_resource_group_parameters():
    """This method provides parameters required for the resource group
    module on PowerFlex"""
    return dict(
        resource_group_name=dict(),
        resource_group_id=dict(),
        template_name=dict(),
        template_id=dict(),
        firmware_repository_id=dict(),
        firmware_repository_name=dict(),
        new_resource_group_name=dict(),
        description=dict(),
        scaleup=dict(type='bool', default=False),
        clone_node=dict(),
        node_count=dict(type='int', default=1),
        validate=dict(type='bool', default=False),
        schedule_date=dict(),
        state=dict(choices=['present', 'absent'], default='present')
    )


if __name__ == '__main__':
    main()
