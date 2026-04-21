# Copyright: (c) 2024, Dell Technologies

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('configuration')


class Configuration:

    """
    The configuration SDK class with shared configuration operations.
    """

    def __init__(self, powerflex_conn, module):
        """
        Initialize the configuration class
        :param configuration: The configuration SDK instance
        :param module: Ansible module object
        """
        self.module = module
        self.powerflex_conn = powerflex_conn

    def get_protection_domain(
        self, protection_domain_name=None, protection_domain_id=None
    ):
        """
        Get protection domain details
        :param protection_domain_name: Name of the protection domain
        :param protection_domain_id: ID of the protection domain
        :return: Protection domain details if exists
        :rtype: dict
        """

        name_or_id = (
            protection_domain_id if protection_domain_id else protection_domain_name
        )

        try:
            if protection_domain_id:
                pd_details = self.powerflex_conn.protection_domain.get(
                    filter_fields={"id": protection_domain_id}
                )

            else:
                pd_details = self.powerflex_conn.protection_domain.get(
                    filter_fields={"name": protection_domain_name}
                )

            if len(pd_details) == 0:
                error_msg = (
                    "Unable to find the protection domain with " "'%s'." % name_or_id
                )
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            return pd_details[0]

        except Exception as e:
            error_msg = (
                "Failed to get the protection domain '%s' with "
                "error '%s'" % (name_or_id, str(e))
            )
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_fault_set(self, fault_set_name=None, fault_set_id=None, protection_domain_id=None):
        """Get fault set details
            :param fault_set_name: Name of the fault set
            :param fault_set_id: Id of the fault set
            :param protection_domain_id: ID of the protection domain
            :return: Fault set details
            :rtype: dict
        """
        name_or_id = fault_set_id if fault_set_id \
            else fault_set_name
        try:
            fs_details = {}
            if fault_set_id:
                fs_details = self.powerflex_conn.fault_set.get(
                    filter_fields={'id': name_or_id})

            if fault_set_name:
                fs_details = self.powerflex_conn.fault_set.get(
                    filter_fields={'name': name_or_id, 'protectionDomainId': protection_domain_id})

            if not fs_details:
                msg = f"Unable to find the fault set with {name_or_id}"
                LOG.info(msg)
                return None

            return fs_details[0]

        except Exception as e:
            error_msg = f"Failed to get the fault set '{name_or_id}' with error '{str(e)}'"
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_associated_sds(self, fault_set_id=None):
        """Get associated SDS to a fault set
            :param fault_set_id: Id of the fault set
            :return: Associated SDS details
            :rtype: dict
        """
        try:
            if fault_set_id:
                sds_details = self.powerflex_conn.fault_set.get_sdss(
                    fault_set_id=fault_set_id)

            return sds_details

        except Exception as e:
            error_msg = f"Failed to get the associated SDS with error '{str(e)}'"
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)
