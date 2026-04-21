# Copyright: (c) 2021, Alina Buzachis <@alinabuzachis>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


import asyncio
import urllib

from ansible.errors import AnsibleLookupError
from ansible.module_utils._text import to_native
from ansible_collections.vmware.vmware_rest.plugins.module_utils.vmware_rest import (
    gen_args,
    open_session,
)


class InvalidVspherePathError(Exception):
    def __init__(self, container_name, object_type):
        self.container_name = container_name
        self.object_type = object_type
        super().__init__(
            "VSphere object '%s' cannot hold objects of type '%s'"
            % (container_name, object_type)
        )


FILTER_MAPPINGS = {
    "resource_pool": {
        "parent_resource_pools": "parent_resource_pools",
        "resource_pools": "resource_pools",
    },
    "datacenter": {
        "parent_folders": "folders",
    },
    "folder": {},
    "cluster": {
        "parent_folders": "folders",
    },
    "host": {
        "parent_folders": "folders",
    },
    "datastore": {
        "parent_folders": "folders",
    },
    "vm": {
        "parent_folders": "folders",
    },
    "network": {"parent_folders": "folders"},
}


class VcenterApi:
    def __init__(self, hostname, session):
        self.hostname = hostname
        self.session = session

    def build_url(self, object_type, filters):
        corrected_filters_for_query = self.correct_filter_names(filters, object_type)
        object_type = object_type.replace("_", "-")

        return (f"https://{self.hostname}/api/vcenter/{object_type}") + gen_args(
            corrected_filters_for_query, corrected_filters_for_query.keys()
        )

    def correct_filter_names(self, filters, object_type):
        """
        Objects in vSphere have slightly different filter names. For example, some use 'parent_folders' and some use 'folders'.
        Its easier to read the code if we do all of the filter corrections at the end using a map.
        Params:
            filters: dict, The active filters that should be applied to the REST request
        """
        if object_type not in FILTER_MAPPINGS.keys():
            raise AnsibleLookupError(
                "object_type must be one of [%s]."
                % ", ".join(list(FILTER_MAPPINGS.keys()))
            )
        corrected_filters = {}
        for filter_key, filter_value in filters.items():
            try:
                corrected_filters[FILTER_MAPPINGS[object_type][filter_key]] = (
                    filter_value
                )
            except KeyError:
                corrected_filters[filter_key] = filter_value

        return corrected_filters

    async def fetch_object_with_filters(self, object_type, filters):
        _url = self.build_url(object_type, filters)
        async with self.session.get(_url) as response:
            return await response.json()


class Lookup:
    def __init__(self, options, session):
        self._options = options
        self.api = VcenterApi(options["vcenter_hostname"], session)
        self.active_filters = {}
        self.object_type = options["object_type"]
        # this is an internal flag that indicates if we tried to find the datacenter or not
        # if its true, we stop trying and save some api calls.
        # see add_intermediate_path_part_to_filter_spec
        self._searched_for_datacenter = False

    @classmethod
    async def entry_point(cls, terms, options):
        if not terms or not terms[0]:
            raise AnsibleLookupError(
                "Option _terms is required but no object has been specified"
            )
        session = None
        try:
            session = await open_session(
                vcenter_hostname=options["vcenter_hostname"],
                vcenter_username=options["vcenter_username"],
                vcenter_password=options["vcenter_password"],
                validate_certs=options.get("vcenter_validate_certs"),
                log_file=options.get("vcenter_rest_log_file"),
            )
        except Exception as e:
            raise AnsibleLookupError(
                f'Unable to connect to vCenter or ESXi API at {options["vcenter_hostname"]}: {to_native(e)}'
            )

        lookup = cls(options, session)
        lookup._options["_terms"] = terms[0]

        try:
            task = asyncio.create_task(lookup.search_for_object_moid_top_down())
            return await task
        except InvalidVspherePathError:
            return ""

    async def search_for_object_moid_top_down(self):
        """
        Searches for the lookup term in VSphere. Uses a top down approach to progress
        through the path (for example /datacenter/vm/foo/bar/my-vm) until it reaches the
        desired object. This guarantees we find the correct object even if multiple have the
        same name, possibly at the cost of performance.
        """
        object_path = self._options["_terms"]
        return_all_children = object_path.endswith("/")
        path_parts = [_part for _part in object_path.split("/") if _part]

        for index, path_part in enumerate(path_parts):
            if index == len(path_parts) - 1:
                # were at the end of the object path. Either return the object, or return
                # all of the objects it contains (for example, the children inside of a folder)
                if return_all_children:
                    await self.add_intermediate_path_part_to_filter_spec(path_part)
                    return await self.get_all_children_in_object()
                else:
                    return await self.get_object_moid_by_name_and_type(path_part)

            else:
                # were in the middle of an object path, lookup the object at this level
                # and add it to the filters for the next round of searching
                await self.add_intermediate_path_part_to_filter_spec(path_part)
                continue

        raise AnsibleLookupError(
            "No objects could be found due to an invalid search path"
        )

    async def add_intermediate_path_part_to_filter_spec(self, intermediate_object_name):
        """
        The intermediate object name is part of the search path that the user provided. This method tries to determine
        what that intermediate object is based on its name and the type of lookup were doing. If the object is found,
        its added to the final lookup filter spec.
        If no object is found, that means the path is invalid for the lookup type, and we raise an error.
        To find an objects filter spec definition, visit the VMware API docs.
        Params:
            intermediate_object_name: str, The name of the current object to search for
        Returns:
            None
        """
        # If we havnt searched for a datacenter yet, this is the first item in the path and its likely
        # the datacenter. If its not, continue the search as normal and dont search for the datacenter
        # again
        if not self._searched_for_datacenter:
            if await self.__add_datacenter_to_filter_spec_if_exists(
                intermediate_object_name
            ):
                return

        # Resource pools can only be in the vm filter spec
        if self.object_type == "vm":
            if await self.__add_object_to_filter_spec_if_exists(
                intermediate_object_name, "resource_pool", "resource_pools"
            ):
                return

        # Clusters can be used in the vm, host, or resource pool filter specs
        if self.object_type in ("vm", "host", "resource_pool"):
            if await self.__add_object_to_filter_spec_if_exists(
                intermediate_object_name, "cluster", "clusters"
            ):
                return

        # Hosts can be in the filter spec for vms, networks, datastores, or resource pools
        if self.object_type in ("vm", "network", "datastore", "resource_pool"):
            if await self.__add_object_to_filter_spec_if_exists(
                intermediate_object_name, "host", "hosts"
            ):
                return

        # Folders can be used in the filter spec for everything except resource pools
        if self.object_type != "resource_pool":
            if await self.__add_object_to_filter_spec_if_exists(
                intermediate_object_name, "folder", "parent_folders"
            ):
                return

        raise InvalidVspherePathError(
            container_name=intermediate_object_name, object_type=self.object_type
        )

    async def __add_datacenter_to_filter_spec_if_exists(self, object_name):
        """
        Search for an object name as a datacenter. If found, add the datacenter to the
        active filter spec.
        Params:
            object_name: str, The name of the current object to search for
        Returns:
            Datacenter MOID or None
        """
        self._searched_for_datacenter = True
        result = await self.get_object_moid_by_name_and_type(object_name, "datacenter")
        if result:
            self.active_filters["datacenters"] = result
            return result

    async def __add_object_to_filter_spec_if_exists(
        self, object_name, object_type, filter_key
    ):
        """
        Search for an object name as a specific object type. If found, add the object ID to the
        active filter spec.
        Params:
            object_name: str, The name of the current object to search for
            object_type: str, The type of object to search for
            filter_key: str, The key in the filter spec that the result will be stored under
        Returns:
            Object MOID or None
        """
        result = await self.get_object_moid_by_name_and_type(object_name, object_type)
        if result:
            self.active_filters[filter_key] = result
            return result

    async def get_object_moid_by_name_and_type(self, object_name, _object_type=None):
        """
        Returns a single object MoID with a specific type, name, and filter set. If more than one object
        is found, and error is thrown.
        Params:
            object_name: str, the name of the object to search for
            _object_type: str, Optional name of the object type to search for. Defaults to the lookup plugin type
        Returns:
            str, a single MoID
        """
        if not _object_type:
            _object_type = self.object_type

        if _object_type == "datacenter":
            _filters = {"folders": "group-d1"}
        else:
            _filters = self.active_filters.copy()

        _filters["names"] = object_name
        _result = await self.api.fetch_object_with_filters(_object_type, _filters)

        object_moid = self.get_single_moid_from_result(
            _result, _object_type, object_name
        )
        return object_moid

    @staticmethod
    def get_single_moid_from_result(result, object_type, object_name=None):
        """
        Parses vSphere returns query results as a json list, validates the results and extracts
        the correct MoID
        Params:
            object_type: str, The type of object to search the results for
            object_name: str, The name of the object to search the results for
        Returns:
            str or None, a single MoID or none if nothing was found
        """
        if not result or not object_name:
            return None

        object_name_decoded = urllib.parse.unquote(object_name)
        if object_name_decoded not in result[0].values():
            return None

        results_with_decoded_names = []
        for obj in result:
            if "%2f" in obj["name"]:
                continue
            results_with_decoded_names.append((obj["name"], obj[object_type]))

        if len(results_with_decoded_names) > 1:
            raise AnsibleLookupError(
                "More than one object found with matching name: [%s]."
                % ", ".join(
                    [f"{item[0]} => {item[1]}" for item in results_with_decoded_names]
                )
            )

        try:
            return results_with_decoded_names[0][1]
        except (TypeError, KeyError, IndexError) as e:
            raise AnsibleLookupError(to_native(e))

    async def get_all_children_in_object(self):
        results = await self.api.fetch_object_with_filters(
            self.object_type, self.active_filters
        )

        try:
            return [result[self.object_type] for result in results]
        except KeyError:
            return None
