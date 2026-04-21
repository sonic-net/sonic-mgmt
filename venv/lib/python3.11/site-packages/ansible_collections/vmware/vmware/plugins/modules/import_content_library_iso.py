#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: import_content_library_iso
short_description: Import an ISO file to a content library from a remote source.
description:
    - Import an ISO library item from a remote source, such as a file on the Ansible host or a URL.
    - This module manages the content library item, not the remote ISO. If state is absent, only the content library item
      will be affected.

author:
    - Ansible Cloud Team (@ansible-collections)

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

options:
    src:
        description:
            - The source ISO file that should be imported to the content library. This can be a local path or a URL.
            - If it is a local path, it should be a valid path on the Ansible host.
            - If it is a URL, its scheme can be HTTPS, HTTP, or datastore (ds://). The file is acquired directly
              from the vCenter appliance.
            - The module will not encode URLs for you. If this is a URL with special characters (like $ or ~), you should
              use the urlencode filter.
            - Required when state is present.
        type: path
        required: false
        aliases: [url, path]
    dest:
        description:
            - The destination name of the ISO item in the content library.
            - If an item with the same name already exists, the module will not update it.
        type: str
        required: true
        aliases: [name]
    state:
        description:
            - Controls if the ISO file should be present or absent in the content library.
        type: str
        choices: [present, absent]
        default: present
    description:
        description:
            - A description for the ISO item in the content library.
        type: str
        required: false
    library_id:
        description:
            - The ID of the library to search within.
            - One of O(library_id) or O(library_name) must be provided.
        type: str
        required: false
    library_name:
        description:
            - The name of the library to search within.
            - One of O(library_id) or O(library_name) must be provided.
        type: str
        required: false
    ssl_thumbprint:
        description:
            - The SSL thumbprint of the source URL, if it uses HTTPS. This is ignored for other schemes.
            - If this is not provided, whatever certificate is presented will be trusted.
        type: str
        required: false
    checksum_algorithm:
        description:
            - The checksum algorithm to use when validating uploads.
            - This is required if O(checksum) is provided.
            - This is not used if the source is an ISO. In that case he local file size is used to validate the upload.
        type: str
        required: false
        choices: ['SHA1', 'MD5', 'SHA512', 'SHA256']
    checksum:
        description:
            - The checksum that should be used to validate the upload.
            - O(checksum_algorithm) is required if this is provided.
            - This is not used if the source is an ISO. In that case he local file size is used to validate the upload.
        type: str
        required: false
    timeout:
        description:
            - The timeout period in seconds for uploads to complete.
        type: int
        required: false
        default: 300
    fail_on_warnings:
        description:
            - Cause the module to treat any warnings thrown during the file upload process as errors.
        default: false
        type: bool

attributes:
    check_mode:
        description: The check_mode support.
        support: full
"""

EXAMPLES = r"""
- name: Acquire An ISO From A Url
  vmware.vmware.import_content_library_iso:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    src: "https://example.com/my/iso/file.iso"
    dest: my_iso_file
    library_name: MyContentLibrary

- name: Acquire An ISO From A Url With Special Chars
  vmware.vmware.import_content_library_iso:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    src: "{{ 'https://example.com/$my$/iso/file.iso' | urlencode }}"
    dest: my_iso_file
    library_name: MyContentLibrary

- name: Upload an ISO From The Ansible Host
  vmware.vmware.import_content_library_iso:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    library_id: "{{ my_library.id }}"
    src: /opt/isos/my_iso.iso
    dest: my_iso_file

- name: Delete an ISO
  vmware.vmware.import_content_library_iso:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    state: absent
    library_id: "{{ my_library.id }}"
    dest: my_iso_file
"""

RETURN = r"""
"""

import time
import ssl
import uuid
import hashlib
import os

from urllib.parse import urlparse

from ansible.module_utils.urls import open_url
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import (
    ModuleRestBase,
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    rest_compatible_argument_spec,
)

try:
    from com.vmware.content.library.item_client import UpdateSessionModel
    from com.vmware.content.library_client import ItemModel
    from com.vmware.content.library.item.updatesession_client import (
        File as UpdateSessionFile,
        PreviewInfo,
        WarningBehavior,
    )
except ImportError:
    # Handled in base class
    pass


class VmwareRemoteIso(ModuleRestBase):
    def __init__(self, module):
        super().__init__(module)
        self.upload_service = self.api_client.content.library.item.UpdateSession
        self.upload_file_service = (
            self.api_client.content.library.item.updatesession.File
        )
        self._library_id = None
        self._library_item_id = None

        if self.params["src"]:
            self.source_is_url = self.params["src"].startswith(
                ("http://", "https://", "ds://")
            )

    def __generate_uuid(self):
        return str(uuid.uuid4())

    @property
    def library_id(self):
        """
        Return a list of library IDs to search for library items, based on
        search parameters.
        If a library ID was supplied, use that.
        If a library name was supplied, search using that name.
        Otherwise, search with a name of None, which essentially means any name

        Returns: str
        """
        if self._library_id:
            pass
        elif self.params["library_id"]:
            self._library_id = self.params["library_id"]
        else:
            self._library_id = self.get_content_library_ids(
                name=self.params["library_name"],
                library_type="LOCAL",
                fail_on_missing=True,
            )[0]

        return self._library_id

    @property
    def library_item_id(self):
        if not self._library_item_id:
            library_item_ids = self.get_library_item_ids(
                name=self.params["dest"], library_id=self.library_id
            )
            self._library_item_id = library_item_ids[0] if library_item_ids else None

        return self._library_item_id

    def create_library_item(self):
        """
        Creates a temporary library item that can then be used as a target when updating files
        """
        lib_item_spec = ItemModel()
        lib_item_spec.name = self.params["dest"]
        lib_item_spec.description = self.params["description"]
        lib_item_spec.library_id = self.library_id
        lib_item_spec.type = "iso"

        # Create a library item
        self._library_item_id = self.library_item_service.create(
            create_spec=lib_item_spec, client_token=self.__generate_uuid()
        )

    def get_file_map(self):
        item_filename = os.path.basename(self.params["src"])
        return {item_filename: self.params["src"]}

    def __create_file_spec(self, name, path):
        """
        Creates an upload spec for a given file.
        Returns:
            File spec
        """
        _kwargs = {"name": name}
        if self.source_is_url:
            _kwargs["source_type"] = UpdateSessionFile.SourceType.PULL
            _kwargs["source_endpoint"] = {
                "uri": path,
                "ssl_certificate_thumbprint": self.__get_source_ssl_thumbprint(),
            }
        else:
            _kwargs["source_type"] = UpdateSessionFile.SourceType.PUSH
            _kwargs["size"] = os.path.getsize(path)

        if self.params["checksum_algorithm"]:
            _kwargs["checksum_info"] = {
                "algorithm": self.params["checksum_algorithm"],
                "checksum": self.params["checksum"],
            }

        return self.upload_file_service.AddSpec(**_kwargs)

    def __get_source_ssl_thumbprint(self):
        """
        If the source URL is https, either return the user supplied thumbprint or get the thumbprint presented by the source.
        Returns:
           None or str
        """
        if not self.params["src"].startswith("https://"):
            return None

        if self.params["ssl_thumbprint"]:
            return self.params["ssl_thumbprint"]

        parsed_url = urlparse(self.params["src"])
        pem = ssl.get_server_certificate((parsed_url.hostname, parsed_url.port or 443))
        sha1 = hashlib.sha1(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
        colon_notion = ":".join(sha1[i : i + 2] for i in range(0, len(sha1), 2))
        return None if sha1 is None else colon_notion

    def __start_upload(self, file_map):
        """
        Initiates the transfer of files to vCenter.
        The transfers are async. Status can be checked via the session
        Params:
            file_map: A dictionary of file names to the file paths. File name is mostly just for identification
        """
        for f_name, f_path in file_map.items():
            file_spec = self.__create_file_spec(f_name, f_path)
            file_info = self.upload_file_service.add(self.session_id, file_spec)
            if self.source_is_url:
                continue
            # Upload the file content to the file upload URL
            with open(f_path, "rb") as local_file:
                headers = {
                    "Cache-Control": "no-cache",
                    "Content-Length": str(os.path.getsize(f_path)),
                    "Content-Type": "text/ovf",
                }
                open_url(
                    method="POST",
                    url=file_info.upload_endpoint.uri,
                    data=local_file.read(),
                    headers=headers,
                    validate_certs=self.params["validate_certs"],
                    timeout=self.params["timeout"],
                )

    def __wait_for_upload(self):
        """
        Periodically checks the current upload and waits for it to reach any state besides ACTIVE.
        Raise errors if the timeout is reached, an unexpected state occurs, or the session has an error.
        Do not fail the module at this point, so we have a chance to clean up.
        """
        start_time = time.time()
        while (time.time() - start_time) < self.params["timeout"]:
            session = self.upload_service.get(self.session_id)
            if session.state != "ACTIVE":
                break
            time.sleep(1)
        else:
            raise Exception(
                "Upload has reached timeout limit %s and has been canceled."
                % self.params["timeout"]
            )

        if session.state == "ERROR":
            raise Exception(
                "Upload session failed with message: %s" % session.error_message
            )

        if session.state != "DONE":
            raise Exception(
                "Upload session is in an unexpected state at the end of the upload, %s"
                % session.state
            )

    def __handle_preview_warnings(self):
        """
        Depending on module parameters, handle any warnings that have occurred during the file transfer.
        If there are warnings and the user has disabled fail_on_warnings, the warnings are essentially
        muted. Otherwise, they cause the transfer to fail.
        """
        if self.params["fail_on_warnings"]:
            return

        self.__wait_for_preview()
        session = self.upload_service.get(self.session_id)

        if session.preview_info.warnings is None:
            return

        warning_types = [warning.type for warning in session.preview_info.warnings]
        if not warning_types:
            return

        # Ignore preview warnings on session
        ignored_warnings = [
            WarningBehavior(type=warn_type, ignored=True) for warn_type in warning_types
        ]
        self.upload_service.update(
            self.session_id,
            update_spec=UpdateSessionModel(warning_behavior=ignored_warnings),
        )

    def upload(self, file_map):
        """
        Initiates and waits for the file transfer. If the file is local, it is pushed to vCenter. If the file is remote (a URL),
        vCenter will initiate a pull.
        If the file transfer fails, the session is cleaned up and the module exits with the error
        """
        self.session_id = self.upload_service.create(
            create_spec=UpdateSessionModel(library_item_id=self.library_item_id),
            client_token=self.__generate_uuid(),
        )
        try:
            self.__start_upload(file_map=file_map)
            self.__handle_preview_warnings()
            # complete tells vcenter that we are done making changes on our side and the upload can complete.
            self.upload_service.complete(self.session_id)
            if self.source_is_url:
                self.__wait_for_upload()
        except Exception as e:
            self.module.fail_json(
                msg="Failed to complete upload of ISO to vCenter: %s" % to_native(e)
            )
        finally:
            self.__cleanup_transfer()

    def __cleanup_transfer(self):
        """
        Cleans up the session object and temporary library item
        """
        session = self.upload_service.get(self.session_id)
        if session.state == "DONE":
            self.upload_service.delete(self.session_id)
            return

        if session.state != "ERROR":
            try:
                self.upload_service.cancel(self.session_id)
            except Exception:
                pass

        self.upload_service.delete(self.session_id)
        if self.library_item_id:
            self.delete_library_item()

    def __wait_for_preview(self):
        """
        Periodically checks the current upload and waits for the preview to become available. The preview
        has information about warnings or validation errors. The file is still being uploaded or is in an error
        state when the preview is available.
        """
        start_time = time.time()
        while (time.time() - start_time) < self.params["timeout"]:
            session = self.upload_service.get(self.session_id)
            if session.state == "ERROR":
                raise Exception(
                    "Session is in error state, error message: %s"
                    % session.error_message
                )

            if session.preview_info.state in [
                PreviewInfo.State.NOT_APPLICABLE,
                PreviewInfo.State.AVAILABLE,
            ]:
                break

            time.sleep(1)

    def delete_library_item(self):
        try:
            self.api_client.content.library.Item.delete(self.library_item_id)
        except Exception as err:
            self.module.fail_json(msg="%s" % to_native(err))

    def state_absent(self, result):
        if not self.library_item_id:
            return
        result["changed"] = True
        result["library_item"]["id"] = self.library_item_id
        if not self.module.check_mode:
            self.delete_library_item()

    def state_present(self, result):
        if self.library_item_id:
            result["library_item"]["id"] = self.library_item_id
            return

        result["changed"] = True
        file_map = self.get_file_map()
        if self.module.check_mode:
            return

        self.create_library_item()
        result["library_item"]["id"] = self.library_item_id
        self.upload(file_map=file_map)


def main():
    module = AnsibleModule(
        argument_spec={
            **rest_compatible_argument_spec(),
            **dict(
                state=dict(
                    type="str", choices=["present", "absent"], default="present"
                ),
                src=dict(type="path", required=False, aliases=["url", "path"]),
                dest=dict(type="str", required=True, aliases=["name"]),
                description=dict(type="str", required=False),
                library_name=dict(type="str", required=False),
                library_id=dict(type="str", required=False),
                ssl_thumbprint=dict(type="str", required=False),
                checksum_algorithm=dict(
                    type="str",
                    required=False,
                    choices=["SHA1", "MD5", "SHA256", "SHA512"],
                ),
                checksum=dict(type="str", required=False),
                timeout=dict(type="int", default=300),
                fail_on_warnings=dict(type="bool", default=False),
            ),
        },
        mutually_exclusive=[
            ("library_name", "library_id"),
        ],
        required_one_of=[("library_name", "library_id")],
        required_together=[("checksum", "checksum_algorithm")],
        required_if=[("state", "present", ("src",))],
        supports_check_mode=True,
    )

    result = dict(changed=False, library_item={"name": module.params["dest"]})

    remote_iso = VmwareRemoteIso(module)

    if module.params["state"] == "absent":
        remote_iso.state_absent(result)

    if module.params["state"] == "present":
        remote_iso.state_present(result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
