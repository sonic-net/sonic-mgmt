#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: file_info
short_description: Information module for File
description:
  - Get File by id.
  - Downloads a file specified by fileId.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fileId:
    description:
      - FileId path parameter. File Identification number.
    type: str
  dirPath:
    description:
      - Directory absolute path. Defaults to the current
        working directory.
    type: str
  saveFile:
    description:
      - Enable or disable automatic file creation of
        raw response.
    type: bool
  filename:
    description:
      - The filename used to save the download file.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for File DownloadAFileByFileId
    description: Complete reference of the DownloadAFileByFileId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!download-a-file-by-file-id
notes:
  - SDK Method used are
    file.File.download_a_file_by_fileid,
  - Paths used are
    get /dna/intent/api/v1/file/{fileId},
"""

EXAMPLES = r"""
---
- name: Get File by id
  cisco.dnac.file_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fileId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "data": "filecontent",
      "filename": "filename",
      "dirpath": "download/directory",
      "path": "download/directory/filename"
    }
"""
