#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_antivirus_profile
short_description: Configure AntiVirus profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify antivirus feature and profile category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

    - The module supports check_mode.

requirements:
    - ansible>=2.15
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    antivirus_profile:
        description:
            - Configure AntiVirus profiles.
        default: null
        type: dict
        suboptions:
            analytics_accept_filetype:
                description:
                    - Only submit files matching this DLP file-pattern to FortiSandbox (post-transfer scan only). Source dlp.filepattern.id.
                type: int
            analytics_bl_filetype:
                description:
                    - Only submit files matching this DLP file-pattern to FortiSandbox. Source dlp.filepattern.id.
                type: int
            analytics_db:
                description:
                    - Enable/disable using the FortiSandbox signature database to supplement the AV signature databases.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            analytics_ignore_filetype:
                description:
                    - Do not submit files matching this DLP file-pattern to FortiSandbox (post-transfer scan only). Source dlp.filepattern.id.
                type: int
            analytics_max_upload:
                description:
                    - Maximum size of files that can be uploaded to FortiSandbox.
                type: int
            analytics_wl_filetype:
                description:
                    - Do not submit files matching this DLP file-pattern to FortiSandbox. Source dlp.filepattern.id.
                type: int
            av_block_log:
                description:
                    - Enable/disable logging for AntiVirus file blocking.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            av_virus_log:
                description:
                    - Enable/disable AntiVirus logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            cifs:
                description:
                    - Configure CIFS AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable CIFS AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            comment:
                description:
                    - Comment.
                type: str
            content_disarm:
                description:
                    - AV Content Disarm and Reconstruction settings.
                type: dict
                suboptions:
                    analytics_suspicious:
                        description:
                            - Enable/disable using CDR as a secondary method for determining suspicous files for analytics.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    cover_page:
                        description:
                            - Enable/disable inserting a cover page into the disarmed document.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    detect_only:
                        description:
                            - Enable/disable only detect disarmable files, do not alter content.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    error_action:
                        description:
                            - Action to be taken if CDR engine encounters an unrecoverable error.
                        type: str
                        choices:
                            - 'block'
                            - 'log-only'
                            - 'ignore'
                    office_action:
                        description:
                            - Enable/disable stripping of PowerPoint action events in Microsoft Office documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    office_dde:
                        description:
                            - Enable/disable stripping of Dynamic Data Exchange events in Microsoft Office documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    office_embed:
                        description:
                            - Enable/disable stripping of embedded objects in Microsoft Office documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    office_hylink:
                        description:
                            - Enable/disable stripping of hyperlinks in Microsoft Office documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    office_linked:
                        description:
                            - Enable/disable stripping of linked objects in Microsoft Office documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    office_macro:
                        description:
                            - Enable/disable stripping of macros in Microsoft Office documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    original_file_destination:
                        description:
                            - Destination to send original file if active content is removed.
                        type: str
                        choices:
                            - 'fortisandbox'
                            - 'quarantine'
                            - 'discard'
                    pdf_act_form:
                        description:
                            - Enable/disable stripping of PDF document actions that submit data to other targets.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_gotor:
                        description:
                            - Enable/disable stripping of PDF document actions that access other PDF documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_java:
                        description:
                            - Enable/disable stripping of PDF document actions that execute JavaScript code.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_launch:
                        description:
                            - Enable/disable stripping of PDF document actions that launch other applications.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_movie:
                        description:
                            - Enable/disable stripping of PDF document actions that play a movie.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_sound:
                        description:
                            - Enable/disable stripping of PDF document actions that play a sound.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_embedfile:
                        description:
                            - Enable/disable stripping of embedded files in PDF documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_hyperlink:
                        description:
                            - Enable/disable stripping of hyperlinks from PDF documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_javacode:
                        description:
                            - Enable/disable stripping of JavaScript code in PDF documents.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            ems_threat_feed:
                description:
                    - Enable/disable use of EMS threat feed when performing AntiVirus scan. Analyzes files including the content of archives.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            extended_log:
                description:
                    - Enable/disable extended logging for antivirus.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            external_blocklist:
                description:
                    - One or more external malware block lists.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - External blocklist. Source system.external-resource.name.
                        required: true
                        type: str
            external_blocklist_archive_scan:
                description:
                    - Enable/disable external-blocklist archive scanning.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            external_blocklist_enable_all:
                description:
                    - Enable/disable all external blocklists.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            feature_set:
                description:
                    - Flow/proxy feature set.
                type: str
                choices:
                    - 'flow'
                    - 'proxy'
            fortiai_error_action:
                description:
                    - Action to take if FortiAI encounters an error.
                type: str
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortiai_timeout_action:
                description:
                    - Action to take if FortiAI encounters a scan timeout.
                type: str
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortindr_error_action:
                description:
                    - Action to take if FortiNDR encounters an error.
                type: str
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortindr_timeout_action:
                description:
                    - Action to take if FortiNDR encounters a scan timeout.
                type: str
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortisandbox_error_action:
                description:
                    - Action to take if FortiSandbox inline scan encounters an error.
                type: str
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortisandbox_max_upload:
                description:
                    - Maximum size of files that can be uploaded to FortiSandbox in Mbytes.
                type: int
            fortisandbox_mode:
                description:
                    - FortiSandbox scan modes.
                type: str
                choices:
                    - 'inline'
                    - 'analytics-suspicious'
                    - 'analytics-everything'
            fortisandbox_timeout_action:
                description:
                    - Action to take if FortiSandbox inline scan encounters a scan timeout.
                type: str
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            ftgd_analytics:
                description:
                    - Settings to control which files are uploaded to FortiSandbox.
                type: str
                choices:
                    - 'disable'
                    - 'suspicious'
                    - 'everything'
            ftp:
                description:
                    - Configure FTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable FTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            http:
                description:
                    - Configure HTTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    content_disarm:
                        description:
                            - Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable HTTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    unknown_content_encoding:
                        description:
                            - Configure the action the FortiGate unit will take on unknown content-encoding.
                        type: str
                        choices:
                            - 'block'
                            - 'inspect'
                            - 'bypass'
            imap:
                description:
                    - Configure IMAP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    content_disarm:
                        description:
                            - Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    executables:
                        description:
                            - Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        type: str
                        choices:
                            - 'default'
                            - 'virus'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable IMAP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            inspection_mode:
                description:
                    - Inspection mode.
                type: str
                choices:
                    - 'proxy'
                    - 'flow-based'
            mapi:
                description:
                    - Configure MAPI AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    executables:
                        description:
                            - Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        type: str
                        choices:
                            - 'default'
                            - 'virus'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable MAPI AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            mobile_malware_db:
                description:
                    - Enable/disable using the mobile malware signature database.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            nac_quar:
                description:
                    - Configure AntiVirus quarantine settings.
                type: dict
                suboptions:
                    expiry:
                        description:
                            - Duration of quarantine.
                        type: str
                    infected:
                        description:
                            - Enable/Disable quarantining infected hosts to the banned user list.
                        type: str
                        choices:
                            - 'none'
                            - 'quar-src-ip'
                    log:
                        description:
                            - Enable/disable AntiVirus quarantine logging.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            name:
                description:
                    - Profile name.
                required: true
                type: str
            nntp:
                description:
                    - Configure NNTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable NNTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            outbreak_prevention:
                description:
                    - Configure Virus Outbreak Prevention settings.
                type: dict
                suboptions:
                    external_blocklist:
                        description:
                            - Enable/disable external malware blocklist.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    ftgd_service:
                        description:
                            - Enable/disable FortiGuard Virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            outbreak_prevention_archive_scan:
                description:
                    - Enable/disable outbreak-prevention archive scanning.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            pop3:
                description:
                    - Configure POP3 AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    content_disarm:
                        description:
                            - Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    executables:
                        description:
                            - Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        type: str
                        choices:
                            - 'default'
                            - 'virus'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable POP3 AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            replacemsg_group:
                description:
                    - Replacement message group customized for this profile. Source system.replacemsg-group.name.
                type: str
            scan_mode:
                description:
                    - Configure scan mode .
                type: str
                choices:
                    - 'default'
                    - 'legacy'
                    - 'quick'
                    - 'full'
            smb:
                description:
                    - Configure SMB AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'fileslimit'
                            - 'timeout'
                            - 'unhandled'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'fileslimit'
                            - 'timeout'
                            - 'unhandled'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    options:
                        description:
                            - Enable/disable SMB AntiVirus scanning, monitoring, and quarantine.
                        type: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable FortiGuard Virus Outbreak Prevention service.
                        type: str
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
            smtp:
                description:
                    - Configure SMTP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    content_disarm:
                        description:
                            - Enable/disable Content Disarm and Reconstruction when performing AntiVirus scan.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    executables:
                        description:
                            - Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        type: str
                        choices:
                            - 'default'
                            - 'virus'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable SMTP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
            ssh:
                description:
                    - Configure SFTP and SCP AntiVirus options.
                type: dict
                suboptions:
                    archive_block:
                        description:
                            - Select the archive types to block.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    archive_log:
                        description:
                            - Select the archive types to log.
                        type: list
                        elements: str
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'partiallycorrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'timeout'
                            - 'unhandled'
                            - 'fileslimit'
                    av_scan:
                        description:
                            - Enable AntiVirus scan service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    emulator:
                        description:
                            - Enable/disable the virus emulator.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
                    external_blocklist:
                        description:
                            - Enable external-blocklist. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        description:
                            - Enable/disable scanning of files by FortiAI.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortindr:
                        description:
                            - Enable scanning of files by FortiNDR.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        description:
                            - Enable scanning of files by FortiSandbox.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    malware_stream:
                        description:
                            - Enable 0-day malware-stream scanning. Analyzes files including the content of archives.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    options:
                        description:
                            - Enable/disable SFTP and SCP AntiVirus scanning, monitoring, and quarantine.
                        type: list
                        elements: str
                        choices:
                            - 'scan'
                            - 'avmonitor'
                            - 'quarantine'
                    outbreak_prevention:
                        description:
                            - Enable virus outbreak prevention service.
                        type: str
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                    quarantine:
                        description:
                            - Enable/disable quarantine for infected files.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
"""

EXAMPLES = """
- name: Configure AntiVirus profiles.
  fortinet.fortios.fortios_antivirus_profile:
      vdom: "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      antivirus_profile:
          analytics_accept_filetype: "0"
          analytics_bl_filetype: "2147483647"
          analytics_db: "disable"
          analytics_ignore_filetype: "0"
          analytics_max_upload: "10"
          analytics_wl_filetype: "2147483647"
          av_block_log: "enable"
          av_virus_log: "enable"
          cifs:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              emulator: "enable"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
          comment: "Comment."
          content_disarm:
              analytics_suspicious: "disable"
              cover_page: "disable"
              detect_only: "disable"
              error_action: "block"
              office_action: "disable"
              office_dde: "disable"
              office_embed: "disable"
              office_hylink: "disable"
              office_linked: "disable"
              office_macro: "disable"
              original_file_destination: "fortisandbox"
              pdf_act_form: "disable"
              pdf_act_gotor: "disable"
              pdf_act_java: "disable"
              pdf_act_launch: "disable"
              pdf_act_movie: "disable"
              pdf_act_sound: "disable"
              pdf_embedfile: "disable"
              pdf_hyperlink: "disable"
              pdf_javacode: "disable"
          ems_threat_feed: "disable"
          extended_log: "enable"
          external_blocklist:
              -
                  name: "default_name_49 (source system.external-resource.name)"
          external_blocklist_archive_scan: "disable"
          external_blocklist_enable_all: "disable"
          feature_set: "flow"
          fortiai_error_action: "log-only"
          fortiai_timeout_action: "log-only"
          fortindr_error_action: "log-only"
          fortindr_timeout_action: "log-only"
          fortisandbox_error_action: "log-only"
          fortisandbox_max_upload: "10"
          fortisandbox_mode: "inline"
          fortisandbox_timeout_action: "log-only"
          ftgd_analytics: "disable"
          ftp:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              emulator: "enable"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
          http:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              content_disarm: "disable"
              emulator: "enable"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
              unknown_content_encoding: "block"
          imap:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              content_disarm: "disable"
              emulator: "enable"
              executables: "default"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
          inspection_mode: "proxy"
          mapi:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              emulator: "enable"
              executables: "default"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
          mobile_malware_db: "disable"
          nac_quar:
              expiry: "<your_own_value>"
              infected: "none"
              log: "enable"
          name: "default_name_125"
          nntp:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              emulator: "enable"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
          outbreak_prevention:
              external_blocklist: "disable"
              ftgd_service: "disable"
          outbreak_prevention_archive_scan: "disable"
          pop3:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              content_disarm: "disable"
              emulator: "enable"
              executables: "default"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
          replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
          scan_mode: "default"
          smb:
              archive_block: "encrypted"
              archive_log: "encrypted"
              emulator: "enable"
              options: "scan"
              outbreak_prevention: "disabled"
          smtp:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              content_disarm: "disable"
              emulator: "enable"
              executables: "default"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
          ssh:
              archive_block: "encrypted"
              archive_log: "encrypted"
              av_scan: "disable"
              emulator: "enable"
              external_blocklist: "disable"
              fortiai: "disable"
              fortindr: "disable"
              fortisandbox: "disable"
              malware_stream: "disable"
              options: "scan"
              outbreak_prevention: "disable"
              quarantine: "disable"
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    find_current_values,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    unify_data_format,
)


def filter_antivirus_profile_data(json):
    option_list = [
        "analytics_accept_filetype",
        "analytics_bl_filetype",
        "analytics_db",
        "analytics_ignore_filetype",
        "analytics_max_upload",
        "analytics_wl_filetype",
        "av_block_log",
        "av_virus_log",
        "cifs",
        "comment",
        "content_disarm",
        "ems_threat_feed",
        "extended_log",
        "external_blocklist",
        "external_blocklist_archive_scan",
        "external_blocklist_enable_all",
        "feature_set",
        "fortiai_error_action",
        "fortiai_timeout_action",
        "fortindr_error_action",
        "fortindr_timeout_action",
        "fortisandbox_error_action",
        "fortisandbox_max_upload",
        "fortisandbox_mode",
        "fortisandbox_timeout_action",
        "ftgd_analytics",
        "ftp",
        "http",
        "imap",
        "inspection_mode",
        "mapi",
        "mobile_malware_db",
        "nac_quar",
        "name",
        "nntp",
        "outbreak_prevention",
        "outbreak_prevention_archive_scan",
        "pop3",
        "replacemsg_group",
        "scan_mode",
        "smb",
        "smtp",
        "ssh",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or (not data[path[index]] and not isinstance(data[path[index]], list))
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
        if len(data[path[index]]) == 0:
            data[path[index]] = None
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["http", "archive_block"],
        ["http", "archive_log"],
        ["http", "options"],
        ["ftp", "archive_block"],
        ["ftp", "archive_log"],
        ["ftp", "options"],
        ["imap", "archive_block"],
        ["imap", "archive_log"],
        ["imap", "options"],
        ["pop3", "archive_block"],
        ["pop3", "archive_log"],
        ["pop3", "options"],
        ["smtp", "archive_block"],
        ["smtp", "archive_log"],
        ["smtp", "options"],
        ["mapi", "archive_block"],
        ["mapi", "archive_log"],
        ["mapi", "options"],
        ["nntp", "archive_block"],
        ["nntp", "archive_log"],
        ["nntp", "options"],
        ["cifs", "archive_block"],
        ["cifs", "archive_log"],
        ["cifs", "options"],
        ["ssh", "archive_block"],
        ["ssh", "archive_log"],
        ["ssh", "options"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


def underscore_to_hyphen(data):
    new_data = None
    if isinstance(data, list):
        new_data = []
        for i, elem in enumerate(data):
            new_data.append(underscore_to_hyphen(elem))
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
    else:
        return data
    return new_data


def antivirus_profile(data, fos, check_mode=False):

    state = None
    vdom = data["vdom"]
    state = data.get("state", None)
    antivirus_profile_data = data["antivirus_profile"]

    filtered_data = filter_antivirus_profile_data(antivirus_profile_data)
    filtered_data = flatten_multilists_attributes(filtered_data)
    converted_data = underscore_to_hyphen(filtered_data)

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkeyname = fos.get_mkeyname(None, None)
        mkey = fos.get_mkey("antivirus", "profile", filtered_data, vdom=vdom)
        current_data = fos.get("antivirus", "profile", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and (
                mkeyname
                and isinstance(current_data.get("results"), list)
                and len(current_data["results"]) > 0
                or not mkeyname
                and current_data["results"]  # global object response
            )
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True or state is None:
            # for non global modules, mkeyname must exist and it's a new module when mkey is None
            if mkeyname is not None and mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            copied_filtered_data = filtered_data.copy()
            copied_filtered_data.pop(mkeyname, None)
            unified_filtered_data = unify_data_format(copied_filtered_data)

            current_data_results = current_data.get("results", {})
            current_config = (
                current_data_results[0]
                if mkeyname
                and isinstance(current_data_results, list)
                and len(current_data_results) > 0
                else current_data_results
            )
            if is_existed:
                unified_current_values = find_current_values(
                    unified_filtered_data,
                    unify_data_format(current_config),
                )

                is_same = is_same_comparison(
                    serialize(unified_current_values), serialize(unified_filtered_data)
                )

                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": unified_current_values, "after": unified_filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}
    # pass post processed data to member operations
    # no need to do underscore_to_hyphen since do_member_operation handles it by itself
    data_copy = data.copy()
    data_copy["antivirus_profile"] = filtered_data
    fos.do_member_operation(
        "antivirus",
        "profile",
        data_copy,
    )

    if state == "present" or state is True:
        return fos.set("antivirus", "profile", data=converted_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "antivirus", "profile", mkey=converted_data["name"], vdom=vdom
        )
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_antivirus(data, fos, check_mode):

    if data["antivirus_profile"]:
        resp = antivirus_profile(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("antivirus_profile"))
    if isinstance(resp, tuple) and len(resp) == 4:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"v_range": [["v6.0.0", ""]], "type": "string", "required": True},
        "comment": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "replacemsg_group": {"v_range": [["v6.0.0", ""]], "type": "string"},
        "feature_set": {
            "v_range": [["v6.4.0", ""]],
            "type": "string",
            "options": [{"value": "flow"}, {"value": "proxy"}],
        },
        "fortisandbox_mode": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [
                {"value": "inline"},
                {"value": "analytics-suspicious"},
                {"value": "analytics-everything"},
            ],
        },
        "fortisandbox_max_upload": {"v_range": [["v7.2.0", ""]], "type": "integer"},
        "analytics_ignore_filetype": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "analytics_accept_filetype": {"v_range": [["v7.0.0", ""]], "type": "integer"},
        "analytics_db": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "mobile_malware_db": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "http": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "content_disarm": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "unknown_content_encoding": {
                    "v_range": [["v7.0.8", "v7.0.12"], ["v7.2.1", "v7.2.2"]],
                    "type": "string",
                    "options": [
                        {"value": "block"},
                        {"value": "inspect"},
                        {"value": "bypass"},
                    ],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "ftp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "imap": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "executables": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "default"}, {"value": "virus"}],
                },
                "content_disarm": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "pop3": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "executables": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "default"}, {"value": "virus"}],
                },
                "content_disarm": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "smtp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "executables": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "default"}, {"value": "virus"}],
                },
                "content_disarm": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "mapi": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "executables": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "default"}, {"value": "virus"}],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "nntp": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.0.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.0.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.0.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.0.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "cifs": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.2.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.2.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.2.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.2.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.2.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.2.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "ssh": {
            "v_range": [["v6.2.0", ""]],
            "type": "dict",
            "children": {
                "av_scan": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable", "v_range": [["v7.0.0", ""]]},
                        {"value": "block", "v_range": [["v7.0.0", ""]]},
                        {"value": "monitor", "v_range": [["v7.0.0", ""]]},
                        {"value": "disabled", "v_range": [["v6.2.0", "v6.4.4"]]},
                        {"value": "files", "v_range": [["v6.2.0", "v6.4.4"]]},
                        {"value": "full-archive", "v_range": [["v6.2.0", "v6.4.4"]]},
                    ],
                },
                "external_blocklist": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "malware_stream": {
                    "v_range": [["v7.6.3", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortindr": {
                    "v_range": [["v7.0.8", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "fortisandbox": {
                    "v_range": [["v7.2.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "quarantine": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "archive_block": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.2.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "archive_log": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "list",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                        {"value": "fileslimit", "v_range": [["v6.2.0", "v7.0.1"]]},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "emulator": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "fortiai": {
                    "v_range": [["v7.0.1", "v7.0.7"]],
                    "type": "string",
                    "options": [
                        {"value": "disable"},
                        {"value": "block"},
                        {"value": "monitor"},
                    ],
                },
                "options": {
                    "v_range": [["v6.2.0", "v6.4.4"]],
                    "type": "list",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
            },
        },
        "nac_quar": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "infected": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "none"}, {"value": "quar-src-ip"}],
                },
                "expiry": {"v_range": [["v6.0.0", ""]], "type": "string"},
                "log": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
            },
        },
        "content_disarm": {
            "v_range": [["v6.0.0", ""]],
            "type": "dict",
            "children": {
                "analytics_suspicious": {
                    "v_range": [["v7.6.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "original_file_destination": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [
                        {"value": "fortisandbox"},
                        {"value": "quarantine"},
                        {"value": "discard"},
                    ],
                },
                "error_action": {
                    "v_range": [["v6.4.0", "v6.4.0"], ["v6.4.4", ""]],
                    "type": "string",
                    "options": [
                        {"value": "block"},
                        {"value": "log-only"},
                        {"value": "ignore"},
                    ],
                },
                "office_macro": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "office_hylink": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "office_linked": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "office_embed": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "office_dde": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "office_action": {
                    "v_range": [["v6.2.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_javacode": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_embedfile": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_hyperlink": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_act_gotor": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_act_launch": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_act_sound": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_act_movie": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_act_java": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "pdf_act_form": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "cover_page": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "detect_only": {
                    "v_range": [["v6.0.0", ""]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
        },
        "outbreak_prevention_archive_scan": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "external_blocklist_enable_all": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "external_blocklist": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "v_range": [["v7.0.0", ""]],
                    "type": "string",
                    "required": True,
                }
            },
            "v_range": [["v7.0.0", ""]],
        },
        "ems_threat_feed": {
            "v_range": [["v7.0.0", ""]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "fortindr_error_action": {
            "v_range": [["v7.0.8", ""]],
            "type": "string",
            "options": [{"value": "log-only"}, {"value": "block"}, {"value": "ignore"}],
        },
        "fortindr_timeout_action": {
            "v_range": [["v7.0.8", ""]],
            "type": "string",
            "options": [{"value": "log-only"}, {"value": "block"}, {"value": "ignore"}],
        },
        "fortisandbox_error_action": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "log-only"}, {"value": "block"}, {"value": "ignore"}],
        },
        "fortisandbox_timeout_action": {
            "v_range": [["v7.2.0", ""]],
            "type": "string",
            "options": [{"value": "log-only"}, {"value": "block"}, {"value": "ignore"}],
        },
        "av_virus_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "extended_log": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "scan_mode": {
            "v_range": [["v6.0.0", ""]],
            "type": "string",
            "options": [
                {"value": "default", "v_range": [["v6.2.0", ""]]},
                {"value": "legacy", "v_range": [["v6.2.0", ""]]},
                {"value": "quick", "v_range": [["v6.0.0", "v6.0.11"]]},
                {"value": "full", "v_range": [["v6.0.0", "v6.0.11"]]},
            ],
        },
        "av_block_log": {
            "v_range": [["v6.0.0", "v7.2.4"]],
            "type": "string",
            "options": [{"value": "enable"}, {"value": "disable"}],
        },
        "ftgd_analytics": {
            "v_range": [["v6.0.0", "v7.0.12"]],
            "type": "string",
            "options": [
                {"value": "disable"},
                {"value": "suspicious"},
                {"value": "everything"},
            ],
        },
        "analytics_max_upload": {"v_range": [["v6.0.0", "v7.0.12"]], "type": "integer"},
        "fortiai_error_action": {
            "v_range": [["v7.0.1", "v7.0.7"]],
            "type": "string",
            "options": [{"value": "log-only"}, {"value": "block"}, {"value": "ignore"}],
        },
        "fortiai_timeout_action": {
            "v_range": [["v7.0.2", "v7.0.7"]],
            "type": "string",
            "options": [{"value": "log-only"}, {"value": "block"}, {"value": "ignore"}],
        },
        "external_blocklist_archive_scan": {
            "v_range": [["v7.0.0", "v7.0.0"]],
            "type": "string",
            "options": [{"value": "disable"}, {"value": "enable"}],
        },
        "analytics_wl_filetype": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
        "analytics_bl_filetype": {"v_range": [["v6.0.0", "v6.4.4"]], "type": "integer"},
        "outbreak_prevention": {
            "v_range": [["v6.2.0", "v6.4.4"]],
            "type": "dict",
            "children": {
                "ftgd_service": {
                    "v_range": [["v6.2.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
                "external_blocklist": {
                    "v_range": [["v6.2.0", "v6.4.4"]],
                    "type": "string",
                    "options": [{"value": "disable"}, {"value": "enable"}],
                },
            },
        },
        "inspection_mode": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "string",
            "options": [{"value": "proxy"}, {"value": "flow-based"}],
        },
        "smb": {
            "v_range": [["v6.0.0", "v6.0.11"]],
            "type": "dict",
            "children": {
                "options": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "scan"},
                        {"value": "avmonitor"},
                        {"value": "quarantine"},
                    ],
                },
                "archive_block": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "fileslimit"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                    ],
                },
                "archive_log": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "encrypted"},
                        {"value": "corrupted"},
                        {"value": "partiallycorrupted"},
                        {"value": "multipart"},
                        {"value": "nested"},
                        {"value": "mailbomb"},
                        {"value": "fileslimit"},
                        {"value": "timeout"},
                        {"value": "unhandled"},
                    ],
                },
                "emulator": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [{"value": "enable"}, {"value": "disable"}],
                },
                "outbreak_prevention": {
                    "v_range": [["v6.0.0", "v6.0.11"]],
                    "type": "string",
                    "options": [
                        {"value": "disabled"},
                        {"value": "files"},
                        {"value": "full-archive"},
                    ],
                },
            },
        },
    },
    "v_range": [["v6.0.0", ""]],
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "antivirus_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["antivirus_profile"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["antivirus_profile"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None
    diff = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "antivirus_profile"
        )

        is_error, has_changed, result, diff = fortios_antivirus(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
