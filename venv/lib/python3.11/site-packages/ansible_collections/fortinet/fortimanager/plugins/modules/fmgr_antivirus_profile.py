#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_antivirus_profile
short_description: Configure AntiVirus profiles.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    antivirus_profile:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            analytics_bl_filetype:
                aliases: ['analytics-bl-filetype']
                type: str
                description: Only submit files matching this DLP file-pattern to FortiSandbox.
            analytics_db:
                aliases: ['analytics-db']
                type: str
                description: Enable/disable using the FortiSandbox signature database to supplement the AV signature databases.
                choices:
                    - 'disable'
                    - 'enable'
            analytics_max_upload:
                aliases: ['analytics-max-upload']
                type: int
                description: Maximum size of files that can be uploaded to FortiSandbox
            analytics_wl_filetype:
                aliases: ['analytics-wl-filetype']
                type: str
                description: Do not submit files matching this DLP file-pattern to FortiSandbox.
            av_block_log:
                aliases: ['av-block-log']
                type: str
                description: Enable/disable logging for AntiVirus file blocking.
                choices:
                    - 'disable'
                    - 'enable'
            av_virus_log:
                aliases: ['av-virus-log']
                type: str
                description: Enable/disable AntiVirus logging.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            extended_log:
                aliases: ['extended-log']
                type: str
                description: Enable/disable extended logging for antivirus.
                choices:
                    - 'disable'
                    - 'enable'
            ftgd_analytics:
                aliases: ['ftgd-analytics']
                type: str
                description: Settings to control which files are uploaded to FortiSandbox.
                choices:
                    - 'disable'
                    - 'suspicious'
                    - 'everything'
            inspection_mode:
                aliases: ['inspection-mode']
                type: str
                description: Inspection mode.
                choices:
                    - 'proxy'
                    - 'flow-based'
            mobile_malware_db:
                aliases: ['mobile-malware-db']
                type: str
                description: Enable/disable using the mobile malware signature database.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Profile name.
                required: true
            replacemsg_group:
                aliases: ['replacemsg-group']
                type: str
                description: Replacement message group customized for this profile.
            scan_mode:
                aliases: ['scan-mode']
                type: str
                description: Choose between full scan mode and quick scan mode.
                choices:
                    - 'quick'
                    - 'full'
                    - 'legacy'
                    - 'default'
            feature_set:
                aliases: ['feature-set']
                type: str
                description: Flow/proxy feature set.
                choices:
                    - 'proxy'
                    - 'flow'
            cifs:
                type: dict
                description: Cifs.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable CIFS AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'quarantine'
                            - 'avmonitor'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            content_disarm:
                aliases: ['content-disarm']
                type: dict
                description: Content disarm.
                suboptions:
                    cover_page:
                        aliases: ['cover-page']
                        type: str
                        description: Enable/disable inserting a cover page into the disarmed document.
                        choices:
                            - 'disable'
                            - 'enable'
                    detect_only:
                        aliases: ['detect-only']
                        type: str
                        description: Enable/disable only detect disarmable files, do not alter content.
                        choices:
                            - 'disable'
                            - 'enable'
                    error_action:
                        aliases: ['error-action']
                        type: str
                        description: Action to be taken if CDR engine encounters an unrecoverable error.
                        choices:
                            - 'block'
                            - 'log-only'
                            - 'ignore'
                    office_action:
                        aliases: ['office-action']
                        type: str
                        description: Enable/disable stripping of PowerPoint action events in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office_dde:
                        aliases: ['office-dde']
                        type: str
                        description: Enable/disable stripping of Dynamic Data Exchange events in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office_embed:
                        aliases: ['office-embed']
                        type: str
                        description: Enable/disable stripping of embedded objects in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office_hylink:
                        aliases: ['office-hylink']
                        type: str
                        description: Enable/disable stripping of hyperlinks in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office_linked:
                        aliases: ['office-linked']
                        type: str
                        description: Enable/disable stripping of linked objects in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    office_macro:
                        aliases: ['office-macro']
                        type: str
                        description: Enable/disable stripping of macros in Microsoft Office documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    original_file_destination:
                        aliases: ['original-file-destination']
                        type: str
                        description: Destination to send original file if active content is removed.
                        choices:
                            - 'fortisandbox'
                            - 'quarantine'
                            - 'discard'
                    pdf_act_form:
                        aliases: ['pdf-act-form']
                        type: str
                        description: Enable/disable stripping of PDF document actions that submit data to other targets.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_gotor:
                        aliases: ['pdf-act-gotor']
                        type: str
                        description: Enable/disable stripping of PDF document actions that access other PDF documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_java:
                        aliases: ['pdf-act-java']
                        type: str
                        description: Enable/disable stripping of PDF document actions that execute JavaScript code.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_launch:
                        aliases: ['pdf-act-launch']
                        type: str
                        description: Enable/disable stripping of PDF document actions that launch other applications.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_movie:
                        aliases: ['pdf-act-movie']
                        type: str
                        description: Enable/disable stripping of PDF document actions that play a movie.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_act_sound:
                        aliases: ['pdf-act-sound']
                        type: str
                        description: Enable/disable stripping of PDF document actions that play a sound.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_embedfile:
                        aliases: ['pdf-embedfile']
                        type: str
                        description: Enable/disable stripping of embedded files in PDF documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_hyperlink:
                        aliases: ['pdf-hyperlink']
                        type: str
                        description: Enable/disable stripping of hyperlinks from PDF documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    pdf_javacode:
                        aliases: ['pdf-javacode']
                        type: str
                        description: Enable/disable stripping of JavaScript code in PDF documents.
                        choices:
                            - 'disable'
                            - 'enable'
                    analytics_suspicious:
                        aliases: ['analytics-suspicious']
                        type: str
                        description: Enable/disable using CDR as a secondary method for determining suspicous files for analytics.
                        choices:
                            - 'disable'
                            - 'enable'
            ftp:
                type: dict
                description: Ftp.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable FTP AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            http:
                type: dict
                description: Http.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    content_disarm:
                        aliases: ['content-disarm']
                        type: str
                        description: Enable Content Disarm and Reconstruction for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable HTTP AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                            - 'strict-file'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_optimize:
                        aliases: ['av-optimize']
                        type: str
                        description: Av optimize.
                        choices:
                            - 'disable'
                            - 'enable'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    unknown_content_encoding:
                        aliases: ['unknown-content-encoding']
                        type: str
                        description: Configure the action the FortiGate unit will take on unknown content-encoding.
                        choices:
                            - 'block'
                            - 'inspect'
                            - 'bypass'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            imap:
                type: dict
                description: Imap.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    content_disarm:
                        aliases: ['content-disarm']
                        type: str
                        description: Enable Content Disarm and Reconstruction for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable IMAP AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            mapi:
                type: dict
                description: Mapi.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable MAPI AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            nac_quar:
                aliases: ['nac-quar']
                type: dict
                description: Nac quar.
                suboptions:
                    expiry:
                        type: str
                        description: Duration of quarantine.
                    infected:
                        type: str
                        description: Enable/Disable quarantining infected hosts to the banned user list.
                        choices:
                            - 'none'
                            - 'quar-src-ip'
                            - 'quar-interface'
                    log:
                        type: str
                        description: Enable/disable AntiVirus quarantine logging.
                        choices:
                            - 'disable'
                            - 'enable'
            nntp:
                type: dict
                description: Nntp.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable NNTP AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            outbreak_prevention:
                aliases: ['outbreak-prevention']
                type: dict
                description: Outbreak prevention.
                suboptions:
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable/disable external malware blocklist.
                        choices:
                            - 'disable'
                            - 'enable'
                    ftgd_service:
                        aliases: ['ftgd-service']
                        type: str
                        description: Enable/disable FortiGuard Virus outbreak prevention service.
                        choices:
                            - 'disable'
                            - 'enable'
            pop3:
                type: dict
                description: Pop3.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    content_disarm:
                        aliases: ['content-disarm']
                        type: str
                        description: Enable Content Disarm and Reconstruction for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable POP3 AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            smtp:
                type: dict
                description: Smtp.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    content_disarm:
                        aliases: ['content-disarm']
                        type: str
                        description: Enable Content Disarm and Reconstruction for this protocol.
                        choices:
                            - 'disable'
                            - 'enable'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    executables:
                        type: str
                        description: Treat Windows executable files as viruses for the purpose of blocking or monitoring.
                        choices:
                            - 'default'
                            - 'virus'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable SMTP AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'file-filter'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            ssh:
                type: dict
                description: Ssh.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable SFTP and SCP AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'avmonitor'
                            - 'quarantine'
                            - 'scan'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    av_scan:
                        aliases: ['av-scan']
                        type: str
                        description: Enable AntiVirus scan service.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    external_blocklist:
                        aliases: ['external-blocklist']
                        type: str
                        description: Enable external-blocklist.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    quarantine:
                        type: str
                        description: Enable/disable quarantine for infected files.
                        choices:
                            - 'disable'
                            - 'enable'
                    fortindr:
                        type: str
                        description: Enable scanning of files by FortiNDR.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortisandbox:
                        type: str
                        description: Enable scanning of files by FortiSandbox.
                        choices:
                            - 'disable'
                            - 'block'
                            - 'monitor'
                    fortiai:
                        type: str
                        description: Enable/disable scanning of files by FortiAI.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
                    malware_stream:
                        aliases: ['malware-stream']
                        type: str
                        description: Enable 0-day malware-stream scanning.
                        choices:
                            - 'disable'
                            - 'monitor'
                            - 'block'
            smb:
                type: dict
                description: Smb.
                suboptions:
                    archive_block:
                        aliases: ['archive-block']
                        type: list
                        elements: str
                        description: Select the archive types to block.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    archive_log:
                        aliases: ['archive-log']
                        type: list
                        elements: str
                        description: Select the archive types to log.
                        choices:
                            - 'encrypted'
                            - 'corrupted'
                            - 'multipart'
                            - 'nested'
                            - 'mailbomb'
                            - 'unhandled'
                            - 'partiallycorrupted'
                            - 'fileslimit'
                            - 'timeout'
                    emulator:
                        type: str
                        description: Enable/disable the virus emulator.
                        choices:
                            - 'disable'
                            - 'enable'
                    options:
                        type: list
                        elements: str
                        description: Enable/disable SMB AntiVirus scanning, monitoring, and quarantine.
                        choices:
                            - 'scan'
                            - 'quarantine'
                            - 'avquery'
                            - 'avmonitor'
                    outbreak_prevention:
                        aliases: ['outbreak-prevention']
                        type: str
                        description: Enable FortiGuard Virus Outbreak Prevention service.
                        choices:
                            - 'disabled'
                            - 'files'
                            - 'full-archive'
            analytics_accept_filetype:
                aliases: ['analytics-accept-filetype']
                type: str
                description: Only submit files matching this DLP file-pattern to FortiSandbox.
            analytics_ignore_filetype:
                aliases: ['analytics-ignore-filetype']
                type: str
                description: Do not submit files matching this DLP file-pattern to FortiSandbox.
            ems_threat_feed:
                aliases: ['ems-threat-feed']
                type: str
                description: Enable/disable use of EMS threat feed when performing AntiVirus scan.
                choices:
                    - 'disable'
                    - 'enable'
            external_blocklist:
                aliases: ['external-blocklist']
                type: raw
                description: (list or str) One or more external malware block lists.
            external_blocklist_archive_scan:
                aliases: ['external-blocklist-archive-scan']
                type: str
                description: Enable/disable external-blocklist archive scanning.
                choices:
                    - 'disable'
                    - 'enable'
            external_blocklist_enable_all:
                aliases: ['external-blocklist-enable-all']
                type: str
                description: Enable/disable all external blocklists.
                choices:
                    - 'disable'
                    - 'enable'
            outbreak_prevention_archive_scan:
                aliases: ['outbreak-prevention-archive-scan']
                type: str
                description: Enable/disable outbreak-prevention archive scanning.
                choices:
                    - 'disable'
                    - 'enable'
            fortindr_error_action:
                aliases: ['fortindr-error-action']
                type: str
                description: Action to take if FortiNDR encounters an error.
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortindr_timeout_action:
                aliases: ['fortindr-timeout-action']
                type: str
                description: Action to take if FortiNDR encounters a scan timeout.
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortisandbox_error_action:
                aliases: ['fortisandbox-error-action']
                type: str
                description: Action to take if FortiSandbox inline scan encounters an error.
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortisandbox_max_upload:
                aliases: ['fortisandbox-max-upload']
                type: int
                description: Maximum size of files that can be uploaded to FortiSandbox.
            fortisandbox_mode:
                aliases: ['fortisandbox-mode']
                type: str
                description: FortiSandbox scan modes.
                choices:
                    - 'inline'
                    - 'analytics-suspicious'
                    - 'analytics-everything'
            fortisandbox_timeout_action:
                aliases: ['fortisandbox-timeout-action']
                type: str
                description: Action to take if FortiSandbox inline scan encounters a scan timeout.
                choices:
                    - 'log-only'
                    - 'block'
                    - 'ignore'
            fortiai_error_action:
                aliases: ['fortiai-error-action']
                type: str
                description: Action to take if FortiAI encounters an error.
                choices:
                    - 'block'
                    - 'log-only'
                    - 'ignore'
            fortiai_timeout_action:
                aliases: ['fortiai-timeout-action']
                type: str
                description: Action to take if FortiAI encounters a scan timeout.
                choices:
                    - 'block'
                    - 'log-only'
                    - 'ignore'
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure AntiVirus profiles.
      fortinet.fortimanager.fmgr_antivirus_profile:
        adom: ansible
        state: present
        antivirus_profile:
          analytics_db: disable
          analytics_max_upload: 20
          av_block_log: disable
          av_virus_log: disable
          comment: "test comment"
          extended_log: disable
          ftgd_analytics: disable
          inspection_mode: proxy
          mobile_malware_db: disable
          name: "antivirus-profile"
          scan_mode: quick

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the antivirus profiles
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "antivirus_profile"
          params:
            adom: "ansible"
            profile: "your_value"
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/antivirus/profile',
        '/pm/config/global/obj/antivirus/profile'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'antivirus_profile': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'analytics-bl-filetype': {'type': 'str'},
                'analytics-db': {'choices': ['disable', 'enable'], 'type': 'str'},
                'analytics-max-upload': {'type': 'int'},
                'analytics-wl-filetype': {'type': 'str'},
                'av-block-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'av-virus-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'comment': {'type': 'str'},
                'extended-log': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ftgd-analytics': {'choices': ['disable', 'suspicious', 'everything'], 'type': 'str'},
                'inspection-mode': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['proxy', 'flow-based'], 'type': 'str'},
                'mobile-malware-db': {'choices': ['disable', 'enable'], 'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'replacemsg-group': {'type': 'str'},
                'scan-mode': {'choices': ['quick', 'full', 'legacy', 'default'], 'type': 'str'},
                'feature-set': {'v_range': [['6.4.0', '']], 'choices': ['proxy', 'flow'], 'type': 'str'},
                'cifs': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avmonitor'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'content-disarm': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'cover-page': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'detect-only': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'error-action': {'v_range': [['6.4.5', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'},
                        'office-action': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-dde': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-embed': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-hylink': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-linked': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'office-macro': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'original-file-destination': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['fortisandbox', 'quarantine', 'discard'],
                            'type': 'str'
                        },
                        'pdf-act-form': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-gotor': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-java': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-launch': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-movie': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-act-sound': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-embedfile': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-hyperlink': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'pdf-javacode': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'analytics-suspicious': {'v_range': [['7.4.7', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'ftp': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['scan', 'file-filter', 'quarantine', 'avquery', 'avmonitor'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'http': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'content-disarm': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['scan', 'file-filter', 'quarantine', 'avquery', 'avmonitor', 'strict-file'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-optimize': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.6.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'unknown-content-encoding': {
                            'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']],
                            'choices': ['block', 'inspect', 'bypass'],
                            'type': 'str'
                        },
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'imap': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'content-disarm': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'executables': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['scan', 'file-filter', 'quarantine', 'avquery', 'avmonitor'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'mapi': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'executables': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avquery', 'avmonitor'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'nac-quar': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'expiry': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'type': 'str'},
                        'infected': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['none', 'quar-src-ip', 'quar-interface'], 'type': 'str'},
                        'log': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'nntp': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['scan', 'file-filter', 'quarantine', 'avquery', 'avmonitor'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'outbreak-prevention': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'external-blocklist': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'ftgd-service': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    }
                },
                'pop3': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'content-disarm': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'executables': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['scan', 'file-filter', 'quarantine', 'avquery', 'avmonitor'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'smtp': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'content-disarm': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'executables': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['default', 'virus'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['scan', 'file-filter', 'quarantine', 'avquery', 'avmonitor'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'ssh': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'type': 'list',
                            'choices': ['avmonitor', 'quarantine', 'scan'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '']],
                            'choices': ['disabled', 'files', 'full-archive', 'disable', 'block', 'monitor'],
                            'type': 'str'
                        },
                        'av-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'external-blocklist': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'quarantine': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'fortindr': {'v_range': [['7.0.5', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortisandbox': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                        'fortiai': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'},
                        'malware-stream': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'monitor', 'block'], 'type': 'str'}
                    }
                },
                'smb': {
                    'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                    'type': 'dict',
                    'options': {
                        'archive-block': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'archive-log': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'type': 'list',
                            'choices': [
                                'encrypted', 'corrupted', 'multipart', 'nested', 'mailbomb', 'unhandled', 'partiallycorrupted', 'fileslimit', 'timeout'
                            ],
                            'elements': 'str'
                        },
                        'emulator': {'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'options': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'type': 'list',
                            'choices': ['scan', 'quarantine', 'avquery', 'avmonitor'],
                            'elements': 'str'
                        },
                        'outbreak-prevention': {
                            'v_range': [['6.2.8', '6.2.13'], ['6.4.5', '7.2.1']],
                            'choices': ['disabled', 'files', 'full-archive'],
                            'type': 'str'
                        }
                    }
                },
                'analytics-accept-filetype': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'analytics-ignore-filetype': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'ems-threat-feed': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'external-blocklist': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'external-blocklist-archive-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'external-blocklist-enable-all': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'outbreak-prevention-archive-scan': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fortindr-error-action': {'v_range': [['7.0.5', '']], 'choices': ['log-only', 'block', 'ignore'], 'type': 'str'},
                'fortindr-timeout-action': {'v_range': [['7.0.5', '']], 'choices': ['log-only', 'block', 'ignore'], 'type': 'str'},
                'fortisandbox-error-action': {'v_range': [['7.2.0', '']], 'choices': ['log-only', 'block', 'ignore'], 'type': 'str'},
                'fortisandbox-max-upload': {'v_range': [['7.2.0', '']], 'type': 'int'},
                'fortisandbox-mode': {'v_range': [['7.2.0', '']], 'choices': ['inline', 'analytics-suspicious', 'analytics-everything'], 'type': 'str'},
                'fortisandbox-timeout-action': {'v_range': [['7.2.0', '']], 'choices': ['log-only', 'block', 'ignore'], 'type': 'str'},
                'fortiai-error-action': {'v_range': [['7.0.1', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'},
                'fortiai-timeout-action': {'v_range': [['7.0.2', '']], 'choices': ['block', 'log-only', 'ignore'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'antivirus_profile'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
