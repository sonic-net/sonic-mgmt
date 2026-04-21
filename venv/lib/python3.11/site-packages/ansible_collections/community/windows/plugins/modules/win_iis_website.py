#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Henrik Wallström <henrik@wallstroms.nu>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_iis_website
short_description: Configures a IIS Web site
description:
     - Creates, Removes and configures a IIS Web site.
deprecated:
    removed_in: 4.0.0
    why: >-
      This module has been deprecated and an alternative supported module is available in the C(microsoft.iis) collection.
    alternative: Use C(microsoft.iis.website) instead.
options:
  name:
    description:
      - Names of web site.
    type: str
    required: yes
  site_id:
    description:
      - Explicitly set the IIS numeric ID for a site.
      - Note that this value cannot be changed after the website has been created.
    type: str
  state:
    description:
      - State of the web site
    type: str
    choices: [ absent, started, stopped, restarted ]
  physical_path:
    description:
      - The physical path on the remote host to use for the new site.
      - The specified folder must already exist.
    type: str
  application_pool:
    description:
      - The application pool in which the new site executes.
    type: str
  port:
    description:
      - The port to bind to / use for the new site.
    type: int
  ip:
    description:
      - The IP address to bind to / use for the new site.
    type: str
  hostname:
    description:
      - The host header to bind to / use for the new site.
    type: str
  parameters:
    description:
      - Custom site Parameters from string where properties are separated by a pipe and property name/values by colon Ex. "foo:1|bar:2"
      - Some custom parameters that you can use are listed below, this isn't a definitive list but some common parameters.
      - C(logfile.directory) - Physical path to store Logs, e.g. C(D:\IIS-LOGs\).
      - C(logfile.period) - Log file rollover scheduled accepting these values, how frequently the log file should be rolled-over,
        e.g. C(Hourly, Daily, Weekly, Monthly).
      - C(logfile.LogFormat) - Log file format, by default IIS uses C(W3C).
      - C(logfile.truncateSize) - The size at which the log file contents will be trunsted, expressed in bytes.
    type: str
seealso:
- module: community.windows.win_iis_virtualdirectory
- module: community.windows.win_iis_webapplication
- module: community.windows.win_iis_webapppool
- module: community.windows.win_iis_webbinding
author:
- Henrik Wallström (@henrikwallstrom)
'''

EXAMPLES = r'''

# Start a website

- name: Acme IIS site
  community.windows.win_iis_website:
    name: Acme
    state: started
    port: 80
    ip: 127.0.0.1
    hostname: acme.local
    application_pool: acme
    physical_path: C:\sites\acme
    parameters: logfile.directory:C:\sites\logs
  register: website

# Remove Default Web Site and the standard port 80 binding
- name: Remove Default Web Site
  community.windows.win_iis_website:
    name: "Default Web Site"
    state: absent

# Create a WebSite with custom Logging configuration (Logs Location, Format and Rolling Over).

- name: Creating WebSite with Custom Log location, Format 3WC and rolling over every hour.
  community.windows.win_iis_website:
    name: MyCustom_Web_Shop_Site
    state: started
    port: 80
    ip: '*'
    hostname: '*'
    physical_path: D:\wwwroot\websites\my-shop-site
    parameters: logfile.directory:D:\IIS-LOGS\websites\my-shop-site|logfile.period:Hourly|logFile.logFormat:W3C
    application_pool: my-shop-site

# Some commandline examples:

# This return information about an existing host
# $ ansible -i vagrant-inventory -m community.windows.win_iis_website -a "name='Default Web Site'" window
# host | success >> {
#     "changed": false,
#     "site": {
#         "ApplicationPool": "DefaultAppPool",
#         "Bindings": [
#             "*:80:"
#         ],
#         "ID": 1,
#         "Name": "Default Web Site",
#         "PhysicalPath": "%SystemDrive%\\inetpub\\wwwroot",
#         "State": "Stopped"
#     }
# }

# This stops an existing site.
# $ ansible -i hosts -m community.windows.win_iis_website -a "name='Default Web Site' state=stopped" host

# This creates a new site.
# $ ansible -i hosts -m community.windows.win_iis_website -a "name=acme physical_path=C:\\sites\\acme" host

# Change logfile.
# $ ansible -i hosts -m community.windows.win_iis_website -a "name=acme physical_path=C:\\sites\\acme" host
'''
