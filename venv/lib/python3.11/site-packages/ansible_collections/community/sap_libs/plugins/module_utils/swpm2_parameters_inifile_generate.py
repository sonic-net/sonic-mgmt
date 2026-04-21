#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Sean Freeman ,
#                      Rainer Leber <rainerleber@gmail.com> <rainer.leber@sva.de>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils.basic import missing_required_lib
import traceback
import sys
import os


BS4_LIBRARY_IMPORT_ERROR = None
try:
    from bs4 import BeautifulSoup
except ImportError:
    BS4_LIBRARY_IMPORT_ERROR = traceback.format_exc()
    HAS_BS4_LIBRARY = False
else:
    HAS_BS4_LIBRARY = True

LXML_LIBRARY_IMPORT_ERROR = None
try:
    from lxml import etree
except ImportError:
    LXML_LIBRARY_IMPORT_ERROR = traceback.format_exc()
    HAS_LXML_LIBRARY = False
else:
    HAS_LXML_LIBRARY = True


def debug_bs4(module):
    # Diagnose XML file parsing errors in Beautiful Soup
    # https://stackoverflow.com/questions/56942892/cannot-parse-iso-8859-15-encoded-xml-with-bs4/56947172#56947172
    if not HAS_BS4_LIBRARY:
        module.fail_json(msg=missing_required_lib(
            "bs4"), exception=BS4_LIBRARY_IMPORT_ERROR)
    from bs4.diagnose import diagnose
    with open('control.xml', 'rb') as f:
        diagnose(f)


# SWPM2 control.xml conversion to utf8
def control_xml_utf8(filepath, module):
    if not HAS_LXML_LIBRARY:
        module.fail_json(msg=missing_required_lib(
            "lxml"), exception=LXML_LIBRARY_IMPORT_ERROR)
    source = filepath + "/control.xml"

    # Convert control.xml from iso-8859-1 to UTF-8, so it can be used with Beautiful Soup lxml-xml parser
    # https://stackoverflow.com/questions/64629600/how-can-you-convert-a-xml-iso-8859-1-to-utf-8-using-python-3-7-7/64634454#64634454
    with open(source, 'rb') as source:
        parser = etree.XMLParser(encoding="iso-8859-1", strip_cdata=False)
        root = etree.parse(source, parser)

    string = etree.tostring(root, xml_declaration=True, encoding="UTF-8",
                            pretty_print=True).decode('utf8').encode('iso-8859-1')

#    string1 = etree.tostring(root, xml_declaration=True, encoding="UTF-8",
#                            pretty_print=True).decode('utf8').encode('utf-8').strip()

    with open('control_utf8.xml', 'wb') as target:
        target.write(string)


# SWPM2 Component and Parameters extract all as CSV
def control_xml_to_csv(filepath, module):
    if not HAS_BS4_LIBRARY:
        module.fail_json(msg=missing_required_lib(
            "bs4"), exception=BS4_LIBRARY_IMPORT_ERROR)

    infile = open(filepath + "/control_utf8.xml", "r")
    contents = infile.read()

    soup = BeautifulSoup(markup=contents, features='lxml-xml')
    space = soup.find('components')

    component_list = space.findChildren("component", recursive=False)

    csv_output = open('control_output.csv', 'w')
    csv_header = '"' + 'Component Name' + '","' + 'Component Display Name' + '","' + 'Parameter Name' + '","' + 'Parameter Inifile Key' + \
        '","' + 'Parameter Access' + '","' + 'Parameter Encode' + '","' + \
        'Parameter Default Value' + '","' + 'Parameter Inifile description' + '"'
    csv_output.write("%s\n" % csv_header)

    for component in component_list:
        for parameter in component.findChildren("parameter"):
            component_key = parameter.findParent("component")
            component_key_name_text = component_key["name"]
            for child in component_key.findChildren("display-name"):
                component_key_display_name_text = child.get_text().replace('\n', '')
            component_parameter_key_name = parameter["name"]
            component_parameter_key_inifile_name = parameter.get(
                "defval-for-inifile-generation", "")
            component_parameter_key_access = parameter.get("access", "")
            component_parameter_key_encode = parameter.get("encode", "")
            component_parameter_key_defval = parameter.get("defval", "")
            component_parameter_contents_doclong_text = parameter.get_text().replace('\n', '')
            component_parameter_contents_doclong_text_quote_replacement = component_parameter_contents_doclong_text.replace(
                '"', '\'')
            csv_string = '"' + component_key_name_text + '","' + component_key_display_name_text + '","' + \
                component_parameter_key_name + '","' + component_parameter_key_inifile_name + '","' + \
                component_parameter_key_access + '","' + component_parameter_key_encode + '","' + \
                component_parameter_key_defval + '","' + \
                component_parameter_contents_doclong_text_quote_replacement + '"'
            csv_output.write("%s\n" % csv_string)

    csv_output.close()


# SWPM2 Component and Parameters extract all and generate template inifile.params
def control_xml_to_inifile_params(filepath, module):
    if not HAS_BS4_LIBRARY:
        module.fail_json(msg=missing_required_lib(
            "bs4"), exception=BS4_LIBRARY_IMPORT_ERROR)

    infile = open(filepath + "/control_utf8.xml", "r")
    contents = infile.read()

    soup = BeautifulSoup(markup=contents, features='lxml-xml')
    space = soup.find('components')

    component_list = space.findChildren("component", recursive=False)

    inifile_output = open('generated_inifile_params', 'w')

    inifile_params_header = """############
    # SWPM Unattended Parameters inifile.params generated export
    #
    #
    # Export of all SWPM Component and the SWPM Unattended Parameters. Not all components have SWPM Unattended Parameters.
    #
    # All parameters are commented-out, each hash # before the parameter is removed to activate the parameter.
    # When running SWPM in Unattended Mode, the activated parameters will create a new SWPM file in the sapinst directory.
    # If any parameter is marked as 'encode', the plaintext value will be coverted to DES hash
    # for this parameter in the new SWPM file (in the sapinst directory).
    #
    # An inifile.params is otherwise obtained after running SWPM as GUI or Unattended install,
    # and will be generated for a specific Product ID (such as 'NW_ABAP_OneHost:S4HANA1809.CORE.HDB.CP').
    ############



    ############
    # MANUAL
    ############

    # The folder containing all archives that have been downloaded from http://support.sap.com/swdc and are supposed to be used in this procedure
    # archives.downloadBasket =
    """

    inifile_output.write(inifile_params_header)

    for component in component_list:
        component_key_name_text = component["name"]
        component_key_display_name = component.find("display-name")
        if component_key_display_name is not None:
            component_key_display_name_text = component_key_display_name.get_text()
        inifile_output.write("\n\n\n\n############\n# Component: %s\n# Component Display Name: %s\n############\n" % (
            component_key_name_text, component_key_display_name_text))
        for parameter in component.findChildren("parameter"):
            #            component_key=parameter.findParent("component")
            component_parameter_key_encode = parameter.get("encode", None)
            component_parameter_key_inifile_name = parameter.get(
                "defval-for-inifile-generation", None)
            component_parameter_key_defval = parameter.get("defval", "")
            component_parameter_contents_doclong_text = parameter.get_text().replace('\n', '')
#            component_parameter_contents_doclong_text_quote_replacement=component_parameter_contents_doclong_text.replace('"','\'')
            if component_parameter_key_inifile_name is not None:
                inifile_output.write("\n# %s" % (
                    component_parameter_contents_doclong_text))
                if component_parameter_key_encode == "true":
                    inifile_output.write(
                        "\n# Encoded parameter. Plaintext values will be coverted to DES hash")
                inifile_output.write("\n# %s = %s\n" % (
                    component_parameter_key_inifile_name, component_parameter_key_defval))

    inifile_output.close()

# SWPM2 product.catalog conversion to utf8


def product_catalog_xml_utf8(filepath, module):
    if not HAS_LXML_LIBRARY:
        module.fail_json(msg=missing_required_lib(
            "lxml"), exception=LXML_LIBRARY_IMPORT_ERROR)

    source = filepath + "/product.catalog"

    # Convert control.xml from iso-8859-1 to UTF-8, so it can be used with Beautiful Soup lxml-xml parser
    # https://stackoverflow.com/questions/64629600/how-can-you-convert-a-xml-iso-8859-1-to-utf-8-using-python-3-7-7/64634454#64634454
    with open(source, 'rb') as source:
        parser = etree.XMLParser(encoding="iso-8859-1", strip_cdata=False)
        root = etree.parse(source, parser)

    string = etree.tostring(root, xml_declaration=True, encoding="UTF-8",
                            pretty_print=True).decode('utf8').encode('iso-8859-1')

    with open('product_catalog_utf8.xml', 'wb') as target:
        target.write(string)

# SWPM2 Product Catalog entries to CSV
# Each Product Catalog entry is part of a components group, which may have attributes:
# output-dir, control-file, product-dir (link to SWPM directory of param file etc)
# Attributes possible for each entry = control-file, db, id, name, os, os-type, output-dir,
# ppms-component, ppms-component-release, product, product-dir, release, table


def product_catalog_xml_to_csv(filepath, module):
    if not HAS_BS4_LIBRARY:
        module.fail_json(msg=missing_required_lib(
            "bs4"), exception=BS4_LIBRARY_IMPORT_ERROR)

    infile = open(filepath + "/product_catalog_utf8.xml", "r")
    contents = infile.read()

    soup = BeautifulSoup(markup=contents, features='lxml-xml')
    space = soup.find_all('component')

    csv_output = open('product_catalog_output.csv', 'w')
    csv_header = '"' + 'Product Catalog Component Name' + '","' + 'Product Catalog Component ID' + '","' + 'Product Catalog Component Table' + '","' + \
        'Product Catalog Component Output Dir' + '","' + 'Product Catalog Component Display Name' + \
        '","' + 'Product Catalog Component UserInfo' + '"'
    csv_output.write("%s\n" % csv_header)

    for component in space:
        component_name = component.get("name", "")
        component_id = component.get("id", "")
        component_table = component.get("table", "")
        component_output_dir = component.get("output-dir", "")
        for displayname in component.findChildren("display-name"):
            component_displayname = displayname.get_text().strip()
        for userinfo in component.findChildren("user-info"):
            html_raw = userinfo.get_text().strip()
            html_parsed = BeautifulSoup(html_raw, 'html.parser')
            component_userinfo = html_parsed.get_text().replace('"', '\'')
        csv_string = '"' + component_name + '","' + component_id + '","' + component_table + '","' + \
            component_output_dir + '","' + component_displayname + \
            '","' + component_userinfo + '"'
        csv_output.write("%s\n" % csv_string)

    csv_output.close()


# Get arguments passed to Python script session
# Define path to control.xml, else assume in /tmp directory

if len(sys.argv) > 1:
    control_xml_path = sys.argv[1]
else:
    control_xml_path = "/tmp"

if control_xml_path == "":
    control_xml_path = os.getcwd()

if os.path.exists(control_xml_path + '/control.xml'):
    control_xml_utf8(control_xml_path, '')
    control_xml_to_csv(control_xml_path, '')
    control_xml_to_inifile_params(control_xml_path, '')
