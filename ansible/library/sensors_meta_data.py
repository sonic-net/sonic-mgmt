#!/usr/bin/python

from __future__ import print_function
from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: sensors_meta_data
version_added:
author: Praveen Chaudhary (pchaudhary@linkedin.com)
short description: Generate file with sensors meta data which can be used with
sensors test suite. Without this module user has to go through tedious process
for creating this Meta data manually.

description:
    - sensors_raw input dictionary defines fields which will be part of sonic
      meta data.
    - create a predefined format similar to file sku-sensors-data.yml for result
      dictionary.
    - fill result dictionary with complete key string on basis of keys in
      sensors_facts.
    - write all non-classifiable strings in [others] keys.
    - write output in file with same format as file sku-sensors-data.yml

Post work items:
    - Manually classify string listed in [others]
    - paste the data in sku-sensors-data.yml to use it for sensors test suite
'''

EXAMPLES = '''
 - name: create sensors meta data file
    sensors_meta_data: sensors_raw={{ sensors['raw'] }} file={{ file }} hwsku={{ hwsku }}
    connection: local
    register: sensors_metadata
'''

class SensorsMetaData(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
              sensors_raw=dict(required=True, type='dict'),
              file_name =dict(required=True, type='str'),
              hwsku=dict(required=True, type='str'),
            ),
            supports_check_mode=True)

        self.rawDict = self.module.params['sensors_raw']
        self.file    = self.module.params['file_name']
        self.hwsku   = self.module.params['hwsku']
        self.sensorsMetaData  = {self.hwsku: {}}
        self.facts   =  {'sensors_meta_data': self.sensorsMetaData}

        return

    def run(self):
        """
            Main method of the class

        """
        self.init()

        keyStr=""
        for key in self.rawDict.keys():
            keyStr = (key+"/")
            self.generateSensorsMetaData(self.rawDict[key],
                self.sensorsMetaData[self.hwsku], keyStr)

        # print resultant dictionary in the file
        with open(self.file,'w') as outputFile:
            self.writeResultInFile(self.sensorsMetaData, "  ", outputFile)

        self.module.exit_json(ansible_facts=self.facts)

        return

    def fillDictResultAlarms(self, keyStr, subResult):
        """
            fill Alarms section of result
        """

        if "fan" in keyStr:
            subResult["alarms"]["fan"].append(keyStr)
        elif "cpu" in keyStr or "CPU" in keyStr or "Psu" in keyStr:
            subResult["alarms"]["power"].append(keyStr)
        elif "temp" in keyStr:
            subResult["alarms"]["temp"].append(keyStr)
        else:
            subResult["alarms"]["power"].append(keyStr)

        return

    def findDictKeyFromStr(self, keyStr):
        '''
            find key for compare section by string parsing
        '''

        if "fan" in keyStr:
            dictKey = "fan"
        elif "cpu" in keyStr or "CPU" in keyStr or "Psu" in keyStr:
            dictKey = "power"
        elif "temp" in keyStr:
            dictKey = "temp"
        else:
            dictKey = "power"

        return dictKey

    def fillCompares(self, keyStr, compareStr, subResult, dictKey):
        '''
            fill compares section of result
        '''
        keyStr     = "- " + keyStr
        compareStr = "  " + compareStr
        subResult["compares"][dictKey].append(keyStr)
        subResult["compares"][dictKey].append(compareStr)

        return

    def fillDictResultCompares(self, keyStr, subResult, rawDict):
        '''
            find compare string and fill compares section
        '''
        compareStr = ""
        for keys in rawDict.keys():
                if "input" in keys:
                    idx = keyStr.rfind("/")
                    compareStr =  keyStr[0:idx+1]
                    compareStr += keys

        if compareStr == "":
            # no input item in this dict"
            subResult["others"].append(keyStr)
            return

        dictKey = self.findDictKeyFromStr(keyStr)

        if "min" in keyStr or "lcrit" in keyStr:
            self.fillCompares(keyStr, compareStr, subResult, dictKey)
        else:
            self.fillCompares(compareStr, keyStr, subResult, dictKey)

        return

    def fillDictResult(self, keyStr, subResult, rawDict):
        '''
            find relavent section of result to fill
        '''

        keyStr = "- " + keyStr

        if "alarm" in keyStr or "fault" in keyStr:
            self.fillDictResultAlarms(keyStr, subResult)

        elif "crit" in keyStr or "max" in keyStr or "min" in keyStr:
            self.fillDictResultCompares(keyStr, subResult, rawDict)

        elif "input" in keyStr:
            dictKey = self.findDictKeyFromStr(keyStr)
            subResult["non-zero"][dictKey].append(keyStr)
        else:
            subResult["others"].append(keyStr)

        return

    def generateSensorsMetaData(self, rawDict, subResult, keyStr):
        '''
            generate key strings meta data from sensors_raw by parsing it
            recursively
        '''

        for keys in rawDict.keys():

            if type(rawDict[keys]) == type(rawDict):
                newStr = keyStr + (keys+"/")
                self.generateSensorsMetaData(rawDict[keys], subResult, newStr)

            else:
                newStr = keyStr + keys
                self.fillDictResult(newStr, subResult, rawDict)
        return

    def writeResultInFile(self, result, tabStr, outputFile):
        '''
            print result dictionary recursively in outputfile
        '''
        for keys in result.keys():
            print(tabStr, end="", file=outputFile)

            if type(result[keys]) == type(result):
                print("{}:".format(keys), file=outputFile)
                self.writeResultInFile(result[keys], "  " + tabStr, outputFile)

            else: # it is a list of string
                if len(result[keys]) == 0:
                    print("{}:".format(keys), end="", file=outputFile)
                    print(" []", file=outputFile)
                else:
                    print("{}:".format(keys), file=outputFile)
                    for item in result[keys]:
                        print(tabStr, end="", file=outputFile)
                        print(item, file=outputFile)
        return

    def init(self):
        '''
            create skelaton of result dictionary
        '''
        sensorsDict = self.sensorsMetaData[self.hwsku]

        sensorsDict["alarms"] = dict()
        sensorsDict["compares"] = dict()
        sensorsDict["non-zero"] = dict()
        sensorsDict["psu_skips"] = dict()
        sensorsDict["others"] = list()

        sensorsDict["alarms"]["fan"] = list()
        sensorsDict["alarms"]["power"] = list()
        sensorsDict["alarms"]["temp"] = list()

        sensorsDict["compares"]["fan"] = list()
        sensorsDict["compares"]["power"] = list()
        sensorsDict["compares"]["temp"] = list()

        sensorsDict["non-zero"]["fan"] = list()
        sensorsDict["non-zero"]["power"] = list()
        sensorsDict["non-zero"]["temp"] = list()

        return

def main():
    sensorsMetaData = SensorsMetaData()
    sensorsMetaData.run()

    return

if __name__ == "__main__":
    main()
