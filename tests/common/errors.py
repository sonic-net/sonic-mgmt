"""
Customize exceptions
"""
class UnsupportedAnsibleModule(Exception):
    pass

class RunAnsibleModuleFail(Exception):
    pass
