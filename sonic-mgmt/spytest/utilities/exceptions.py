
class SPyTestCmdException(RuntimeError):
    def __init__(self, message):
        message = "Command Exception: {}".format(str(message))
        super(SPyTestCmdException, self).__init__(message)

class SPyTestException(RuntimeError):
    def __init__(self, message):
        message = "Runtime Exception: {}".format(str(message))
        super(SPyTestException, self).__init__(message)

class DeviceConnectionError(SPyTestException):
    pass

class DeviceConnectionTimeout(SPyTestException):
    pass

class DeviceAuthenticationFailure(SPyTestException):
    pass

class DeviceNotConnectedError(SPyTestException):
    pass

class DeviceConnectionLostError(SPyTestException):
    pass

class CircularDependencyError(SPyTestException):
    pass

class XpathError(SPyTestException):
    pass
