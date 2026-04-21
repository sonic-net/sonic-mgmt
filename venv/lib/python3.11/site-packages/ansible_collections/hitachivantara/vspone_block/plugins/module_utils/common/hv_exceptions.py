from .hv_log import Log


class HiException0(Exception):

    pass


class HiException(Exception):

    def format(self):
        result = {}
        result["ErrorMessage"] = self.errorMessage
        result["MessageID"] = self.messageId
        return result

    def __init__(self, arg1=None, arg2=None):

        self.logger = Log()
        self.messageId = "E0000000"
        self.errorMessage = ""
        self.parentException = None
        self.arg1 = arg1
        self.arg2 = arg2

        if isinstance(arg1, Exception):

            self.message = arg1.message
            arg = arg1.message
            if "ErrorMessage" in arg:
                self.errorMessage = arg["ErrorMessage"]
            if "MessageID" in arg:
                self.messageId = arg["MessageID"]

        if isinstance(arg1, dict):
            if "ErrorMessage" in arg1:
                self.errorMessage = arg1["ErrorMessage"]
            if "MessageID" in arg1:
                self.messageId = arg1["MessageID"]


class HiException2(Exception):

    def __init__(self, arg1=None, arg2=None):
        self.logger = Log()
        self.logger.writeInfo("HiException.init")
        self.messageId = "E0000000"
        self.parentException = None
        self.arg1 = arg1
        self.arg2 = arg2

        if isinstance(arg1, Exception):
            self.logger.writeInfo("Exception")
            self.parentException = arg1
            hiJsonException = arg1.args[0]
            if isinstance(hiJsonException, dict):
                if "ErrorMessage" in hiJsonException:
                    super().message = arg1.args[0]["ErrorMessage"]
                if "MessageID" in hiJsonException:
                    self.messageId = arg1.args[0]["MessageID"]
            elif isinstance(hiJsonException, str):
                super().message = hiJsonException
        elif isinstance(arg1, tuple):
            self.logger.writeInfo("tuple")
            hiJsonException = arg1.args[0]
            if isinstance(hiJsonException, dict):
                if "ErrorMessage" in hiJsonException:
                    super().message = arg1.args[0]["ErrorMessage"]
                if "MessageID" in hiJsonException:
                    self.messageId = arg1.args[0]["MessageID"]
            elif isinstance(hiJsonException, str):
                super().message = hiJsonException


class HTTPException(Exception):
    """Exception raised for all HTTP errors."""

    def __init__(self, message="HTTP error occurred.", status_code=None):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

    def __str__(self):
        if self.status_code:
            return f"{self.message} (Status Code: {self.status_code})"
        else:
            return self.message


class ValidationException(Exception):
    """Exception raised for validation errors."""

    def __init__(self, message="Validation error occurred."):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return self.message
