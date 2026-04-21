import inspect
import os.path

try:
    from ..common.hv_log import Log
except ImportError:
    from common.hv_log import Log

from functools import wraps

logger = Log()


class LogDecorator:
    """Class containing logging functionalities and decorators."""

    @staticmethod
    def log(message):
        # Get the caller frame from the stack
        caller_frame = inspect.stack()[2]

        # Extract filename and line number
        filename = os.path.basename(caller_frame.filename)
        line_number = caller_frame.lineno

        # Get the method or function name from the caller frame
        method_name = caller_frame.function

        # Log the message
        logger.writeDebug(
            f"{filename}:{LogDecorator.__name__}.{method_name}:[{line_number}] {message}"
        )

    @staticmethod
    def truncate_string(s, length):
        return (s[:length] + "...") if len(s) > length else s

    @classmethod
    def debug_methods(cls, target_class):
        """Class decorator to add logging to all methods of the target class."""

        def loggable_method(func):
            @wraps(func)
            def wrapper(self, *args, **kwargs):
                self._current_method = func.__name__
                arg_list = [repr(a) for a in args]
                arg_list += [f"{k}={v!r}" for k, v in kwargs.items()]
                LogDecorator.log(f"ENTER: Params:({', '.join(arg_list)})")

                result = func(self, *args, **kwargs)

                if isinstance(result, bytes):
                    LogDecorator.log(
                        "EXIT: Result is a bytes object and cannot be logged."
                    )
                elif isinstance(result, str):
                    max_chars = 1000
                    if len(result) > max_chars:
                        result = LogDecorator.truncate_string(result, max_chars)
                        LogDecorator.log("EXIT: Result:   .....truncated")
                    LogDecorator.log("EXIT:")
                else:
                    LogDecorator.log("EXIT: ")
                return result

            return wrapper

        for attribute_name, attribute in vars(target_class).items():
            if callable(attribute) and not attribute_name.startswith("__"):
                setattr(target_class, attribute_name, loggable_method(attribute))
        return target_class
