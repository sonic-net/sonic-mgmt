from functools import wraps


def ignore_loganalyzer(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        """
        try to fetch loganalyzer instances from kwargs:
        if ignore_loganalyzer is not passed, do nothing but execute the decorated function.
        if ignore_loganalyzer is passed, to avoid 'unexpected keyword argument error',
            delete the ignore_loganalyzer from kwargs so that it would not be passed to the decorated function,
            and set ignore_loganalyzer markers before and after the decorated function on all log analyzer instances.
        """

        loganalyzer = None
        if 'ignore_loganalyzer' in kwargs and kwargs['ignore_loganalyzer'] is not None:
            loganalyzer = kwargs['ignore_loganalyzer']
            kwargs.pop('ignore_loganalyzer')

        if loganalyzer:
            for _, dut_loganalyzer in loganalyzer.items():
                dut_loganalyzer.add_start_ignore_mark()

        res = func(*args, **kwargs)

        if loganalyzer:
            for _, dut_loganalyzer in loganalyzer.items():
                dut_loganalyzer.add_end_ignore_mark()

        return res

    return decorated
