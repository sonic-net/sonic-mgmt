
def skip_loganalyzer_bug_handler(duthost, request):
    """
    return True if the bug handler will be skipped.
    User could implement their own logic here.
    """
    return True


def log_analyzer_bug_handler(duthost, request):
    """
    If the not skip bug handler after the loganalyzer, run this function to handle the err msg detected in the
    loganalyzer.
    User could implement their own logic here.
    """
    pass
