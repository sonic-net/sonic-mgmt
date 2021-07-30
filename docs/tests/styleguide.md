# Software for Open Networking in the Cloud - SONiC
## Management Repo Style Guide

### 1. LGTM
PRs should not introduce any new LGTM errors, with one notable exception:
- `unused-import` errors can be ignored **if you are importing a fixture.** In this case, you should do the following:
    ```
    from ptfhost_utils import copy_ptftests_directory  # lgtm[py/unused-import]
    ```

If you believe LGTM has flagged a false positive, please raise it in the PR and discuss with the reviewers.

### 2. PEP8
All PRs should follow the [Official Python PEP8 Standard](https://www.python.org/dev/peps/pep-0008/), with one notable exception:
- `E501` (line >80 characters) can be ignored. Reviewers are expected to use their best judgement until we adopt an official standard.

There are tools like `flake8`, `pylint`, and others that will report PEP8 errors and integrate nicely with text editors and IDEs. You can also check online using http://pep8online.com/.

### 3. Documentation
Contributors should use [Google-style docstrings](http://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) to document all **public** interfaces. Comments for private interfaces are still encouraged, but can be omitted for simple private methods.

#### Example

```
"""
This is a one line description of what this module does.

This section expands on the one line description and adds context. You can use this part to describe what your module is supposed to do or what kind of behavior this set of test cases is exercising.
"""

class Example(object):
    """
    This is a one line description of what this class does.

    You can provide more info here.

    You can even include multiple sections if you really feel like it.

    Attributes:
        testing_is_cool: A *public* attribute of this class that returns whether
                        testing is cool or not (spoiler alert: it's always True).

    Examples:
        foo = Example()
        if foo.testing_is_cool:
            foo.write_more_tests()
    """

    def __init__(self, duthost, example_input):
        """
        Initializes an Example object.

        Initializers should *definitely* have a docstring describing what
        needs to be passed in to the object.

        Args:
            duthost: Fixture for interacting with the DUT. [NOTE: A short
                     description like this for fixtures is perfectly OK
                     because the dev can go look at the documentation
                     for duthost/SonicHost to get more info, if needed.]
            example_input: A List of integers that I am using as a convenient
                           example for how to describe a non-fixture input.

        """
        ... code ...

    def write_more_tests(self):
        """
        Write more tests for the sonic-mgmt repo.

        Remember, comments should describe *what* the operation does and not
        necessarily how it is done, unless the "how it's done" warrants some
        warning to the client, which leads us to...

        Warning:
            If there is some side effect your method has that the client *really*
            needs to know about, mention it in a warning tag. (Also consider
            a different abstraction/mechanism that /doesn't/ warrant a dire
            warning to your client.)

        Note:
            If there is some confusing behavior or specific use case or 
            otherwise noteworthy thing that your method does, mention in a 
            note tag.

        Returns: [or "Yields"]
            Try to be as specific as possible with your return type, and provide
            examples if you return something like a Dictionary with key/values
            the client might be interested in.

        """
        ...code...

    def _complex_private_method(self):
        """
        Do some complicated operation that is not part of the public API.

        Help future maintainers by providing some context for your private
        helper methods. :)

        Raises:
            Exceptions that are raised *by this method* should be described
            here. You do not need to describe every exception that may
            occur in methods called by this method unless you catch
            and re-raise them.

        """
        ...code...

    def _simple_private_method(self):
        """Do some simple operation that can be described in one line."""
        ...code...
```
