## Background
We introduced a new approach to PR testing called _Impacted area based PR testing_. \
In this model, the scope of PR testing is determined by the specific areas of the code that are impacted by the changes,
allowing for more focused and efficient testing.
This means, we need to establish clear boundaries between different sections of code
and minimize dependencies as much as possible.

We can consider the test scripts in this way:
```
sonic-mgmgt
     |
     | - tests
           |
           | - common      ---------- shared
           | - arp         -----|
           | - ecmp             | --- features
           | - vlan             |
           | - ......      -----|
```
Within the tests directory in sonic-mgmt, we categorize scripts into two sections: shared and features.
Scripts in the common folder fall under the shared section and can be utilized across different folders.
In contrast, scripts in other folders belong to the features section, representing specific functionalities such as arp, ecmp, and vlan,
and are intended for use within their respective folders.

However, the previous code had numerous cross-feature dependencies.
To achieve the above goal, we have removed the cross-feature references from the existing code.
But we need a mechanism to check future modifications and new code to prevent reintroducing these issues.


## Design
The _ast_ module helps python applications to process trees of the python abstract syntax grammar.
This module produces a tree of objects, where each object is an instance of a class that inherits from _ast.AST_.
There are two classes related to the imports:

#### ast.Import
  - An import statement such as `import x as a,y`
  - _names_ is a list of alias nodes.
```
    Import(names=[
        alias(name='x',
        asname='a')
    ]),
    Import(names=[
        alias(name='y',
        asname=None)
    ]),
```
#### ast.ImportFrom
  - Represents `from x import y,z`.
  - _module_ is a raw string of the ‘from’ name, without any leading dots, or None for statements such as `from . import foo.`
  - _level_ is an integer holding the level of the relative import (0 means absolute import)
```
ImportFrom(
    module='x',
    names=[
        alias(name='y', asname=None),
        alias(name='z', asname=None)],
    level=0)
```

To achieve our goal, we need to follow these steps.
 + Gather all scripts to be analyzed
 + Identify all imported modules in each script along with their import paths
 + Compare each imported path with its corresponding script path

### Gather all scripts to be analyzed
To collect all scripts for analysis,
we can use `os.walk` to gather every script within the specified path

### Identify all imported modules in each script along with their import paths
To identify all imported modules,
we can use the _ast_ module, as mentioned above, to analyze each collected script and obtain its abstract syntax tree.
Then, using the _ast.ImportFrom_ and _ast.Import_ classes, we can extract the imported modules from each script.


Here are the steps and configuration methods for Python to search for module paths:
+ The current script's directory or the directory from which the Python interpreter is started.
+ Standard library path: Contains the standard library modules from the Python installation directory.
+ Third-party library path: For example, the site-packages directory, where third-party libraries installed via pip and other tools are stored.
+ Environment variable path: Custom directories can be added to sys.path via the PYTHONPATH environment variable.

As paths of project is not included in the sys path, we need to add them into sys path first.

+ `importlib.util.find_spec` is a function in Python that is used to find the specification of a module.
  The specification contains details about the module, such as its location (file path), loader, and other attributes.
  It can find the path of standard library, third-party libraries and custom modules which are imported with no hierarchy.

  For statement like `import math`, `from tests.common.plugins.allure_wrapper import allure_step_wrapper`, `from gnmi_utils import apply_gnmi_file`,
  we can use `importlib.util.find_spec` to get their imported path.
+ For hierarchy imported, we can calculate the abs path using the current file path and level to navigate up to the corresponding directory.

### Compare each imported path with its corresponding script path
We will focus only on imported paths that start with `sonic-mgmt/tests`.
Paths imported from other folders within `sonic-mgmt` are treated as common locations.

For paths beginning with `sonic-mgmt/tests`, there are three special cases:
+ sonic-mgmt/tests/common
+ sonic-mgmt/tests/ptf_runner.py
+ sonic-mgmt/tests/conftest.py
which are also considered as common paths.

For all other paths, we will compare each imported path to the path of the corresponding script based on the following principles:
+ The first-level folders under `sonic-mgmt/tests` (e.g., arp, bgp) are considered feature folders.
+ If both the imported module and the script are in the same feature folder, there is no cross-feature dependency.
+ If they are in different feature folders, it indicates a cross-feature dependency, causing the check to fail.


We will add this check as a step in `Pre_test` in PR test.
