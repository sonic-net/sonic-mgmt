## Background
In current PR testing process, a fixed set of test scripts is executed regardless of the change scope.
This approach lacks flexibility. On the one hand, if changes are only related to a few lines of codebase,
we may don't need to run the whole scope. On the other hand, if there are new added test scripts,
we need to add them manually.

With approximately 570 test scripts running, the process has become excessively large and the runtime increased significantly.
Due to the maximum execution time limit, more instances are needed to run the tests in parallel.
For example, to meet this requirement, we need 20 instances for t0 and 25 instances for t1.
The cost per PR has reached $35, and we will use $23,000 per month to run PR testing, which is considerably high.

To address these issues, we propose a new PR testing model called 'Impacted Area-Based PR Testing.

## Preparation
We can organize the codebase in this way:
```
sonic-mgmgt
     | - .azure-pipelines
     | - ansible
     | - docs
     | - ......
     | - tests
           |
           | - common      ---------- shared
           | - arp         -----|
           | - ecmp             | --- features
           | - vlan             |
           | - ......      -----|
```
Under sonic-mgmt, there are several top-level folders such as `.azure-pipelines`, `ansible`, `docs`, `tests`, and more.
Except for the `tests` folder, we classify all other folders as part of the shared section of the repo.

Within the `tests` folder, there are multiple second-level directories.
Among them, the common folder is also considered part of the shared section.
Other folders, such as `arp`, `ecmp`, and similar directories, are classified as feature-specific parts.

Scripts in the common folder fall under the shared section and can be utilized across different folders.
In contrast, scripts in other folders belong to the features section, representing specific functionalities such as arp, ecmp, and vlan,
and are intended for use within their respective folders.
This hierarchy helps us more effectively identify the impacted areas for the new PR testing process.

However, the previous code had numerous cross-feature dependencies.
To achieve our goal, we carried out some preparatory work by eliminating these cross-feature dependencies.


## Design
### Impcated Area
To take advantage of such code structure, we introduce a new term called `impacted area`, which represents the scope of PR testing.
The `impacted area` can be defined by specific features, so that we can narrow down the scope into folders.

This term can be elaborated as follows:
- If the changes are confined to a specific feature folder, we can narrow the scope of testing to only include files within that folder.
As files in other feature folders remain unaffected and do not require testing.
- If the changes affect the common components, we cannot narrow the testing scope and must run all test scripts to ensure comprehensive coverage, as they are commonly used by other features.

We can determine the impcated area using command `git diff`.

### Distribute scripts to PR checkers
In our new PR test, we will have multiple PR checkers classified by topology type.
To distribute all required scripts for each PR checker, which means,
these scripts should not only within the scope that we changed, but also meet the requirement of topology.

We can suggest two approaches to achieve this:
- One approach is by using the `--topology` parameter supported by pytest.
It compares against the topology marked with `pytest.mark.topology` in script,
and if the mark matches, the script is deemed necessary.
However, this method triggers pytest's collection process for each script,
leading to unnecessary time consumption, which is not expected.

- Another approach is to collect and analyze all scripts before execution.
Each script includes the `pytest.mark.topology` marker to indicate the applicable topology it can run on.
We will perform a global scan of all test scripts in the impacted area to identify this marker and extract its value,
which represents the topology type compatible with the script.
After determining the valid topology for each script, we can distribute the script to corresponding PR checkers.
This method eliminates unnecessary processes by executing only the on-demand scripts, resulting in reduced running time.

### Implement dynamic instances
Since the scope of PR testing is dynamic and determined by the impacted area,
the number of instances required also needs to be dynamic to ensure cost efficiency.
To achieve this, we must accurately estimate the total execution time in advance,
allowing us to allocate the appropriate number of instances.
This estimation can be achieved by analyzing historical data,
which provides insights into execution times for similar scenarios.

We now have a Kusto table that logs details about the execution of test cases,
including the running time, date, results, and more.
To determine the preset running time for each test script,
we will calculate the average running time of the latest five run times.
If no relevant records are found in Kusto, a default value(1800s per script) will be used for the preset running time.
This approach allows us to estimate the total execution time for our scripts accurately.

Using this information, we will evenly distribute the scripts across instances,
ensuring that the workload is balanced of each instance.
Ideally, each instance will run its assigned scripts in approximately 1.5 hours,
leaving additional time for tasks such as testbed preparation and clean-up and keeping the total runtime within 2 hours.

## Advantages
Impacted area based PR testing runs test scripts on demand, reducing the overall scale of the PR test and saving execution time.
And instances will be allocated as needed, resulting in more cost-efficient resource usage.
Additionally, the PR testing will be more flexible as we can collect test scripts automatically rather than hard code.

## Safeguard
As impacted area based PR testing would not cover all test scripts, we need a safeguard to run all test scripts daily to prevent any unforeseen issues.
Fortunately, we have Baseline testing to do so.
Baseline testing involves running all test scripts in the test plan daily to ensure the overall stability of the system and identify potential issues.
We conduct five rounds of baseline testing each day, and if any issues are detected, an ADO is automatically created, and email alerts are sent to notify the relevant teams.
