## Terminology
- Instance: A KVM running on an Azure VMSS used for executing PR tests. 
            Each instance corresponds to a specific topology and is utilized to perform the tests.
- Scope: The set of test scripts that are executed during the PR test.

## Background
In current PR testing process, a fixed set of test scripts is executed regardless of the change scope.
With approximately 440 test scripts running, the process has become excessively large.
Due to the maximum execution time limit, more instances are needed to run the tests in parallel.
For example, to meet this requirement, we need 20 instances for t0 and 25 instances for t1.
The cost per PR has reached $35, which is considerably high.
To address these issues, we propose a new PR testing model called 'Impacted Area-Based PR Testing.

## Preparation 
We can organization the test scripts in this way:
```buildoutcfg
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
This hierarchy helps us more effectively identify the impacted areas for the new PR testing process.

However, the previous code had numerous cross-feature dependencies. 
To achieve our goal, we carried out some preparatory work by eliminating these cross-feature dependencies.


## Design
### Impcated Area
We introduce a new term called `impacted area`, which represents the scope of PR testing. 
This term can be defined as follows:
- If changes are made solely to the scripts within the feature folders, 
  the impacted area is considered to be those specific feature folders.
- If changes occur in the common folder, 
  the impacted area encompasses both common and all feature folders.
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

### Allocate instances dynamically
Our goal is to complete the entire PR test within 2 hours.
In the current PR test, each checker uses a fixed number of instances.
However, in the new simplified test, the number of scripts executed varies,
so the number of instances should be dynamically adjusted for cost efficiency.
The number of instances we allocate will be determined by the total estimated execution time of the scripts that need to be run.
We can leverage historical data to obtain the average running time of each script from previous test executions.

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
Additionally, instances will be allocated as needed, resulting in more cost-efficient resource usage.

## Safeguard
As impacted area based PR testing would not cover all test scripts, 
we need a safeguard to run all test scripts daily to prevent any unforeseen issues. 
Fortunately, we have Baseline test to do so. 