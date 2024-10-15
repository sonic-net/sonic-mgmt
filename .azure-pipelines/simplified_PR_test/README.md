## Background
In the current PR test process, we run a fixed set of test scripts regardless of the scope of changes,
leading to unnecessary resource consumption.
However, in the sonic-mgmt repository,
it's sufficient to run only the relevant test scripts to validate the changes.

To optimize this, we propose a simplified PR test
that runs only the necessary test scripts located in the same folder as the modified files,
which reduces both time and cost efficiently.


## Design
Our new simplified PR test will follow below principles:
- If changes are made only to the scripts within the features folder,
we will run only the specific scripts in those feature folders.
- If our change related to the common folder, we will run all test scripts,
which is same as our previous PR test.

In our new PR test, we will have multiple PR checkers classified by topology type.
To collect all required scripts for each PR checker, which means,
these scripts should not only within the scope that we changed, but also meet the requirement of topology.

Because the number of scripts per test is variable,
the instances used by Elastictest will also be automatically scheduled concurrently,


### To meet the requirement of topology
One approach to achieve this is by using the `--topology` parameter supported by pytest.
It compares against the topology marked with `pytest.mark.topology` in script,
and if the mark matches, the script is deemed necessary.
However, this method triggers pytest's collection process for each script,
leading to unnecessary time consumption.

Another approach is to collect and analyze all scripts before execution.
Each script includes the `pytest.mark.topology` marker to indicate the applicable topology it can run on.
We will perform a global scan of all test scripts to identify this marker and extract its value,
which represents the topology type compatible with the script.
After determining the valid topology for each script,
we will group them accordingly and maintain a set of test scripts for each topology.
Then, in each PR checker, we will select relevant scripts in the set within the change scope.
This method eliminates unnecessary processes by executing only the on-demand scripts,
resulting in reduced running time.


### To schedule instances automatically
Our goal is to complete the entire PR test within 2 hours.
In the current PR test, each checker uses a fixed number of instances.
However, in the new simplified test, the number of scripts executed varies,
so the number of instances should be dynamically adjusted for cost efficiency.
The number of instances we allocate will be determined by the total estimated execution time of the scripts that need to be run.
We can leverage historical data to obtain the average running time of each script from previous test executions.

We now have a Kusto table that logs details about the execution of test cases,
including the running time, date, results, and more.
To determine the preset running time for each test script,
we will calculate the average running time of successful runs over the past three days.
If no relevant records are found in Kusto, a default value will be used for the preset running time.
This approach allows us to estimate the total execution time for our scripts accurately.

Using this information, we will evenly distribute the scripts across instances,
ensuring that the workload is balanced of each instance.
Ideally, each instance will run its assigned scripts in approximately 1.5 hours,
leaving additional time for tasks such as testbed preparation and keeping the total runtime within 2 hours.

## Benefits
This new simplified PR test will run on demand, reducing both time and cost efficiently.
