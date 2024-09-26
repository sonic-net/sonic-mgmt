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
We will maintain a set of test scripts for each topology,
allowing us to select relevant scripts based on the corresponding topology set within the change scope.
This method eliminates unnecessary processes by executing only the on-demand scripts,
resulting in reduced running time.

### To schedule instances automatically
We will dynamically allocate instances based on the number of scripts each PR checker executes.
By analyzing the running time of each script from previous runs,
we will allocate instances proportional to the total execution time for each PR checker.

## Benefits
This new simplified PR test will run on demand, reducing both time and cost efficiently.
