## Background
In the current PR test process, we run a fixed set of test scripts regardless of the scope of changes,
leading to unnecessary resource consumption.
However, in the sonic-mgmt repository,
it's sufficient to run only the relevant test scripts to validate the changes.

To optimize this, we propose a simplified PR test
that runs only the necessary test scripts located in the same folder as the modified files.

## Design
Our new simplified PR test will follow below principles:
- If changes are made only to the scripts within the features folder,
we will run only the specific scripts in those feature folders.
- If our change related to the common folder, we will run all test scripts.

In our new PR test, the number of scripts per test is variable,
so instances used by Elastictest will be automatically scheduled concurrently.

In our new PR test, we will also have multiple PR checkers classified by topology type.
To collect all required scripts for each PR checker, which means,
these scripts should not only within the scope that we changed, but also meet the requirement of topology.

To
One approach to achieve this is by using the `--topology` parameter supported by pytest.
It compares against the topology marked with `pytest.mark.topology` in script,
and if the mark matches, the script is deemed necessary.
However, this method triggers pytest's collection process for each script,
leading to unnecessary time consumption.

We



## Benefits
This new simplified PR test will run on demand, reducing both time and cost efficiently.
