# Background
In the current PR test process, we run a fixed set of test scripts regardless of the scope of changes, leading to unnecessary resource consumption.
However, in the sonic-mgmt repository, it's sufficient to run only the relevant test scripts to validate the changes.

To optimize this, we propose a simplified PR test that runs only the necessary test scripts located in the same folder as the modified files.
