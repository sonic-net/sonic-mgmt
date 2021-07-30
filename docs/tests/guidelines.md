# Guidelines

## Creating new test cases ##
* Please add custom marker to specify if the test case is applicable to t0/t1/any/util/t0-soak topology.
    * t0/t1: test case can run on either t0 or t1 toplogy but not the other.
    * any: test case can run on both t0 and t1 topology.
    * util: test case is a utility, eitehr pre-test or post-test. Usually only need to be run once per test session.
    * t0-soak: special test case that could take very long time to finish and applicable to t0 topology.