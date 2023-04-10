# Important Note for Contributors

Test cases in this directory have been migrated to /tests/snappi. **Since December 2022, Snappi has become our primary API (through `snappi`) for interacting with Keysight Ixia devices**, while we are deprecating the existing `ixia` API from our test repository. Any new test cases from contributors requiring the use of any *Ixia* devices should utilise the `snappi` API, and any new pull requests which still calls the `ixia` API will be disregarded.

You can find more information on the `snappi` API such as its usage [here](https://github.com/open-traffic-generator/snappi-ixnetwork) or by viewing the code in the [tests/snappi](https://github.com/sonic-net/sonic-mgmt/tree/master/tests/snappi) directory of this repository.

--

*Ixia* and its associated brand names are owned by Keysight Technologies.
