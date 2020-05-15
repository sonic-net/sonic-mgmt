# High level steps to add a new subscribe test

Subscribe tests in gnmitest framework are identified by the field specified
within the `args oneof` of `SubscribeTest`. When adding a new test, a new field
needs to be added to the `oneof`. The type of the field depends upon the test
argument, in some cases an existing message may be re-used, whereas in others
a new one will be required to specify the test arguments. If the test requires
no arguments, the `Default` message, `SubscribeTest` in
[tests.proto](https://github.com/openconfig/gnmitest/blob/master/proto/tests/tests.proto)
can be used. To add a new `foo_verification` test, we therefore would extend the
`SubscribeTest` `args` `oneof` by adding a new field:

```proto
message SubscribeTest {
  ...
  oneof args {
    ...
    Default foo_verification = X;
  }
}
```

The next step is to add the Go implementation of the new test. To achieve this:

*   A new Subscribe test implementing `subscribe.Subscribe` interface must be
    added. The new test must therefore provide a type which implements the
    following interface:

    ```go
    // Subscribe is the interface of a test for gnmi Subscribe RPC.
    type Subscribe interface {
      // Process is called for each individual message received. Status returned by
      // Process may have Running or Complete status. When Complete is returned,
      // test framework calls Check function of the test to get the holistic test
      // result and to end the test.
      Process(sr *gpb.SubscribeResponse) (Status, error)
      // Check is called to get the holistic test result in the following cases;
      // - Process function returns Complete
      // - Test times out
      // - GNMI RPC request fails
      Check() error
    }
    ```

*   A factory function must be created to return a new instance of the type
    implementing the `Subscribe` interface. The factory function's arguments and
    return values must be as follows:

    `func (st *tests_go_proto.Test) (subscribe.Subscribe, error)`

*   The next step is to register the test to framework. To achieve this, func
    init() of the package must be implemented as follows:

    ```go
    // init registers the factory function of the test to global tests registry.
    func init() {
      register.NewSubscribeTest(&tpb.SubscribeTest_FooVerification{}, newTest)
    }
    ```
>    **Note:** As seen above, the type used to register the test is the type of
      args oneof field in *SubscribeTest*. So, two different tests can use same
      message type. For instance:
>
>```proto
>message SubscribeTest {
>  ...
>  oneof args {
>    ...
>    Default foo_verification = X;
>    Default bar_verification = X+1;
>  }
>}


*   Finally, import the new test package in [gnmitest service main](https://github.com/openconfig/gnmitest/blob/8faacdae6b7a8bddbeb3781b1288f389e7d25c4e/service/service.go#L32).
    Test should be ready to use in `Suite` message after rebuilding and
    restarting gnmitest service.
