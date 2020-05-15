# Understanding the gnmitest Suite proto message

The gnmitest service has an RPC called **Run**. It receives a `Suite` proto
message from a client and returns a `Report` proto message. The `Suite` message
contains connection information, and a test specification (including gNMI
message payloads, such as subscription paths). At a high level, the `Suite`
message contains a list of `InstanceGroup` messages to execute sequentially.
Each `InstanceGroup` contains a set of `Instance` messages to run in parallel.
`Instance` contains a `Test` message which specifies a particular test to be run
against a gNMI RPC.

A `Test` message can have either `SubscribeTest` or `GetSetTest` messages
specified. `SubscribeTest` describes a set of tests that can be run against the
gNMI `Subscribe` RPC. `GetSetTest` describes tests that can be run against
either `Get`, `Set`, or both. The other fields (`timeout`, `schema` and
`connection`) of the `Test` message may be set if the `Suite` level counterparts
are to be overridden.

For the `Subscribe` RPC the `SubscribeTest` message describes both the gNMI
`SubscribeRequest`, and hence the subscription information, as well as the test
to execute. The oneof `args` field in `SubscribeTest` indicates which test is
to be executed by the framework using the specified subscription (i.e., which
test handles the `SubscribeResponse` messages received). Some tests require
arguments, which are described in the message within the `args` `oneof`
corresponding to the test.

## Example Suite Message

The sample `Suite` message below demonstrates the high-level structure of a
gnmitest `Suite`:

```proto
name: "demo suite"
# duration in seconds a test is allowed to run.
timeout: 5
schema: "openconfig"
connection {
  target: "_target_"
  address: "_address_of_gnmi_server_"
  # dial timeout.
  timeout: 10
}

instance_group_list {
  description: "existence check"
  instance {
    description: "has keys test for _target_"
    test {
      subscribe {
        request {
          subscribe {
            prefix {
              target: "_target_"
              origin: "openconfig"
            }
            subscription {
            }
            mode: ONCE
          }
        }
        has_keys {
          path {
            elem {
              name: "components"
            }
            elem {
              name: "component"
            }
          }
          item {
            key {
              key: "name"
              value: "_key_"
            }
          }
        }
      }
    }
  }
}
```

The `Suite` message above specifies a simple test that checks for the
presence of the key `_key_` in the `/components/component` OpenConfig list.
The test that executes this check is the `has_keys` test. The arguments supplied
are specified within the `has_keys` field of the `args` oneof.

When the `Suite` message is sent to the gnmitest runner, it
creates a subscription to the device with the given gNMI `SubscribeRequest` and
dispatches received messages to the `has_keys` test. The `Suite` level
configuration parameters are effective unless they are overridden by individual
tests:

*   __timeout:__ Amount of time a test is allowed to run.
*   __connection:__ Address and credentials to use while connecting to gNMI
target.
*   __schema:__ An identifier to choose between registered Go representation of
OpenConfig schemas.

    **Note**: By default, OpenConfig is assumed to be the schema that is
    supported by the target. Other YANG schemas can be used by generating Go
    code using [ygot](https://github.com/openconfig/ygot) and registering the
    schema with gnmitest, (by creating a
    [registration package](https://github.com/openconfig/gnmitest/blob/master/schemas/openconfig/register/openconfig.go)
    and [importing it](https://github.com/openconfig/gnmitest/blob/8faacdae6b7a8bddbeb3781b1288f389e7d25c4e/service/service.go#L30)).

## Executing a gnmitest Suite

The gnmitest framework is exposed through the gnmitest service which is a gRPC
server. To start gnmitest service, you should run the following command:

```
go run $GOPATH/src/github.com/openconfig/gnmitest/cmd/gnmitest_service/gnmitest_service.go
```

**Note:** Host and port to start the service can be configured with `bind` and
`port` flags. Default values are ==localhost:11601==.

Once the gnmitest service is running, we can use **gnmitest_cli** to execute a
`Suite` message as follows:

```
go run $GOPATH/src/github.com/openconfig/gnmitest/cmd/gnmitest_cli/gnmitest_cli.go -address localhost:11601 -suite testdata/suite.textproto -report testdata/report.textproto
```

**Note:** Address provided above is the default host and port value specified to
run **gnmitest_service**.

**Note:** The example `Suite` textproto specified in the command above doesn't
specify a valid gNMI target. You can edit the `Connection` message in `Suite`
text proto to override this.

## Example Report Message

Once `Suite` is executed, a `Report` is returned that summarizes the set of
tests executed and their results. An example `Report` looks like as follows:

```proto
results: <
  instance: <
    test: <
      test: <
        timeout: 20
        schema: "openconfig"
        connection: <
          target: "_target_"
          address: "_address_of_gnmi_server_"
          timeout: 10
        >
        subscribe: <
          request: <
            subscribe: <
              prefix: <
                origin: "openconfig"
                target: "_target_"
              >
              subscription: <
              >
              mode: ONCE
            >
          >
          value_validation: <
          >
        >
      >
      result: FAIL
      subscribe: <
        status: EARLY_FINISHED
        errors: <
          message: "rpc error: code = Unknown desc = failed to update struct field Type in *uoc.OpenconfigPlatform_Components_Component_State with value string_val:\"MODULE\" ; could not find suitable union type to unmarshal value string_val:\"MODULE\"  type *gnmi_go_proto.TypedValue into parent struct type *uoc.OpenconfigPlatform_Components_Component_State field Type"
        >
      >
    >
  >
>
```

`Report` message has a similar structure to `Suite` message. There is an
`InstanceGroup` result message in `Report` proto corresponding to each
`InstanceGroup` in `Suite` proto. The sample provided above corresponds to an
`InstanceGroup` containing single `Instance`. The `Test` message in `Suite`
proto is included in the result. `result` field contains the result of running
`Test`. For `Subscribe` tests, additional information about how test ended
(`status`) and errors received while running test are also included. In `Suite`
proto, you could also set `log_responses` to true to indicate including
`SubscribeResponse` messages in the report.
