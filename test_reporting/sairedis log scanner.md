

# Background
In order to better utilize the sairedis log to analyze the running process of sai, like API, attributes or operations that have been used, we extract the key and useful information fields of sairedis and store them in the kusto table.

# Environment
For ingesting json file to the kusto , you maybe need `sonic-mgmt` container [how to setup](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Docker.md)


# Pipline
1. collect
   - collect sairedis logs from different types of machines
2. analyze
    - analyze the logs, extract the key and value organized by json
3. ingest
   - ingest json file to the kusto table SwssInvocationReport


 ## Collect
- Get logs from devices for each type tuple(DeploymentType,Type).
- and for each device, we get all the sairedis.rec or at least 50 files(if all is more than 50)
- logs are under `/var/log/swss`
- btw, we should use `show version` to get sonic version
- create a directory in the server/vm where sonic-mgmt repo/container be placed
- and use `scp` command to send logs from sonic device in the lab to the server/vm subdirectory(each device has a dir) in repo
- unzip the *.gz file by `gunzip */sairedis*.gz` in server/vm

### Device types
> In this example, there are 4 types(deployType1,deployType2, deployType3,deployType4) of device, and each type have several subtypes

|deployment_type  | deployment_subtype |
|--|--|
|deployType1  |  subtype1|
|deployType1  | subtype2 |
| deployType2 | subtype2 |
| deployType3 | subtype2 |
|deployType3  | subtype3 |
|deployType3  | subtype2 |
|  deployType4|subtype3|

## Analyze
Go through the log line by line, skip the line without 'SAI_OBJECT_TYPE' or not with the defined operations(like operation_map test_reporting/swss.yml).
Base on sairedis log format, split line by char '|' to get the item list as below

```
1. log_time: get from list[0]
2. sai_op: list[1]{'r':'remove', 'c':'create','g':'get','s':'set','q':'query','S':'bulk_set','C':'bulk create','R':'bulk remove'}
3. sai_obj: split list[2], get sai_obj from part one by remove'SAI_OBJECT_TYPE'
4. sai_obj_key: split list[2], get sai_obj_key from part two
5. sai_api: Concat sai_op and sai_obj
6. sai_feature: generate by matching header file and sai_obj
7. sai_obj_attr_key: search list, if item has '=', split by '=',left is sai_obj_attr_key, right is sai_obj_attr_value
8. sai_obj_attr_value: as before
9. header_file: header file <---> feature <---> sai_obj, so get can get header file through sai_obj (sai_obj <---> file)
10. deployment_type
11. deployment_subtype
12. ngsdevice_type: const value for t0 devices 'ToRRouter'
13. device name
14. log: the content of log
15. log_file: log path
16. os_version
```
**if the operation is bulk which means operate several objects in the meantime（bulk operations are only supported after sonic version 2020）**
**if n attributes this line, we will insert n entries in db table, an attribute one entry**
**here is pseudo-code**
```
for obj_key, attributes in zip(sai_object_key, obj_key_attrs):
    for attribute in attributes:
        items.append(log_item)
```

All those process integrated with in python code https://github.com/sonic-net/sonic-mgmt/tree/master/test_reporting/sai_swss_invocations.py
```
    for info in swss_device_log_items:
        generate_json_logs(info['log_path'], info)
```

## Ingest
Store the generated json data in kusto.

Table name: SwssInvocationReport
 connection parameters that we need to **set as environment variable**:
     1. kusto cluster
     2. tenant id
     3. client id
     4. client key
**edit yaml file for your config**
run the process
```
python file: sonic-mgmt(-int)/test_reporting/sai_swss_invocations.py
python sai_swss_invocations.py --config_path <YOUR CONFIG FILE>
```

Example:
```
export TEST_REPORT_INGEST_KUSTO_CLUSTER="https://****.kusto.windows.net"
export TEST_REPORT_AAD_TENANT_ID="****-86f1-*******"
export TEST_REPORT_AAD_CLIENT_ID="****-ff00-*******"
export TEST_REPORT_AAD_CLIENT_KEY=*******

cd test_reporting
python sai_swss_invocations.py --config_path swss.yml
```
> Example for config file are right here https://github.com/sonic-net/sonic-mgmt/tree/master/test_reporting/swss.yml
