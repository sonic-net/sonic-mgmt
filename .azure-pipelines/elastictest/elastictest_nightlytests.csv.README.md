# Description

This document provides instructions on how to configure and add new entries to the Elastictest nightly test pipeline configuration CSV file. 
The CSV file is used to define various parameters for scheduled pipelines, including their execution conditions, associated testbeds, and resource allocation.

## Structure of `elastictest_nightlytests.csv` File

The CSV file contains the following headers, each with a specific purpose:

| Column Name             | Description                                                                                                                                  | Example                                                                                   |  
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|  
| `pipeline_name`        | The unique name of the pipeline. This is used to identify the pipeline for different nightly tests.                                          | `"arista.720dt.m0.202311"`                                                                |  
| `enabled`              | A boolean value (`True` or `False`) indicating whether the pipeline is enabled for schedule execution.                                       | `True`                                                                                    |  
| `cron`                 | The cron schedule in the format `minute hour day month day_of_week` for when the pipeline will run.                                          | `"30 3 * * 2"`                                                                            |  
| `testbed_name`         | The name of the testbeds that can be allocated for this nightly test.                                                                        | `"testbed-bjw-can-720dt-1,testbed-bjw-can-720dt-2"`                                       |  
| `min_worker`           | The minimum number of testbeds required for this nightly test to run.                                                                        | `1`                                                                                       |  
| `max_worker`           | The maximum number of testbeds that can be allocated for this nightly test.                                                                  | `2`                                                                                       |  
| `image_url`            | The sonic build image URL to run nightly test.                                                                                               | `"$(BJW_IMAGE_BRCM_ABOOT_202311)"`                                                        |  
| `mgmt_branch`          | The branch of sonic-mgmt-int to run nightly test.                                                                                            | `"internal-202311"`                                                                       |  
| `scripts`              | A comma-separated list of scripts that this nightly test will execute. If empty, will run all scripts.                                       | `"bgp/test_bgp_fact.py,test_features.py"`                                                 |  
| `scripts_exclude`      | A comma-separated list of scripts that should be excluded from execution.                                                                    | `"copp/test_copp.py"`                                                                     |  
| `features`             | A comma-separated list of features to enable for this nightly test. If empty and scripts emtpy, will run all features.                       | `"featureA,featureB"`                                                                     |  
| `features_exclude`     | A comma-separated list of features to disable for this nightly test.                                                                         | `"featureC"`                                                                              |  
| `common_extra_params`  | Any additional parameters(used for pytest) that are common to run this nightly test.                                                         | `"--topology m0,any --no_dscp_uniform --unresettable_xcvr_types=SFP"`                     |  
| `max_run_test_minutes` | The maximum allowed time (in minutes) for this nightly test to run before being terminated.                                                  | `1440`                                                                                    |  
| `affinity`             | Association between test cases and testbeds. Specify which TB the test case should run on or not. Currently support 2 operations: ON, NOT_ON | `"[{'name': 'bgp/test_bgp_fact.py', 'op': 'ON', 'value': ['testbed-bjw-can-720dt-2']}]"`  |

## Trigger your Nightly Test pipelines

There are 2 approaches to trigger nightly test pipelines.
Firstly, you need to add a new row to the [nightlytests.csv](elastictest_nightlytests.csv).

- Triggered by schedule: 

When the scheduling time arrives(Fall within a short time window), a pipeline will trigger the nightly tests that need to be run.

- Triggered manually: 

Go to [Elastictest Nightly Test Trigger (General)](https://dev.azure.com/mssonic/internal/_build?definitionId=2079&_a=summary) Pipeline, manually run a pipeline with specific pipeline_name(defined in nightlytests.csv).