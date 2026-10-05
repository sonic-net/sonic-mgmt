# Steps to add a New PR Checker for Impacted Area-Based PR Testing

### Background
In our PR testing, each PR checker represents a specific topology and runs the corresponding test cases. As more topology types are added to production environments, we need to add additional PR checkers. This document will guide you through the process of adding a new PR checker in impacted area-based PR testing.

### Location of PR Checkers
PR checkers are defined in the `sonic-mgmt/azure-pipelines.yml` file. Each job represents a PR checker. Here’s a template example of the job:
```
- job: impacted_area_dualtor_elastictest  
  displayName: "impacted-area-kvmtest-dualtor by Elastictest"  
  dependsOn:  
  - get_impacted_area  
  - choose_between_mixed_and_py3_ptf_image  
  condition: contains(dependencies.get_impacted_area.outputs['SetVariableTask.PR_CHECKERS'], 'dualtor_checker')  
  variables:  
    TEST_SCRIPTS: $[ dependencies.get_impacted_area.outputs['SetVariableTask.TEST_SCRIPTS'] ]  
    set_ptf_image_tag: $[ dependencies.choose_between_mixed_and_py3_ptf_image.outputs['ptf_image_tag.tag_value'] ]  
  timeoutInMinutes: 240  
  continueOnError: false  
  pool: sonic-ubuntu-1c  
  steps:  
    - template: .azure-pipelines/impacted_area_testing/calculate-instance-numbers.yml  
      parameters:  
        TOPOLOGY: dualtor  
        BUILD_BRANCH: $(BUILD_BRANCH)  
        # 30 mins for preparing testbed, 30 mins for pre-test and 20 mins for post-test  
        PREPARE_TIME: 80  
  
    - template: .azure-pipelines/run-test-elastictest-template.yml  
      parameters:  
        TOPOLOGY: dualtor  
        PTF_IMAGE_TAG: $(set_ptf_image_tag)  
        SCRIPTS: $(SCRIPTS)  
        MIN_WORKER: $(INSTANCE_NUMBER)  
        MAX_WORKER: $(INSTANCE_NUMBER)  
        COMMON_EXTRA_PARAMS: "--disable_loganalyzer "  
        KVM_IMAGE_BRANCH: $(BUILD_BRANCH)  
        MGMT_BRANCH: $(BUILD_BRANCH)
```

### Steps to Add a New PR Checker
Before adding a new topology for testing, please contact with `sonicelastictest@microsoft.com` that suitable VM instances are available to set up the corresponding testbed. 
Otherwise, there is a risk that the testbed cannot be locked during testing due to the lack of appropriate resources.

**1. Update Test Scripts with Topology Marks**

Each test script includes a pytest mark to specify supported topologies. For your new PR checker, ensure the relevant test scripts include the new topology mark:

Example: 
```
pytestmark = [    
    pytest.mark.topology('t0', 't1-multi-asic', '<topology_name>')
]
```
This ensures the tests will run in the newly added PR checker.

**2. Add New Constants in `.azure-pipelines/impacted_area_testing/constant.py`**
1. Add your new topology checker `<topology_name>_checker` to the `PR_TOPOLOGY_TYPE` list.
2. Add the mapping of your new topology checker in the PR_CHECKER_TOPOLOGY_NAME dictionary:
```buildoutcfg
<topology_name>: [<topology_type>, "_kvmtest-<topology_name>_"]
```
This mapping is used for Kusto query conditions.

**3. Add a New Job in `azure-pipelines.yml`**

Follow these steps to add a new job for your new PR checker in sonic-mgmt/azure-pipelines.yml:
1. **job & displayName** Set:
   + **job**: impacted_area_<topology_name>_elastictest 
   + **displayName**: impacted-area-kvmtest-<topology_name> by Elastictest

2. **dependsOn**:
This field lists the other jobs that your job depends on. Generally, you do not need to change this.

3. **condition**:
This condition determines whether the PR checker should run in the current test cycle. In Impact Area-Based PR testing, only test scripts relevant to the changes are executed, so some PR checkers may not be required. Modify the condition as follows:
```buildoutcfg
contains(dependencies.get_impacted_area.outputs['SetVariableTask.PR_CHECKERS'], '<topology_name>_checker')  
```
4. **variables**:
This section defines variables used by the job. These variables are typically inherited from other jobs, so no changes are needed here.

5. **timeoutInMinutes**:
The default timeout is 240 minutes. You can modify it based on your requirements.

6. **continueOnError**:
This is a boolean field. Set it to `true` if you want the workflow to continue to the next step or job even if the current one fails. Set it to `false` if you want to stop the workflow if the job fails.

7. **pool**:
This is the agent pool used to trigger test, you don't need to do any change.

8. **Calculate Instance Numbers**:
Use the provided template (`.azure-pipelines/impacted_area_testing/calculate-instance-numbers.yml`) to calculate the number of instances required for your tests. You don't have to change this.
+ **parameters**
  + **TOPOLOGY**: Specify the new topology in this field.
    ```buildoutcfg
    TOPOLOGY: <topology_name>
    ```
  + **BUILD_BRANCH**: This is a system variable (`$(BUILD_BRANCH)`) that specifies the branch under test. Do not change this.
  + **PREPARE_TIME**: If preparation and cleanup of the testbed will take more than 30 minutes, specify the `PREPARE_TIME` here.

9. **Trigger Elastictest Test Plans**:
Use another template (`.azure-pipelines/run-test-elastictest-template.yml`) to trigger the Elastictest test plans. You don't have to change this.
+ **parameters**
  + **TOPOLOGY**: Specify the topology you defined in `ansible/vtestbed.yaml`.
  + **PTF_IMAGE_TAG & SCRIPTS**: These variables are passed from other jobs and do not need modification.
  + **MIN_WORKER & MAX_WORKER**: These are calculated and assigned in the first template, so no changes are required here.
  + **COMMON_EXTRA_PARAMS**: If you do not need additional command parameters, remove this field.
  + **KVM_IMAGE_BRANCH & MGMT_BRANCH**: These are system variables and do not need to be modified.
+ **Handle Sonic-mgmt Master Branch vs. Other Branches**
  + If the branch is sonic-mgmt master, you do not need to refer to the remote repository when calling the template. Simply use:
    ```buildoutcfg
    - template: .azure-pipelines/run-test-elastictest-template.yml
    ```
  + For other branches, you need to refer to the remote sonic-mgmt repository, as the template is maintained in the master branch. Use the following:
    ```buildoutcfg
    - template: .azure-pipelines/run-test-elastictest-template.yml@sonic-mgmt
    ```

By following these steps, you can successfully add a new PR checker for your new topology and ensure it runs in the Impacted Area-based PR testing when relevant changes are made.
If you have any questions or need further assistance, please feel free to contact `sonicelastictest@microsoft.com`.

