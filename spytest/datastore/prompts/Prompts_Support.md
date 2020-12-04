# Prompts Support:  
  
We have placed a file "sonic_prompts.yaml" under "datastore/prompts" directory in spytest clone.  
Little bit of help/comments are also provided in that file.

This file contains 3 sections:  
#### **patterns:**
Where users will define each pattern with a unique name. Each pattern name and value should be unique.
For sonic management framework, "**--sonic-mgmt--**" is a default value used by framework,
please do not change that and add your pattern using the above default value.

#### **modes:**
Whatever name we have given to a pattern in the above section, we have to provide a mechanism to enter into that prompt.
So here, for each pattern, we have to provide the parent pattern and the command which need to be executed to enter into that mode and a command which need to be executed to come out of that mode.
There are some areas where we have to provide some values along with the command to enter into a mode.
For such scenarios, keep a place holder({}) for that.

#### **required_args:**
In the above section, for some commands, we added place holders. Names for those place holders will be added here.
We have written an example script "**tests/infra_ut/test_ut_modes.py**" as part of our unit testing.
Look for functions which match "**test_mgmt_cli_mode_\***", "**test_vtysh_prompt_modes_\***", "**test_vtysh_mgmt_prompt_modes_\***" and "**test_all_modes_\***"

# Example:  

To add support for acl prompts, following is the way:

To enter into ACL prompt, we have to execute "**ip access-list ACL_NAME**" and to come out of it is "**exit**".
After entering the prompt will be like "**--sonic-mgmt--(config-ipv4-acl)#**"

So add as follow in pattern section:
**`mgmt-ipv4-acl-config: '--sonic-mgmt--\(config-ipv4-acl\)#'`**

And in modes section:
**`mgmt-ipv4-acl-config: ['mgmt-config', 'ip access-list {}', 'exit']`**

For entering into that mode, ACL_NAME should be provided as input. So, need to add the following in required args
**`mgmt-ipv4-acl-config: ['aclname']`**

