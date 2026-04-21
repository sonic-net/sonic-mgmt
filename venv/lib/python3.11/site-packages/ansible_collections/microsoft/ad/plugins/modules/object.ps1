#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'type'
            Option = @{ type = 'str' }

            Attribute = 'objectClass'
            StateRequired = 'present'
            New = {
                param ($Module, $ADParams, $NewParams)

                $NewParams.Type = $Module.Params.type
                $Module.Diff.after.type = $Module.Params.type
            }
            Set = {
                param ($Module, $ADParams, $SetParams, $ADObject)

                $Module.Diff.after.type = $ADObject.ObjectClass

                if ($ADObject.ObjectClass -ne $Module.Params.type) {
                    $msg = -join @(
                        "Cannot change object type $($ADObject.ObjectClass) of existing object "
                        "$($ADObject.DistinguishedName) to $($Module.Params.type)"
                    )
                    $Module.FailJson($msg)
                }
            }
        }
    )
}
Invoke-AnsibleADObject @setParams
