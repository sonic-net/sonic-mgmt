#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'category'
            Option = @{
                choices = 'distribution', 'security'
                type = 'str'
            }
            Attribute = 'GroupCategory'
            CaseInsensitive = $true
        }
        [PSCustomObject]@{
            Name = 'homepage'
            Option = @{ type = 'str' }
            Attribute = 'Homepage'
        }
        [PSCustomObject]@{
            Name = 'managed_by'
            Option = @{ type = 'str' }
            Attribute = 'ManagedBy'
            DNLookup = $true
        }
        [PSCustomObject]@{
            Name = 'members'
            Option = @{ type = 'add_remove_set' }
            Attribute = 'member'
            DNLookup = $true
            IsRawAttribute = $true
            # If the group is part of the CN=Builtin groups, it cannot
            # use -Replace. This ensures it always uses -Add/-Remove when
            # setting a changed value to handle this.
            # https://github.com/ansible-collections/microsoft.ad/issues/130
            SupportsReplace = $false
        }
        [PSCustomObject]@{
            Name = 'sam_account_name'
            Option = @{ type = 'str' }
            Attribute = 'sAMAccountName'
        }
        [PSCustomObject]@{
            Name = 'scope'
            Option = @{
                choices = 'domainlocal', 'global', 'universal'
                type = 'str'
            }
            Attribute = 'GroupScope'
            CaseInsensitive = $true
        }
    )
    ModuleNoun = 'ADGroup'
    DefaultPath = {
        param($Module, $ADParams)

        $GUID_USERS_CONTAINER_W = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        $defaultNamingContext = (Get-ADRootDSE @ADParams -Properties defaultNamingContext).defaultNamingContext

        Get-ADObject @ADParams -Identity $defaultNamingContext -Properties wellKnownObjects |
            Select-Object -ExpandProperty wellKnownObjects |
            Where-Object { $_.StartsWith("B:32:$($GUID_USERS_CONTAINER_W):") } |
            ForEach-Object Substring 38
    }
    PreAction = {
        param ($Module, $ADParams, $ADObject)

        if ($Module.Params.state -eq 'present' -and (-not $Module.Params.scope) -and (-not $ADObject)) {
            $Module.FailJson("scope must be set when state=present and the group does not exist")
        }
    }
    PostAction = {
        param($Module, $ADParams, $ADObject)

        if ($ADObject) {
            $Module.Result.sid = $ADObject.SID.Value
        }
        elseif ($Module.Params.state -eq 'present') {
            # Use dummy value for check mode when creating a new user
            $Module.Result.sid = 'S-1-5-0000'
        }
    }
}
Invoke-AnsibleADObject @setParams
