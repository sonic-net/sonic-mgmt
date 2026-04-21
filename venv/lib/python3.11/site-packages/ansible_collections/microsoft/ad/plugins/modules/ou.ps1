#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'city'
            Option = @{ type = 'str' }
            Attribute = 'City'
        }
        [PSCustomObject]@{
            Name = 'country'
            Option = @{ type = 'str' }
            Attribute = 'Country'
        }
        [PSCustomObject]@{
            Name = 'managed_by'
            Option = @{ type = 'str' }
            Attribute = 'ManagedBy'
            DNLookup = $true
        }
        [PSCustomObject]@{
            Name = 'postal_code'
            Option = @{ type = 'str' }
            Attribute = 'PostalCode'
        }
        [PSCustomObject]@{
            Name = 'state_province'
            Option = @{ type = 'str' }
            Attribute = 'State'
        }
        [PSCustomObject]@{
            Name = 'street'
            Option = @{ type = 'str' }
            Attribute = 'StreetAddress'
        }
    )
    ModuleNoun = 'ADOrganizationalUnit'
}
Invoke-AnsibleADObject @setParams
