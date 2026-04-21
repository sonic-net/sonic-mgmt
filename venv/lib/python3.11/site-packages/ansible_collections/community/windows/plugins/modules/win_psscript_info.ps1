#!powershell

# Copyright: (c) 2020, Brian Scholer <@briantist>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#Requires -Module Ansible.ModuleUtils.CamelConversion
#Requires -Module PowerShellGet

$spec = @{
    options = @{
        name = @{ type = 'str' ; default = '*' }
        repository = @{ type = 'str' }
    }
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

function Convert-ObjectToSnakeCase {
    <#
        .SYNOPSIS
        Converts an object with CamelCase properties to a dictionary with snake_case keys.
        Works in the spirit of and depends on the existing CamelConversion module util.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [OutputType([System.Collections.Specialized.OrderedDictionary])]
        [Object]
        $InputObject ,

        [Parameter()]
        [Switch]
        $NoRecurse ,

        [Parameter()]
        [Switch]
        $OmitNull
    )

    Process {
        $result = [Ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $value = $property.Value
            if (-not $NoRecurse -and $value -is [System.Collections.IDictionary]) {
                $value = Convert-DictToSnakeCase -dict $value
            }
            elseif (-not $NoRecurse -and ($value -is [Array] -or $value -is [System.Collections.ArrayList])) {
                $value = Convert-ListToSnakeCase -list $value
            }
            elseif ($null -eq $value) {
                if ($OmitNull) {
                    continue
                }
            }
            elseif (-not $NoRecurse -and $value -isnot [System.ValueType] -and $value -isnot [string]) {
                $value = Convert-ObjectToSnakeCase -InputObject $value
            }

            $name = Convert-StringToSnakeCase -string $property.Name
            $result[$name] = $value
        }
        $result
    }
}

function ConvertTo-SerializableScriptInfo {
    <#
        .SYNOPSIS
        Transforms some members of a PSRepositoryItemInfo object to be more serialization-friendly.

        .DESCRIPTION
        Stringifies [DateTime], [enum], and [type] values for serialization
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object]
        $InputObject ,

        [Parameter()]
        [string[]]
        $ExcludeProperty = @(
            <#
                Includes is for modules, containing the stuff they export.
            #>
            'Includes' ,

            <#
                This is always 'Script' for scripts.
            #>
            'Type'
        )
    )

    Process {
        $properties = foreach ($p in $InputObject.PSObject.Properties) {
            $pName = $p.Name
            $pValue = $p.Value

            if ($pValue -is [datetime]) {
                @{
                    Name = $pName
                    Expression = { $pValue.ToString('o') }.GetNewClosure()
                }
            }
            elseif ($pValue -is [enum] -or $pValue -is [type]) {
                @{
                    Name = $pName
                    Expression = { $pValue.ToString() }.GetNewClosure()
                }
            }
            else {
                $pName
            }
        }

        $InputObject | Select-Object -Property $properties -ExcludeProperty $ExcludeProperty
    }
}

$module.Result.scripts = @(
    Get-InstalledScript -Name $module.Params.name -ErrorAction SilentlyContinue |
        Where-Object -FilterScript { -not $module.Params.repository -or $_.Repository -eq $module.Params.repository } |
        ConvertTo-SerializableScriptInfo |
        Convert-ObjectToSnakeCase -NoRecurse
)

$module.ExitJson()
