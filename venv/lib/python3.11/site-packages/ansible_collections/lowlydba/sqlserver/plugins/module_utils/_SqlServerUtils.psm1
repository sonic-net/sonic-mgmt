# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Private

function Get-LowlyDbaSqlServerAuthSpec {
    <#
        .SYNOPSIS
        Output the auth spec used by every module.

        .DESCRIPTION
        Standardized way to access the common auth spec for modules.
        Uses the recommended Ansible naming convention.
    #>
    @{
        options = @{
            sql_instance = @{type = 'str'; required = $true }
            sql_username = @{type = 'str'; required = $false }
            sql_password = @{type = 'str'; required = $false; no_log = $true }
        }
        required_together = @(
            , @('sql_username', 'sql_password')
        )
    }
}

function Get-SqlCredential {
    <#
        .SYNOPSIS
        Build a credential object for SQL Authentication.

        .DESCRIPTION
        Standardized way to build a SQL Credential object that is required for SQL Authentication.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_.GetType().FullName -eq 'Ansible.Basic.AnsibleModule' })]
        $Module
    )
    try {
        $sqlInstance = $module.Params.sql_instance
        if ($null -ne $Module.Params.sql_username) {
            [securestring]$secPassword = ConvertTo-SecureString $Module.Params.sql_password -AsPlainText -Force
            [pscredential]$sqlCredential = New-Object System.Management.Automation.PSCredential ($Module.Params.sql_username, $secPassword)
        }
        else {
            $sqlCredential = $null
        }
        return $sqlInstance, $sqlCredential
    }
    catch {
        Write-Error ("Error building Credential for SQL Authentication spec.")
    }
}

function ConvertTo-SerializableObject {
    <#
        .SYNOPSIS
        Transforms some members of a DbaTools result objects to be more serialization-friendly and prevent infinite recursion.

        .DESCRIPTION
        Stringifies version properties so we don't get serialized [System.Version] objects which aren't very useful.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object]
        $InputObject,
        [Parameter()]
        [string[]]
        $ExcludeProperty = @(
            <#
                Returning a list of properties as a property is redundant.
            #>
            'Properties',
            <#
                Urn is not useful.
            #>
            'Urn',
            <#
                ExecutionManager can contain a login password in plain text.
            #>
            'ExecutionManager',
            <#
                UserData is not useful.
            #>
            'UserData',
            <#
                ParentCollection is redundant.
            #>
            'ParentCollection',
            <#
                DatabaseEngineEdition is not useful.
            #>
            'DatabaseEngineEdition',
            <#
                DatabaseEngineType is not useful.
            #>
            'DatabaseEngineType',
            <#
                ServerVersion is not useful.
            #>
            'ServerVersion',
            <#
                Server is redundant.
            #>
            'Server',
            <#
                Parent is not useful.
            #>
            'Parent'
        ),
        [bool]$UseDefaultProperty = $true
    )

    Begin {
        # We need to remove this type data so that arrays don't get serialized weirdly.
        # In some cases, an array gets serialized as an object with a Count and Value property where the value is the actual array.
        # See: https://stackoverflow.com/a/48858780/3905079
        # This only affects Windows PowerShell.
        # This has to come after the AnsibleModule is created, otherwise it will break the sanity tests.
        if (-not $IsLinux) {
            Remove-TypeData -TypeName System.Array -ErrorAction SilentlyContinue
        }
    }

    Process {
        $defaultProperty = $InputObject.PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames
        if ($defaultProperty -and $UseDefaultProperty) {
            $objectProperty = $InputObject.PSObject.Properties | Where-Object { $_.Name -in $defaultProperty -and $_.Name -notin $ExcludeProperty }
        }
        else {
            $objectProperty = $InputObject.PSObject.Properties | Where-Object { $_.Name -notin $ExcludeProperty }
        }
        $properties = foreach ($p in $objectProperty) {
            $pName = $p.Name
            $pValue = $p.Value

            switch ($p) {
                { $null -eq $pValue } {
                    @{
                        Name = $pName
                        Expression = { $null }.GetNewClosure()
                    }
                    break
                }
                { $pValue -is [datetime] } {
                    @{
                        Name = $pName
                        Expression = { $pValue.ToString('o') }.GetNewClosure()
                    }
                    break
                }
                { $pValue -is [enum] -or $pValue -is [type] } {
                    @{
                        Name = $pName
                        Expression = { $pValue.ToString() }.GetNewClosure()
                    }
                    break
                }
                { $pValue.GetType().Name -like '*Collection' } {
                    @{
                        Name = $pName
                        Expression = { [string[]]($pValue.Name) }.GetNewClosure()
                    }
                    break
                }
                { $pValue.GetType().Name -eq 'User' } {
                    @{
                        Name = $pName
                        Expression = { [string[]]($pValue.Name) }.GetNewClosure()
                    }
                    break
                }
                default { $pName }
            }
        }
        return $InputObject | Select-Object -Property $properties
    }
}

$exportMembers = @("Get-SqlCredential", "ConvertTo-SerializableObject", "Get-LowlyDbaSqlServerAuthSpec")
Export-ModuleMember -Function $exportMembers
