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

# We need to remove this type data so that arrays don't get serialized weirdly.
# In some cases, an array gets serialized as an object with a Count and Value property where the value is the actual array.
# See: https://stackoverflow.com/a/48858780/3905079
Remove-TypeData System.Array

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

function ConvertTo-SerializableModuleInfo {
    <#
        .SYNOPSIS
        Transforms some members of a ModuleInfo object to be more serialization-friendly and prevent infinite recursion.

        .DESCRIPTION
        Stringifies version properties so we don't get serialized [System.Version] objects which aren't very useful.

        ExportedCommands and some other Exported* members are problematic in a few ways.
        For one, they contain a reference to the full ModuleInfo object they are found in. This is probably useful
        for nested modules and such, but in most cases they are just a reference to the current module, and this will
        recurse infinitely.

        Further, the rest of the properties of the exported commands aren't needed for this module. A low depth on JSON
        conversion doesn't fully work because some other module fields need it deeper than 1, and since this is a
        dictionary we get a JSOn object whose property names and values are both just the name of the command.

        So instead we just make an array of the names, as that's good enough for what we want to return.

        NestedModules and RequiredModules are full ModuleInfo objects so that becomes a recursive call.
        Limiting depth or reference counting shouldn't be necessary because the entries aren't references; they
        have to actually exist.

        ModuleList gets recursed as well even though it's a tiny subset of fields, to transform versions and to
        convert to snake_case.

        PrivateData can contain any data but a module manifest is a static file that can't contain references or
        problematic types like [Type]. Unfortunately some module types like CIM (and presumably binary?) seem to be
        able to populate that with whatever they want.

        As a precaution then, for module type that is not Script or Manifest, we limit PrivateData to a shallow depth.
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
                Definition is the script that makes up the script module.
                Big to return from this module, but also it doesn't ever seem to be filled in
                in the data from Get-Module -ListAvailable.
            #>
            'Definition',
            <#
                OnRemove is a script that gets run before the module is removed.
                Not necessary for return.
            #>
            'OnRemove',
            <#
                For binary modules, ImplementingAssembly is a reference to the assembly.
                No use returning it.
            #>
            'ImplementingAssembly',
            <#
                The session state instance of a loaded module. It's a runtime property only returned
                without -ListAvailable and has no value serialized.
            #>
            'SessionState'
        )
    )

    Process {
        $properties = foreach ($p in $InputObject.PSObject.Properties) {
            $pName = $p.Name
            $pValue = $p.Value

            switch -Regex ($pName) {
                '^PrivateData$' {
                    if (
                        $InputObject.ModuleType -notin @(
                            [System.Management.Automation.ModuleType]::Script,
                            [System.Management.Automation.ModuleType]::Manifest
                        )
                    ) {
                        $safeVal = $pValue | ConvertTo-Json -Depth 1 | ConvertFrom-Json
                        @{
                            Name = $pName
                            Expression = { $safeVal }.GetNewClosure()
                        }
                    }
                    else {
                        $pName
                    }
                    break
                }
                '^(?:NestedModules|ModuleList|RequiredModules)$' {
                    # Nested and Required modules are full moduleinfo objects
                    # ModuleList isn't but its simplified fields need much of the same treatment
                    if ($pValue) {
                        @{
                            Name = $pName
                            Expression = {
                                @(, ($pValue | ConvertTo-SerializableModuleInfo | Convert-ObjectToSnakeCase -NoRecurse))
                            }.GetNewClosure()
                        }
                    }
                    else {
                        $pName
                    }
                    break
                }
                'Version$' {
                    @{
                        Name = $pName
                        Expression = { $pValue.ToString() }.GetNewClosure()
                    }
                    break
                }
                '^Exported' {
                    @{
                        Name = $pName
                        Expression = { @(, $pValue.Keys) }.GetNewClosure()
                    }
                    break
                }
                default {
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
            }
        }

        $InputObject | Select-Object -Property $properties -ExcludeProperty $ExcludeProperty
    }
}

function Add-ModuleRepositoryInfo {
    <#
        .SYNOPSIS
        Takes a ModuleInfo object and adds some info that came from PowerShellGet

        .DESCRIPTION
        Checks if there's information from Get-InstalledModule about the current module,
        and if so adds to it to ModuleInfo object. The fields are always added, with null
        values if need be.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $InputObject ,

        [Parameter()]
        [String]
        $RepositoryName
    )

    Begin {
        $wantedProperties = @(
            'PublishedDate',
            'InstalledDate',
            'UpdatedDate',
            'Dependencies',
            'Repository',
            'PackageManagementProvider',
            'InstalledLocation',
            'RepositorySourceLocation',
            'Tags',
            'CompatiblePSEditions',
            'LicenseUri',
            'ProjectUri',
            'IconUri',
            'ReleaseNotes',
            'ExportedDscResources', # ExportedDscResources is not returned here, this is a hack for Windows 2012/R2 to ensure the field is present
            'Prefix'                # Prefix is not actually returned here, this is a hack for Windows 2012 just to ensure the field is present
        )

        # Get all the installed modules at once. This prevents us from having to make an expensive individual call for every
        # local module, the vast majority of which didn't come from PowerShellGet.
        # The results here won't contain every version, but that's ok because we'll still have a fast signal as to whether
        # it makes sense to make a version-specific call for the individual module.
        $installedModules = Get-InstalledModule -ErrorAction SilentlyContinue | Group-Object -Property Name -AsHashTable -AsString
    }

    Process {
        $moduleName = $InputObject.Name

        $installed = if ($installedModules -and $installedModules.Contains($moduleName)) {
            # we know at least one version of this module was installed from PowerShellGet
            # if the version of this local modle matches what we got it in the initial installed module list
            # use it
            if ($installedModules[$moduleName].Version -eq $InputObject.Version) {
                $installedModules[$moduleName]
            }
            else {
                # make an individual call to see if this specific version of the local module was installed from PowerShellGet
                $im = Get-InstalledModule -Name $InputObject.Name -RequiredVersion $InputObject.Version -AllowPrerelease -ErrorAction SilentlyContinue
                if ($im) {
                    $im
                }
            }
        }

        if ($RepositoryName -and $installed.Repository -ne $RepositoryName) {
            return
        }

        $members = @{}
        $wantedProperties | ForEach-Object -Process {
            if (-not $InputObject.$_) {
                # if the fields are present in both places, let's prefer what's sent in
                $members[$_] = $installed.$_
            }
        }

        $InputObject | Add-Member -NotePropertyMembers $members -Force -PassThru
    }
}

$module.Result.modules = @(
    Get-Module -ListAvailable -Name $module.Params.name |
        Add-ModuleRepositoryInfo -RepositoryName $module.Params.repository |
        ConvertTo-SerializableModuleInfo |
        Convert-ObjectToSnakeCase -NoRecurse
)

$module.ExitJson()
