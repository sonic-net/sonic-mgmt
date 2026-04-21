#!powershell

# Copyright: (c) 2020, Brian Scholer <@briantist>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    supports_check_mode = $true
    options = @{
        source = @{
            type = 'path'
            default = '%LOCALAPPDATA%\Microsoft\Windows\PowerShell\PowerShellGet\PSRepositories.xml'
        }
        name = @{
            type = 'list'
            elements = 'str'
            default = @(
                '*'
            )
        }
        exclude = @{
            type = 'list'
            elements = 'str'
        }
        profiles = @{
            type = 'list'
            elements = 'str'
            default = @(
                '*'
            )
        }
        exclude_profiles = @{
            type = 'list'
            elements = 'str'
            default = @(
                'systemprofile'
                'LocalService'
                'NetworkService'
            )
        }
        force = @{
            type = 'bool'
            default = $false
        }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Diff.before = @{}
$module.Diff.after = @{}

function Select-Wildcard {
    <#
        .SYNOPSIS
        Compares a value to an Include and Exclude list of wildcards,
        returning the input object if a match is found

        .DESCRIPTION
        If $Property is specified, that property of the input object is
        compared rather than the object itself, but the original object
        is returned, not the property.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]
        $InputObject ,

        [Parameter()]
        [String]
        $Property ,

        [Parameter()]
        [String[]]
        $Include ,

        [Parameter()]
        [String[]]
        $Exclude
    )

    Process {
        $o = if ($Property) {
            $InputObject.($Property)
        }
        else {
            $InputObject
        }

        foreach ($inc in $Include) {
            $imatch = $o -like $inc
            if ($imatch) {
                break
            }
        }

        if (-not $imatch) {
            return
        }

        foreach ($exc in $Exclude) {
            if ($o -like $exc) {
                return
            }
        }

        $InputObject
    }
}

function Get-ProfileDirectory {
    <#
        .SYNOPSIS
        Returns DirectoryInfo objects for each profile on the system, as reported by the registry

        .DESCRIPTION
        The special "Default" profile, used as a template for newly created users, is explicitly
        added to the list of possible profiles returned. Public is explicitly excluded.
        Paths reported by the registry that don't exist on the filesystem are silently skipped.
    #>
    [CmdletBinding()]
    [OutputType([System.IO.DirectoryInfo])]
    param(
        [Parameter()]
        [String[]]
        $Include ,

        [Parameter()]
        [String[]]
        $Exclude
    )

    $regPL = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

    # note: this is a key named "Default", not the (Default) key
    $default = Get-ItemProperty -LiteralPath $regPL | Select-Object -ExpandProperty Default

    # "ProfileImagePath" is always the local side of the profile, even if roaming profiles are used
    # This is what we want, because PSRepositories are stored in AppData/Local and don't roam
    $profiles = (
        @($default) +
        (Get-ChildItem -LiteralPath $regPL | Get-ItemProperty | Select-Object -ExpandProperty ProfileImagePath)
    ) -as [System.IO.DirectoryInfo[]]

    $profiles |
        Where-Object -Property Exists -EQ $true |
        Select-Wildcard -Property Name -Include $Include -Exclude $Exclude
}

function ConvertTo-ComparableObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $InputObject
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        # Using a sorted dictionary to ensure consistent key ordering
        $dict = [System.Collections.Generic.SortedDictionary[string, object]]::new()
        foreach ($kvp in $InputObject.GetEnumerator()) {
            $dict[$kvp.Key] = ConvertTo-ComparableObject -InputObject $kvp.Value
        }
        $dict
    }
    elseif ($InputObject -is [System.Collections.IList]) {
        # Leading , ensures the output is an array and isn't unrolled.
        , @(
            foreach ($item in $InputObject) {
                ConvertTo-ComparableObject -InputObject $item
            }
        )
    }
    else {
        $InputObject
    }
}

function Compare-Dictionary {
    <#
    .SYNOPSIS
    Attempts to naively compare two dictionaries
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $ReferenceObject,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $DifferenceObject
    )

    $refDict = ConvertTo-ComparableObject -InputObject $ReferenceObject
    $difDict = ConvertTo-ComparableObject -InputObject $DifferenceObject

    $sRef = ConvertTo-Json -InputObject $refDict -Compress
    $sDif = ConvertTo-Json -InputObject $difDict -Compress

    $sRef -ceq $sDif
}

# load the repositories from the source file
try {
    $src = $module.Params.source
    $src_repos = Import-Clixml -LiteralPath $src -ErrorAction Stop
}
catch [System.IO.FileNotFoundException] {
    $module.FailJson("The source file '$src' was not found.", $_)
}
catch {
    $module.FailJson("There was an error loading the source file '$src': $($_.Exception.Message).", $_)
}

$profiles = Get-ProfileDirectory -Include $module.Params.profiles -Exclude $module.Params.exclude_profiles

foreach ($user in $profiles) {
    $username = $user.Name

    $repo_dir = $user.FullName | Join-Path -ChildPath 'AppData\Local\Microsoft\Windows\PowerShell\PowerShellGet'
    $repo_path = $repo_dir | Join-Path -ChildPath 'PSRepositories.xml'

    if (Test-Path -LiteralPath $repo_path) {
        $cur_repos = Import-Clixml -LiteralPath $repo_path
    }
    else {
        $cur_repos = @{}
    }

    $updated = $false
    if ($module.Params.force) {
        $new_repos = $src_repos.Clone()
        $updated = $true
    }
    else {
        $new_repos = $cur_repos.Clone()
        $src_repos.Keys |
            Select-Wildcard -Include $module.Params.name -Exclude $module.Params.exclude |
            ForEach-Object -Process {
                # explicit scope used inside ForEach-Object to satisfy lint (PSUseDeclaredVarsMoreThanAssignment)
                # see https://github.com/PowerShell/PSScriptAnalyzer/issues/827
                $Script:updated = $true
                $Script:new_repos[$_] = $Script:src_repos[$_]
            }
    }

    $module.Diff.before[$username] = $cur_repos
    $module.Diff.after[$username] = $new_repos

    if ($updated -and -not (Compare-Dictionary -ReferenceObject $cur_repos -DifferenceObject $new_repos)) {
        if (-not $module.CheckMode) {
            $null = New-Item -Path $repo_dir -ItemType Directory -Force -ErrorAction SilentlyContinue
            $new_repos | Export-Clixml -LiteralPath $repo_path -Force
        }
        $module.Result.changed = $true
    }
}

$module.ExitJson()
