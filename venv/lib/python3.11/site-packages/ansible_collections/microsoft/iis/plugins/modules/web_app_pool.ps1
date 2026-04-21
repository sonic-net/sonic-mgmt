#!powershell

# Copyright: (c) 2015, Henrik Wallström <henrik@wallstroms.nu>
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        name = @{
            required = $true
            type = "str"
        }
        state = @{
            type = "str"
            default = "present"
            choices = @("absent", "present", "restarted", "started", "stopped")
        }
        attributes = @{
            type = "dict"
            # default empty dictionary to ensure it's always a dictionary
            default = @{}
        }
    }
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$name = $module.Params.name
$state = $module.Params.state
$check_mode = $module.CheckMode
$module.Result.changed = $false

# Stores the free form attributes for the module
$attributes = $module.Params.attributes

Function Get-DotNetClassForAttribute($attribute_parent) {
    switch ($attribute_parent) {
        "attributes" { [Microsoft.Web.Administration.ApplicationPool] }
        "cpu" { [Microsoft.Web.Administration.ApplicationPoolCpu] }
        "failure" { [Microsoft.Web.Administration.ApplicationPoolFailure] }
        "processModel" { [Microsoft.Web.Administration.ApplicationPoolProcessModel] }
        "recycling" { [Microsoft.Web.Administration.ApplicationPoolRecycling] }
        default { [Microsoft.Web.Administration.ApplicationPool] }
    }
}

Function Convert-CollectionToList($collection) {
    $list = @()

    if ($collection -is [String]) {
        $raw_list = $collection -split ","
        foreach ($entry in $raw_list) {
            $list += $entry.Trim()
        }
    }
    elseif ($collection -is [Microsoft.IIs.PowerShell.Framework.ConfigurationElement]) {
        # the collection is the value from IIS itself, we need to conver accordingly
        foreach ($entry in $collection.Collection) {
            $list += $entry.Value.ToString()
        }
    }
    elseif ($collection -isnot [Array]) {
        $list += $collection
    }
    else {
        $list = $collection
    }

    return , $list
}

Function Compare-Value($current, $new) {
    if ($null -eq $current) {
        return $true
    }

    if ($current -is [Array]) {
        if ($new -isnot [Array]) {
            return $true
        }

        if ($current.Count -ne $new.Count) {
            return $true
        }
        for ($i = 0; $i -lt $current.Count; $i++) {
            if ($current[$i] -ne $new[$i]) {
                return $true
            }
        }
    }
    else {
        if ($current -ne $new) {
            return $true
        }
    }
    return $false
}

Function Convert-ToPropertyValue($pool, $attribute_key, $attribute_value) {
    # Will convert the new value to the enum value expected and cast accordingly to the type
    if ([bool]($attribute_value.PSobject.Properties -match "Value")) {
        $attribute_value = $attribute_value.Value
    }
    $attribute_key_split = $attribute_key -split "\."
    if ($attribute_key_split.Length -eq 1) {
        $attribute_parent = "attributes"
        $attribute_child = $attribute_key
        $attribute_meta = $pool.Attributes | Where-Object { $_.Name -eq $attribute_child }
    }
    elseif ($attribute_key_split.Length -gt 1) {
        $attribute_parent = $attribute_key_split[0]
        $attribute_key_split = $attribute_key_split[1..$($attribute_key_split.Length - 1)]
        $parent = $pool.$attribute_parent

        foreach ($key in $attribute_key_split) {
            $attribute_meta = $parent.Attributes | Where-Object { $_.Name -eq $key }
            $parent = $parent.$key
            if ($null -eq $attribute_meta) {
                $attribute_meta = $parent
            }
        }
        $attribute_child = $attribute_key_split[-1]
    }

    if ($attribute_meta) {
        if (($attribute_meta.PSObject.Properties.Name -eq "Collection").Count -gt 0) {
            return , (Convert-CollectionToList -collection $attribute_value)
        }
        $type = $attribute_meta.Schema.Type
        $value = $attribute_value
        if ($type -eq "enum") {
            # Attempt to convert the value from human friendly to enum value - use existing value if we fail
            $dot_net_class = Get-DotNetClassForAttribute -attribute_parent $attribute_parent
            $enum_attribute_name = $attribute_child.Substring(0, 1).ToUpper() + $attribute_child.Substring(1)
            $enum = $dot_net_class.GetProperty($enum_attribute_name).PropertyType.FullName
            if ($enum) {
                $enum_values = [Enum]::GetValues($enum)
                foreach ($enum_value in $enum_values) {
                    if ($attribute_value.GetType() -is $enum_value.GetType()) {
                        if ($enum_value -eq $attribute_value) {
                            $value = $enum_value
                            break
                        }
                    }
                    else {
                        if ([System.String]$enum_value -eq [System.String]$attribute_value) {
                            $value = $enum_value
                            break
                        }
                    }
                }
            }
        }
        # Try and cast the variable using the chosen type, revert to the default if it fails
        Set-Variable -Name casted_value -Value ($value -as ([type] $attribute_meta.TypeName))
        if ($null -eq $casted_value) {
            $value
        }
        else {
            $casted_value
        }
    }
    else {
        $attribute_value
    }
}

# Ensure WebAdministration module is loaded
if ($null -eq (Get-Module -Name "WebAdministration" -ErrorAction SilentlyContinue)) {
    Import-Module WebAdministration
    $web_admin_dll_path = Join-Path $env:SystemRoot system32\inetsrv\Microsoft.Web.Administration.dll
    Add-Type -LiteralPath $web_admin_dll_path
}

$pool = Get-Item -LiteralPath IIS:\AppPools\$name -ErrorAction SilentlyContinue
if ($state -eq "absent") {
    # Remove pool if present
    if ($pool) {
        try {
            Remove-WebAppPool -Name $name -WhatIf:$check_mode
        }
        catch {
            $module.FailJson("Failed to remove Web App pool $($name): $($_.Exception.Message)", $_)
        }
        $module.Result.changed = $true
    }
}
else {
    # Add pool if absent
    if (-not $pool) {
        if (-not $check_mode) {
            try {
                New-WebAppPool -Name $name > $null
            }
            catch {
                $module.FailJson("Failed to create new Web App Pool $($name): $($_.Exception.Message)", $_)
            }
        }
        $module.Result.changed = $true
        # If in check mode this pool won't actually exists so skip it
        if (-not $check_mode) {
            $pool = Get-Item -LiteralPath IIS:\AppPools\$name
        }
    }

    # Cannot run the below in check mode if the pool did not always exist
    if ($pool) {
        # Modify pool based on parameters
        foreach ($attribute in $attributes.GetEnumerator()) {
            $attribute_key = $attribute.Key
            $new_raw_value = $attribute.Value
            $new_value = Convert-ToPropertyValue -pool $pool -attribute_key $attribute_key -attribute_value $new_raw_value

            $current_raw_value = Get-ItemProperty -LiteralPath IIS:\AppPools\$name -Name $attribute_key -ErrorAction SilentlyContinue
            $current_value = Convert-ToPropertyValue -pool $pool -attribute_key $attribute_key -attribute_value $current_raw_value

            $changed = Compare-Value -current $current_value -new $new_value
            if ($changed -eq $true) {
                if ($new_value -is [Array]) {
                    try {
                        Clear-ItemProperty -LiteralPath IIS:\AppPools\$name -Name $attribute_key -WhatIf:$check_mode
                    }
                    catch {
                        $msg = -join @(
                            "Failed to clear attribute to Web App Pool $name. Attribute: $attribute_key, "
                            "Exception: $($_.Exception.Message)"
                        )
                        $module.FailJson($msg, $_)
                    }
                    foreach ($value in $new_value) {
                        try {
                            New-ItemProperty -LiteralPath IIS:\AppPools\$name -Name $attribute_key -Value @{value = $value } -WhatIf:$check_mode > $null
                        }
                        catch {
                            $msg = -join @(
                                "Failed to add new attribute to Web App Pool $name. Attribute: $attribute_key, "
                                "Value: $value, Exception: $($_.Exception.Message)"
                            )
                            $module.FailJson($msg, $_)
                        }
                    }
                }
                else {
                    try {
                        Set-ItemProperty -LiteralPath IIS:\AppPools\$name -Name $attribute_key -Value $new_value -WhatIf:$check_mode
                    }
                    catch {
                        $msg = -join @(
                            "Failed to set attribute to Web App Pool $name. Attribute: $attribute_key, "
                            "Value: $new_value, Exception: $($_.Exception.Message)"
                        )
                        $module.FailJson($msg, $_)
                    }
                }
                $module.Result.changed = $true
            }
        }

        # Set the state of the pool
        if ($pool.State -eq "Stopped") {
            if ($state -eq "started" -or $state -eq "restarted") {
                if (-not $check_mode) {
                    try {
                        Start-WebAppPool -Name $name > $null
                    }
                    catch {
                        $module.FailJson("Failed to start Web App Pool $($name): $($_.Exception.Message)", $_)
                    }
                }
                $module.Result.changed = $true
            }
        }
        else {
            if ($state -eq "stopped") {
                if (-not $check_mode) {
                    try {
                        Stop-WebAppPool -Name $name > $null
                    }
                    catch {
                        $module.FailJson("Failed to stop Web App Pool $($name): $($_.Exception.Message)", $_)
                    }
                }
                $module.Result.changed = $true
            }
            elseif ($state -eq "restarted") {
                if (-not $check_mode) {
                    try {
                        Restart-WebAppPool -Name $name > $null
                    }
                    catch {
                        $module.FailJson("Failed to restart Web App Pool $($name): $($_.Exception.Message)", $_)
                    }
                }
                $module.Result.changed = $true
            }
        }
    }
}

$module.ExitJson()
