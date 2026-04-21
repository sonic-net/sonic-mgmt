#!powershell

# Copyright: (c) 2017, Jordan Borean <jborean93@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.Legacy

$ErrorActionPreference = 'Stop'

$params = Parse-Args $args -supports_check_mode $true
$check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false
$diff_mode = Get-AnsibleParam -obj $Params -name "_ansible_diff" -type "bool" -default $false

$section = Get-AnsibleParam -obj $params -name "section" -type "str" -failifempty $true
$key = Get-AnsibleParam -obj $params -name "key" -type "str" -failifempty $true
$value = Get-AnsibleParam -obj $params -name "value" -failifempty $true

$result = @{
    changed = $false
    section = $section
    key = $key
    value = $value
}

if ($diff_mode) {
    $result.diff = @{}
}

Function Invoke-SecEdit($arguments) {
    $stdout = $null
    $stderr = $null
    $log_path = [IO.Path]::GetTempFileName()
    $arguments = $arguments + @("/log", $log_path)

    try {
        $stdout = &SecEdit.exe $arguments | Out-String
    }
    catch {
        $stderr = $_.Exception.Message
    }
    $log = Get-Content -LiteralPath $log_path
    Remove-Item -LiteralPath $log_path -Force

    $return = @{
        log = ($log -join "`n").Trim()
        stdout = $stdout
        stderr = $stderr
        rc = $LASTEXITCODE
    }

    return $return
}

Function Export-SecEdit() {
    # GetTempFileName() will create a file but it doesn't have any content. This is problematic as secedit uses the
    # encoding of the file at /cfg if it exists and because there is no BOM it will export using the "ANSI" encoding.
    # By making sure the file exists and has a UTF-16-LE BOM we can be sure our parser reads the bytes as a string
    # correctly.
    $secedit_ini_path = [IO.Path]::GetTempFileName()
    Set-Content -LiteralPath $secedit_ini_path -Value '' -Encoding Unicode

    # while this will technically make a change to the system in check mode by
    # creating a new file, we need these values to be able to do anything
    # substantial in check mode
    $export_result = Invoke-SecEdit -arguments @("/export", "/cfg", $secedit_ini_path, "/quiet")

    # check the return code and if the file has been populated, otherwise error out
    if (($export_result.rc -ne 0) -or ((Get-Item -LiteralPath $secedit_ini_path).Length -eq 0)) {
        Remove-Item -LiteralPath $secedit_ini_path -Force
        $result.rc = $export_result.rc
        $result.stdout = $export_result.stdout
        $result.stderr = $export_result.stderr
        Fail-Json $result "Failed to export secedit.ini file to $($secedit_ini_path)"
    }
    $secedit_ini = ConvertFrom-Ini -file_path $secedit_ini_path

    return $secedit_ini
}

Function Import-SecEdit($ini) {
    $secedit_ini_path = [IO.Path]::GetTempFileName()
    $secedit_db_path = [IO.Path]::GetTempFileName()
    Remove-Item -LiteralPath $secedit_db_path -Force # needs to be deleted for SecEdit.exe /import to work

    $ini_contents = ConvertTo-Ini -ini $ini

    # Use Unicode (UTF-16-LE) as that is the same across all PowerShell versions and we don't have to worry about
    # changing ANSI encodings.
    Set-Content -LiteralPath $secedit_ini_path -Value $ini_contents -Encoding Unicode
    $result.changed = $true

    $import_result = Invoke-SecEdit -arguments @("/configure", "/db", $secedit_db_path, "/cfg", $secedit_ini_path, "/quiet")
    $result.import_log = $import_result.log
    Remove-Item -LiteralPath $secedit_ini_path -Force
    if ($import_result.rc -ne 0) {
        $result.rc = $import_result.rc
        $result.stdout = $import_result.stdout
        $result.stderr = $import_result.stderr
        Fail-Json $result "Failed to import secedit.ini file from $($secedit_ini_path)"
    }

    # https://github.com/ansible-collections/community.windows/issues/153
    # The LegalNoticeText entry is stored in the ini with type 7 (REG_MULTI_SZ) where each comma entry is read as a
    # newline. When secedit imports the value it sets LegalNoticeText in the registry to be a REG_SZ type with the
    # newlines but it also adds the extra null char at the end that REG_MULTI_SZ uses to denote the end of an entry.
    # We manually trim off that extra null char so the legal text does not contain the unknown character symbol.
    $legalPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $legalName = 'LegalNoticeText'
    $prop = Get-ItemProperty -LiteralPath $legalPath
    if ($legalName -in $prop.PSObject.Properties.Name) {
        $existingText = $prop.LegalNoticeText.TrimEnd("`0")
        Set-ItemProperty -LiteralPath $legalPath -Name $legalName -Value $existingText
    }
}

Function ConvertTo-Ini($ini) {
    $content = @()
    foreach ($key in $ini.GetEnumerator()) {
        $section = $key.Name
        $values = $key.Value

        $content += "[$section]"
        foreach ($value in $values.GetEnumerator()) {
            $value_key = $value.Name
            $value_value = $value.Value

            if ($null -ne $value_value) {
                $content += "$value_key = $value_value"
            }
        }
    }

    return $content -join "`r`n"
}

Function ConvertFrom-Ini($file_path) {
    $ini = @{}
    switch -Regex -File $file_path {
        "^\[(.+)\]" {
            $section = $matches[1]
            $ini.$section = @{}
        }
        "(.+?)\s*=(.*)" {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            if ($value -match "^\d+$") {
                $value = [int]$value
            }
            elseif ($value.StartsWith('"') -and $value.EndsWith('"')) {
                $value = $value.Substring(1, $value.Length - 2)
            }

            $ini.$section.$name = $value
        }
    }

    return $ini
}

if ($section -eq "Privilege Rights") {
    Add-Warning -obj $result -message "Using this module to edit rights and privileges is error-prone, use the ansible.windows.win_user_right module instead"
}

$will_change = $false
$secedit_ini = Export-SecEdit
if (-not ($secedit_ini.ContainsKey($section))) {
    Fail-Json $result "The section '$section' does not exist in SecEdit.exe output ini"
}

if ($secedit_ini.$section.ContainsKey($key)) {
    $current_value = $secedit_ini.$section.$key

    if ($current_value -cne $value) {
        if ($diff_mode) {
            $result.diff.prepared = @"
[$section]
-$key = $current_value
+$key = $value
"@
        }

        $secedit_ini.$section.$key = $value
        $will_change = $true
    }
}
elseif ([string]$value -eq "") {
    # Value is requested to be removed, and has already been removed, do nothing
}
else {
    if ($diff_mode) {
        $result.diff.prepared = @"
[$section]
+$key = $value
"@
    }
    $secedit_ini.$section.$key = $value
    $will_change = $true
}

if ($will_change -eq $true) {
    $result.changed = $true
    if (-not $check_mode) {
        Import-SecEdit -ini $secedit_ini

        # secedit doesn't error out on improper entries, re-export and verify
        # the changes occurred
        $verification_ini = Export-SecEdit
        $new_section_values = $verification_ini.$section
        if ($new_section_values.ContainsKey($key)) {
            $new_value = $new_section_values.$key
            if ($new_value -cne $value) {
                Fail-Json $result "Failed to change the value for key '$key' in section '$section', the value is still $new_value"
            }
        }
        elseif ([string]$value -eq "") {
            # Value was empty, so OK if no longer in the result
        }
        else {
            Fail-Json $result "The key '$key' in section '$section' is not a valid key, cannot set this value"
        }
    }
}

Exit-Json $result
