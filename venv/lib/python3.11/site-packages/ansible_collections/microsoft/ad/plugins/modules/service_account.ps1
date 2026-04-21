#!powershell

# Copyright: (c) 2024, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'allowed_to_retrieve_password'
            Option = @{
                # The values aren't password, will satisfy sanity tests
                no_log = $false
                type = 'add_remove_set'
            }
            Attribute = 'PrincipalsAllowedToRetrieveManagedPassword'
            DNLookup = $true
        }
        [PSCustomObject]@{
            Name = 'delegates'
            Option = @{
                aliases = 'principals_allowed_to_delegate'
                type = 'add_remove_set'
            }
            Attribute = 'PrincipalsAllowedToDelegateToAccount'
            DNLookup = $true
        }
        [PSCustomObject]@{
            Name = 'dns_hostname'
            Option = @{ type = 'str' }
            Attribute = 'DNSHostName'
        }
        [PSCustomObject]@{
            Name = 'do_not_append_dollar_to_sam'
            Option = @{
                default = $false
                type = 'bool'
            }
        }
        [PSCustomObject]@{
            Name = 'enabled'
            Option = @{ type = 'bool' }
            Attribute = 'Enabled'
        }
        [PSCustomObject]@{
            Name = 'kerberos_encryption_types'
            Option = @{
                type = 'add_remove_set'
                choices = 'aes128', 'aes256', 'des', 'rc4'
            }
            Attribute = 'KerberosEncryptionType'
            CaseInsensitive = $true

            New = {
                param($Module, $ADParams, $NewParams)

                $encTypes = @(
                    $Module.Params.kerberos_encryption_types.add
                    $Module.Params.kerberos_encryption_types.set
                ) | Select-Object -Unique

                $NewParams.KerberosEncryptionType = $encTypes
                $Module.Diff.after.kerberos_encryption_types = $MencTypes
            }
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                # This is an enum value and needs custom handling for things like
                # unsetting the values with none.
                $rawValue = $ADObject.KerberosEncryptionType.Value

                $existing = foreach ($v in [System.Enum]::GetValues($rawValue.GetType())) {
                    if ($rawValue -band $v) { $v.ToString() }
                }
                if ($existing -eq 'None') {
                    $existing = @()
                }
                $module.Diff.before.kerberos_encryption_types = $existing

                $desired = $Module.Params.kerberos_encryption_types
                $compareParams = @{
                    Existing = $existing
                    CaseInsensitive = $true
                }
                $res = Compare-AnsibleADIdempotentList @compareParams @desired
                if ($res.Changed) {
                    if ($res.Value) {
                        $SetParams.KerberosEncryptionType = $res.Value -join ', '
                    }
                    else {
                        $SetParams.KerberosEncryptionType = 'None'
                    }
                }
                $module.Diff.after.kerberos_encryption_types = $res.Value
            }
        }
        [PSCustomObject]@{
            Name = 'outbound_auth_only'
            Option = @{
                default = $false
                type = 'bool'
            }
        }
        [PSCustomObject]@{
            Name = 'sam_account_name'
            Option = @{ type = 'str' }
            Attribute = 'sAMAccountName'
            # New handling is done in PostAction as New-ADServiceAccount cannot
            # set a SAM without the $ suffix.
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                # Using the -SAMAccountName parameter will automatically append
                # '$' to the value. We want to set the provided user value
                # which may not have the suffix so we use the raw attribute
                # replacement method.
                $sam = $Module.Params.sam_account_name
                if ($sam -ne $ADObject.SAMAccountName) {
                    if (-not $SetParams.ContainsKey('Replace')) {
                        $SetParams['Replace'] = @{}
                    }
                    $SetParams.Replace['sAMAccountName'] = $sam
                }

                $module.Diff.after.sam_account_name = $sam
            }
        }
        [PSCustomObject]@{
            Name = 'spn'
            Option = @{
                aliases = 'spns'
                type = 'add_remove_set'
            }
            Attribute = 'servicePrincipalName'
            CaseInsensitive = $true
            IsRawAttribute = $true
        }
        [PSCustomObject]@{
            Name = 'trusted_for_delegation'
            Option = @{ type = 'bool' }
            Attribute = 'TrustedForDelegation'
        }
        [PSCustomObject]@{
            Name = 'upn'
            Option = @{ type = 'str' }
            Attribute = 'userPrincipalName'
            IsRawAttribute = $true
        }
    )
    ModuleNoun = 'ADServiceAccount'
    DefaultPath = {
        param($Module, $ADParams)

        $GUID_MANAGED_SERVICE_ACCOUNTS_CONTAINER_W = '1EB93889E40C45DF9F0C64D23BBB6237'
        $defaultNamingContext = (Get-ADRootDSE @ADParams -Properties defaultNamingContext).defaultNamingContext

        Get-ADObject @ADParams -Identity $defaultNamingContext -Properties otherWellKnownObjects |
            Select-Object -ExpandProperty otherWellKnownObjects |
            Where-Object { $_.StartsWith("B:32:$($GUID_MANAGED_SERVICE_ACCOUNTS_CONTAINER_W):") } |
            ForEach-Object Substring 38
    }
    PreAction = {
        param ($Module, $ADParams, $ADObject)

        if ($Module.Params.outbound_auth_only) {
            if ($Module.Params.dns_hostname) {
                $Module.FailJson("dns_hostname can not be set when outbound_auth_only=true.")
            }
            elseif (-not $ADObject) {
                # -RestrictToOutboundAuthenticationOnly is used in a parameter
                # set where we cannot set
                # PrincipalsAllowedToRetrieveManagedPassword. If
                # outbound_auth_only is set, we use a temp value and unset it
                # in the post action to simplify our code.
                $Module.Params.dns_hostname = [Guid]::NewGuid().ToString()
            }
        }
        elseif (
            $module.Params.state -eq 'present' -and
            -not $ADObject -and
            -not $Module.Params.dns_hostname
        ) {
            $Module.FailJson('dns_hostname is required when creating a new service account.')
        }

        if (
            $Module.Params.sam_account_name -and
            -not $Module.Params.sam_account_name.EndsWith('$') -and
            -not $Module.Params.do_not_append_dollar_to_sam
        ) {
            $Module.Params.sam_account_name = "$($Module.Params.sam_account_name)$"
        }
    }
    PostAction = {
        param($Module, $ADParams, $ADObject)

        if ($ADObject) {
            $Module.Result.sid = $ADObject.SID.Value

            $setParams = @{}
            # This should only happen when the service account was created.
            # The code will set sam_account_name to the desired value without
            # the '$' suffix.
            if (
                $Module.Params.state -eq 'present' -and
                $Module.Params.sam_account_name -and
                $Module.Params.do_not_append_dollar_to_sam -and
                $Module.Params.sam_account_name -ne $ADObject.SAMAccountName
            ) {
                $setParams['Replace'] = @{
                    sAMAccountName = $module.Params.sam_account_name
                }
            }
            if (
                $Module.Params.state -eq 'present' -and
                $Module.Params.outbound_auth_only
            ) {
                $Module.Diff.after.Remove('dns_hostname')
                $setParams['Clear'] = 'dnsHostName'
            }

            if ($setParams.Count) {
                $ADObject | Set-ADServiceAccount -WhatIf:$Module.CheckMode @ADParams @setParams
            }
        }
        elseif ($Module.Params.state -eq 'present') {
            # Use dummy value for check mode when creating a new user
            $Module.Result.sid = 'S-1-5-0000'
        }
    }
}
Invoke-AnsibleADObject @setParams
