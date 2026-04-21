#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.AccessToken
#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

Function Test-Credential {
    param(
        [String]$Username,
        [String]$Password,
        [String]$Domain = $null
    )
    if (($Username.ToCharArray()) -contains [char]'@') {
        # UserPrincipalName
        $Domain = $null # force $Domain to be null, to prevent undefined behaviour, as a domain name is already included in the username
    }
    elseif (($Username.ToCharArray()) -contains [char]'\') {
        # Pre Win2k Account Name
        $Domain = ($Username -split '\\')[0]
        $Username = ($Username -split '\\', 2)[-1]
    } # If no domain provided, so maybe local user, or domain specified separately.

    try {
        ([Ansible.AccessToken.TokenUtil]::LogonUser($Username, $Domain, $Password, "Network", "Default")).Dispose()
        return $true
    }
    catch [Ansible.AccessToken.Win32Exception] {
        # following errors indicate the creds are correct but the user was
        # unable to log on for other reasons, which we don't care about
        $success_codes = @(
            0x0000052F, # ERROR_ACCOUNT_RESTRICTION
            0x00000530, # ERROR_INVALID_LOGON_HOURS
            0x00000531, # ERROR_INVALID_WORKSTATION
            0x00000569  # ERROR_LOGON_TYPE_GRANTED
        )
        $failed_codes = @(
            0x0000052E, # ERROR_LOGON_FAILURE
            0x00000532, # ERROR_PASSWORD_EXPIRED
            0x00000701, # ERROR_ACCOUNT_EXPIRED
            0x00000773, # ERROR_PASSWORD_MUST_CHANGE
            0x00000533  # ERROR_ACCOUNT_DISABLED
        )

        if ($_.Exception.NativeErrorCode -in $failed_codes) {
            return $false
        }
        elseif ($_.Exception.NativeErrorCode -in $success_codes) {
            return $true
        }
        else {
            # an unknown failure, reraise exception
            throw $_
        }
    }
}

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'account_locked'
            Option = @{
                choices = @(, $false)
                type = 'bool'
            }
            Attribute = 'LockedOut'
            # We cannot lock a user and creating a user that is unlocked
            # requires no action.
            New = {}
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                if ($ADObject.LockedOut) {
                    Unlock-ADAccount @ADParams -Identity $ADObject.ObjectGUID -WhatIf:$Module.CheckMode
                    $Module.Result.changed = $true
                }

                $Module.Diff.after.account_locked = $false
            }
        }

        [PSCustomObject]@{
            Name = 'city'
            Option = @{ type = 'str' }
            Attribute = 'City'
        }

        [PSCustomObject]@{
            Name = 'company'
            Option = @{ type = 'str' }
            Attribute = 'company'
        }

        [PSCustomObject]@{
            Name = 'country'
            Option = @{ type = 'str' }
            Attribute = 'Country'
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
            Name = 'email'
            Option = @{ type = 'str' }
            Attribute = 'EmailAddress'
        }

        [PSCustomObject]@{
            Name = 'enabled'
            Option = @{ type = 'bool' }
            Attribute = 'Enabled'
        }

        [PSCustomObject]@{
            Name = 'firstname'
            Option = @{ type = 'str' }
            Attribute = 'givenName'
        }

        [PSCustomObject]@{
            Name = 'groups'
            Option = @{
                type = 'dict'
                options = @{
                    add = @{ type = 'list'; elements = 'raw' }
                    remove = @{ type = 'list'; elements = 'raw' }
                    set = @{ type = 'list'; elements = 'raw' }
                    lookup_failure_action = @{
                        aliases = @('missing_behaviour')
                        choices = 'fail', 'ignore', 'warn'
                        default = 'fail'
                        type = 'str'
                    }
                    permissions_failure_action = @{
                        choices = 'fail', 'ignore', 'warn'
                        default = 'fail'
                        type = 'str'
                    }

                }
            }
        }

        [PSCustomObject]@{
            Name = 'password'
            Option = @{
                no_log = $true
                type = 'str'
            }
            New = {
                param($Module, $ADParams, $NewParams)

                $NewParams.AccountPassword = (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.password)
                $Module.Diff.after.password = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
            }
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                $Module.Diff.before.password = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'

                $changed = switch ($Module.Params.update_password) {
                    always { $true }
                    on_create { $false }
                    when_changed {
                        # Try and use the UPN but fallback to msDS-PrincipalName if none is defined
                        $username = $ADObject.UserPrincipalName
                        if (-not $username) {
                            $username = $ADObject['msDS-PrincipalName']
                        }

                        -not (Test-Credential -Username $username -Password $module.Params.password)
                    }
                }

                if (-not $changed) {
                    $Module.Diff.after.password = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
                    return
                }

                # -WhatIf was broken until Server 2016 and will set the
                # password. Just avoid calling this in check mode.
                if (-not $Module.CheckMode) {
                    $setParams = @{
                        Identity = $ADObject.ObjectGUID
                        Reset = $true
                        Confirm = $false
                        NewPassword = (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.password)
                    }
                    Set-ADAccountPassword @setParams @ADParams
                }

                $Module.Diff.after.password = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER - changed'
                $Module.Result.changed = $true
            }
        }

        [PSCustomObject]@{
            Name = 'password_expired'
            Option = @{ type = 'bool' }
            Attribute = 'PasswordExpired'
            New = {
                param($Module, $ADParams, $NewParams)

                $NewParams.ChangePasswordAtLogon = $module.Params.password_expired
                $Module.Diff.after.password_expired = $module.Params.password_expired
            }
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                if ($ADObject.PasswordExpired -ne $Module.Params.password_expired) {
                    $SetParams.ChangePasswordAtLogon = $Module.Params.password_expired
                }

                $Module.Diff.after.password_expired = $Module.Params.password_expired
            }
        }

        [PSCustomObject]@{
            Name = 'password_never_expires'
            Option = @{ type = 'bool' }
            Attribute = 'PasswordNeverExpires'
        }

        [PSCustomObject]@{
            Name = 'postal_code'
            Option = @{ type = 'str' }
            Attribute = 'PostalCode'
        }

        [PSCustomObject]@{
            Name = 'sam_account_name'
            Option = @{ type = 'str' }
            Attribute = 'sAMAccountName'
        }

        [PSCustomObject]@{
            Name = 'spn'
            Option = @{
                aliases = 'spns'
                type = 'dict'
                options = @{
                    add = @{ type = 'list'; elements = 'str' }
                    remove = @{ type = 'list'; elements = 'str' }
                    set = @{ type = 'list'; elements = 'str' }
                }
            }
            Attribute = 'ServicePrincipalNames'
            New = {
                param($Module, $ADParams, $NewParams)

                $spns = @(
                    $Module.Params.spn.add
                    $Module.Params.spn.set
                ) | Select-Object -Unique

                $NewParams.ServicePrincipalNames = $spns
                $Module.Diff.after.spn = $spns
            }
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                $desired = $Module.Params.spn
                $compareParams = @{
                    Existing = $ADObject.ServicePrincipalNames
                    CaseInsensitive = $true
                }
                $res = Compare-AnsibleADIdempotentList @compareParams @desired
                if ($res.Changed) {
                    $SetParams.ServicePrincipalNames = @{}
                    if ($res.ToAdd) {
                        $SetParams.ServicePrincipalNames.Add = $res.ToAdd
                    }
                    if ($res.ToRemove) {
                        $SetParams.ServicePrincipalNames.Remove = $res.ToRemove
                    }
                }
                $module.Diff.after.spn = @($res.Value | Sort-Object)
            }
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

        [PSCustomObject]@{
            Name = 'surname'
            Option = @{
                aliases = 'lastname'
                type = 'str'
            }
            Attribute = 'Surname'
        }

        [PSCustomObject]@{
            Name = 'update_password'
            Option = @{
                choices = 'always', 'on_create', 'when_changed'
                default = 'always'
                type = 'str'
            }
        }

        [PSCustomObject]@{
            Name = 'upn'
            Option = @{ type = 'str' }
            Attribute = 'userPrincipalName'
        }

        [PSCustomObject]@{
            Name = 'user_cannot_change_password'
            Option = @{ type = 'bool' }
            Attribute = 'CannotChangePassword'
        }
    )
    ModuleNoun = 'ADUser'
    DefaultPath = {
        param($Module, $ADParams)

        $GUID_USERS_CONTAINER_W = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        $defaultNamingContext = (Get-ADRootDSE @ADParams -Properties defaultNamingContext).defaultNamingContext

        Get-ADObject @ADParams -Identity $defaultNamingContext -Properties wellKnownObjects |
            Select-Object -ExpandProperty wellKnownObjects |
            Where-Object { $_.StartsWith("B:32:$($GUID_USERS_CONTAINER_W):") } |
            ForEach-Object Substring 38
    }
    ExtraProperties = @(
        # Used for password when checking if the password is valid
        'msDS-PrincipalName'
    )
    PreAction = {
        param ($Module, $ADParams, $ADObject)

        if (
            $Module.Params.state -eq 'present' -and
            $null -eq $ADObject -and
            $null -eq $Module.Params.enabled
        ) {
            $Module.Params.enabled = -not ([String]::IsNullOrWhiteSpace($Module.Params.password))
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

        if ($null -eq $Module.Params.groups -or $Module.Params.groups.Count -eq 0 -or $Module.Params.state -eq 'absent') {
            return
        }

        [string[]]$existingGroups = @(
            # In check mode the ADObject won't be given
            if ($ADObject) {
                try {
                    # Get-ADPrincipalGroupMembership doesn't work well with
                    # cross domain membership. It also gets the primary group
                    # so this code reflects that using Get-ADUser instead.
                    $userMembership = Get-ADUser -Identity $ADObject.ObjectGUID @ADParams -Properties @(
                        'MemberOf',
                        'PrimaryGroup'
                    ) -ErrorAction Stop
                    $userMembership.memberOf
                    $userMembership.PrimaryGroup
                }
                catch {
                    $module.Warn("Failed to enumerate user groups but continuing on: $($_.Exception.Message)")
                }
            }
        )

        if ($Module.Diff.before) {
            $Module.Diff.before.groups = @($existingGroups | Sort-Object)
        }

        $compareParams = @{
            CaseInsensitive = $true
            Existing = $existingGroups
        }
        $dnServerParams = @{}
        foreach ($actionKvp in $Module.Params.groups.GetEnumerator()) {
            if ($null -eq $actionKvp.Value -or $actionKvp.Key -in @('lookup_failure_action', 'missing_behaviour', 'permissions_failure_action')) {
                continue
            }

            $convertParams = @{
                Module = $Module
                Context = "groups.$($actionKvp.Key)"
                FailureAction = $Module.Params.groups.lookup_failure_action
            }
            $dns = foreach ($lookupId in $actionKvp.Value) {
                $dn = $lookupId | ConvertTo-AnsibleADDistinguishedName @ADParams @convertParams
                if (-not $dn) {
                    continue  # Warning was written
                }

                # As membership is done on the group server, we need to store
                # correct server and credentials that was used for the lookup.
                if ($lookupId -is [System.Collections.IDictionary] -and $lookupId.server) {
                    $dnServerParams[$dn] = @{
                        Server = $lookupId.server
                    }

                    if ($Module.ServerCredentials.ContainsKey($lookupId.server)) {
                        $dnServerParams[$dn].Credential = $Module.ServerCredentials[$lookupId.server]
                    }
                }
                else {
                    $dnServerParams[$dn] = $ADParams
                }

                $dn
            }

            $compareParams[$actionKvp.Key] = @($dns)
        }

        $res = Compare-AnsibleADIdempotentList @compareParams
        $Module.Diff.after.groups = $res.Value

        if ($res.Changed) {
            $commonParams = @{
                Confirm = $false
                WhatIf = $Module.CheckMode
            }
            foreach ($member in $res.ToAdd) {
                $lookupParams = if ($dnServerParams.ContainsKey($member)) {
                    $dnServerParams[$member]
                }
                else {
                    $ADParams
                }
                if ($ADObject) {
                    try {
                        Set-ADObject -Identity $member -Add @{
                            member = $ADObject.DistinguishedName
                        } @lookupParams @commonParams
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        if ($Module.Params.groups.permissions_failure_action -ne "fail") {
                            if ($Module.Params.groups.permissions_failure_action -eq "warn") {
                                $Module.Warn("Cannot add group '$member'. You do not have the required permissions, skipping: $($_.Exception.Message)")
                            }
                        }
                        else {
                            throw
                        }
                    }
                }
                $Module.Result.changed = $true
            }
            foreach ($member in $res.ToRemove) {
                $lookupParams = if ($dnServerParams.ContainsKey($member)) {
                    $dnServerParams[$member]
                }
                else {
                    $ADParams
                }
                if ($ADObject) {
                    try {
                        Set-ADObject -Identity $member -Remove @{
                            member = $ADObject.DistinguishedName
                        } @lookupParams @commonParams
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        if ($_.Exception.ErrorCode -eq 0x0000055E) {
                            # ERROR_MEMBERS_PRIMARY_GROUP - win_domain_user didn't
                            # fail in this scenario. To preserve compatibility just
                            # display a warning. The warning isn't added if set
                            # was an empty list.
                            if ($null -eq $Module.Params.groups -or $Module.Params.groups.set.Length -ne 0) {
                                $Module.Warn("Cannot remove group '$member' as it's the primary group of the user, skipping: $($_.Exception.Message)")
                            }
                            $Module.Diff.after.groups = @($Module.Diff.after.groups; $member)
                        }
                        elseif ($Module.Params.groups.permissions_failure_action -ne "fail") {
                            if ($Module.Params.groups.permissions_failure_action -eq "warn") {
                                $Module.Warn("Cannot remove group '$member'. You do not have the required permissions, skipping: $($_.Exception.Message)")
                            }
                        }
                        else {
                            throw
                        }
                    }
                }
                $Module.Result.changed = $true
            }
        }

        # Ensure it's in alphabetical order to match before state as much as possible
        $Module.Diff.after.groups = @($res.Value | Sort-Object)
    }
}
Invoke-AnsibleADObject @setParams
