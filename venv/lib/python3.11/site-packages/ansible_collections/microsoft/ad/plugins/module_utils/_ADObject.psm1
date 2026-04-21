# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

#AnsibleRequires -CSharpUtil Ansible.Basic

Function Compare-AnsibleADAttribute {
    <#
    .SYNOPSIS
    Compares AD attribute values.

    .PARAMETER Name
    The attribute name to compare.

    .PARAMETER ADObject
    The AD object to compare with.

    .PARAMETER Attribute
    The attribute value(s) to add/remove/set.

    .PARAMETER Action
    Set to Add to add the value(s), Remove to remove the value(s), and Set to replace the value(s).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter()]
        [AllowNull()]
        [Microsoft.ActiveDirectory.Management.ADObject]
        $ADObject,

        [Parameter()]
        [AllowEmptyCollection()]
        [object]
        $Attribute,

        [ValidateSet("Add", "Remove", "Set")]
        [string]
        $Action
    )

    <# Gets all the known types the AD module can return

    DateTime, Guid, SecurityIdentifier are all from readonly properties
    that the AD module alaises of the real LDAP attributes.

    Get-ADObject -LDAPFilter '(objectClass=*)' -Properties * |
        ForEach-Object {
            foreach ($name in $_.PSObject.Properties.Name) {
                if ($name -in @('AddedProperties', 'ModifiedProperties', 'RemovedProperties', 'PropertyNames')) { continue }

                $v = $_.$name
                if ($null -eq $v) { continue }
                if ($v -isnot [System.Collections.IList] -or $v -is [System.Byte[]]) {
                    $v = @(, $v)
                }

                foreach ($value in $v) {
                    $value.GetType()
                }
            }
        } |
        Sort-Object -Unique
    #>
    $getDiffValue = {
        if ($_ -is [System.Byte[]]) {
            [System.Convert]::ToBase64String($_)
        }
        elseif ($_ -is [System.DateTime]) {
            $_.ToUniversalTime().ToFileTimeUtc()
        }
        elseif ($_ -is [System.DirectoryServices.ActiveDirectorySecurity]) {
            $_.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        }
        else {
            # Bool, Int32, Int64, String
            $_
        }
    }

    $existingAttributes = [System.Collections.Generic.List[object]]@()
    if ($ADObject -and $null -ne $ADObject.$Name) {
        $existingValues = $ADObject.$Name
        if ($null -ne $existingValues) {
            if (
                $existingValues -is [System.Collections.IList] -and
                $existingValues -isnot [System.Byte[]]
            ) {
                # Wrap with @() to help pwsh unroll the property value collection
                $existingAttributes.AddRange(@($existingValues))

            }
            else {
                $existingAttributes.Add($existingValues)
            }
        }
    }

    $desiredAttributes = [System.Collections.Generic.List[object]]@()
    if ($null -ne $Attribute -and $Attribute -isnot [System.Collections.IList]) {
        $Attribute = @($Attribute)
    }
    foreach ($attr in $Attribute) {
        if ($attr -is [System.Collections.IDictionary]) {
            if ($attr.Keys.Count -gt 2) {
                $keyList = $attr.Keys -join "', '"
                throw "Attribute '$Name' entry should only contain the 'type' and 'value' keys, found: '$keyList'"
            }

            $type = $attr.type
            $value = $attr.value
        }
        else {
            $type = 'raw'
            $value = $attr
        }

        switch ($type) {
            bool {
                $desiredAttributes.Add([System.Boolean]$value)
            }
            bytes {
                $desiredAttributes.Add([System.Convert]::FromBase64String($value))
            }
            date_time {
                $dtVal = [DateTimeOffset]::ParseExact(
                    $value,
                    [string[]]@("yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"),
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal)
                $desiredAttributes.Add($dtVal.UtcDateTime)
            }
            int {
                $desiredAttributes.Add([Int64]$value)
            }
            security_descriptor {
                $sd = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorSddlForm($value)
                $desiredAttributes.Add($sd)
            }
            string {
                $desiredAttributes.Add($value.ToString())
            }
            raw {
                # If the value is an Int32 we need it to be Int64 to ensure
                # the values are all the same type.
                if ($value -is [int]) {
                    $value = [Int64]$value
                }
                $desiredAttributes.Add($value)
            }
            default { throw "Attribute type '$type' must be bytes, date_time, int, security_descriptor, or raw" }
        }
    }

    $diffBefore = @($existingAttributes | ForEach-Object -Process $getDiffValue)
    $diffAfter = [System.Collections.Generic.List[object]]@()
    $value = [System.Collections.Generic.List[object]]@()
    $changed = $false

    # It's a lot easier to compare the string values
    $existing = [string[]]$diffBefore
    $desired = [string[]]@($desiredAttributes | ForEach-Object -Process $getDiffValue)

    if ($Action -eq 'Add') {
        $diffAfter.AddRange($existingAttributes)

        for ($i = 0; $i -lt $desired.Length; $i++) {
            if ($desired[$i] -cnotin $existing) {
                $value.Add($desiredAttributes[$i])
                $diffAfter.Add($desiredAttributes[$i])
                $changed = $true
            }
        }
    }
    elseif ($Action -eq 'Remove') {
        $diffAfter.AddRange($existingAttributes)

        for ($i = $desired.Length - 1; $i -ge 0; $i--) {
            if ($desired[$i] -cin $existing) {
                $value.Add($desiredAttributes[$i])
                $diffAfter.RemoveAt($i)
                $changed = $true
            }
        }
    }
    else {
        $diffAfter.AddRange($desiredAttributes)

        $toAdd = [string[]][System.Linq.Enumerable]::Except($desired, $existing)
        $toRemove = [string[]][System.Linq.Enumerable]::Except($existing, $desired)
        if ($toAdd.Length -or $toRemove.Length) {
            $changed = $true
        }

        if ($changed) {
            $value.AddRange($desiredAttributes)
        }
    }

    [PSCustomObject]@{
        Name = $Name
        Value = $value.ToArray()  # AD cmdlets expect an array here
        Changed = $changed
        DiffBefore = @($diffBefore | Sort-Object)
        DiffAfter = @($diffAfter | ForEach-Object -Process $getDiffValue | Sort-Object)
    }
}

Function Update-AnsibleADSetADObjectParam {
    <#
    .SYNOPSIS
    Updates the Set-AD* parameter splat with the parameters needed to set the
    attributes requested.
    It will output a boolean that indicates whether a change is needed to
    update the attributes.

    .PARAMETER Splat
    The parameter splat to update.

    .PARAMETER Add
    The attributes to add.

    .PARAMETER Remove
    The attributes to remove.

    .PARAMETER Set
    The attributes to set.

    .PARAMETER Diff
    An optional dictionary that can be used to store the diff output value on
    what was changed.

    .PARAMETER ADObject
    The AD object to compare the requested attribute values with.

    .PARAMETER ForNew
    This Splat is used for New-AD* and will update the OtherAttributes
    parameter.
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Splat,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary]
        $Add,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary]
        $Remove,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary]
        $Set,

        [Parameter()]
        [System.Collections.IDictionary]
        $Diff,

        [Parameter()]
        [AllowNull()]
        [Microsoft.ActiveDirectory.Management.ADObject]
        $ADObject,

        [Parameter()]
        [switch]
        $ForNew
    )

    $diffBefore = @{}
    $diffAfter = @{}

    $addAttributes = @{}
    $removeAttributes = @{}
    $replaceAttributes = @{}
    $clearAttributes = [System.Collections.Generic.List[String]]@()

    if ($Add.Count) {
        foreach ($kvp in $Add.GetEnumerator()) {
            $val = Compare-AnsibleADAttribute -Name $kvp.Key -ADObject $ADObject -Attribute $kvp.Value -Action Add
            if ($val.Changed -and $val.Value.Count) {
                $addAttributes[$kvp.Key] = $val.Value
            }
            $diffBefore[$kvp.Key] = $val.DiffBefore
            $diffAfter[$kvp.Key] = $val.DiffAfter
        }
    }
    # remove doesn't make sense when creating a new object
    if (-not $ForNew -and $Remove.Count) {
        foreach ($kvp in $Remove.GetEnumerator()) {
            $val = Compare-AnsibleADAttribute -Name $kvp.Key -ADObject $ADObject -Attribute $kvp.Value -Action Remove
            if ($val.Changed -and $val.Value.Count) {
                $removeAttributes[$kvp.Key] = $val.Value
            }
            $diffBefore[$kvp.Key] = $val.DiffBefore
            $diffAfter[$kvp.Key] = $val.DiffAfter
        }
    }
    if ($Set.Count) {
        foreach ($kvp in $Set.GetEnumerator()) {
            $val = Compare-AnsibleADAttribute -Name $kvp.Key -ADObject $ADObject -Attribute $kvp.Value -Action Set
            if ($val.Changed) {
                if ($val.Value.Count) {
                    $replaceAttributes[$kvp.Key] = $val.Value
                }
                else {
                    $clearAttributes.Add($kvp.Key)
                }
            }
            $diffBefore[$kvp.Key] = $val.DiffBefore
            $diffAfter[$kvp.Key] = $val.DiffAfter
        }
    }

    $changed = $false
    if ($ForNew) {
        $diffBefore = $null
        $otherAttributes = @{}

        foreach ($kvp in $addAttributes.GetEnumerator()) {
            $otherAttributes[$kvp.Key] = $kvp.Value
        }
        foreach ($kvp in $replaceAttributes.GetEnumerator()) {
            $otherAttributes[$kvp.Key] = $kvp.Value
        }

        if ($otherAttributes.Count) {
            $changed = $true
            $Splat.OtherAttributes = $otherAttributes
        }
    }
    else {
        if ($addAttributes.Count) {
            $changed = $true
            $Splat.Add = $addAttributes
        }
        if ($removeAttributes.Count) {
            $changed = $true
            $Splat.Remove = $removeAttributes
        }
        if ($replaceAttributes.Count) {
            $changed = $true
            $Splat.Replace = $replaceAttributes
        }
        if ($clearAttributes.Count) {
            $changed = $true
            $Splat.Clear = $clearAttributes
        }
    }

    if ($null -ne $Diff.Count) {
        $Diff.after = $diffAfter
        $Diff.before = $diffBefore
    }

    $changed
}


Function Compare-AnsibleADIdempotentList {
    <#
    .SYNOPSIS
    Common code to compare AD property values with an add/remove/set collection.

    .PARAMETER Existing
    The existing values for the property.

    .PARAMETER Add
    A list of values to add

    .PARAMETER Remove
    A list of values to remove

    .PARAMETER Set
    A list of files to set, will remove existing values if they are not in the
    list and add ones that are not in the existing values.

    .PARAMETER CaseInsensitive
    Whether to perform a case insensitive comparison check.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]
        $Existing,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]
        $Add,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]
        $Remove,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]
        $Set,

        [Parameter()]
        [switch]
        $CaseInsensitive
    )

    # It's easier to compare with strings.
    $existingString = [string[]]@(if ($null -ne $Existing) { $Existing | ForEach-Object ToString })
    $comparer = if ($CaseInsensitive) {
        [System.StringComparer]::OrdinalIgnoreCase
    }
    else {
        [System.StringComparer]::CurrentCulture
    }

    $value = [System.Collections.Generic.List[Object]]@()
    $toAdd = [System.Collections.Generic.List[Object]]@()
    $toRemove = [System.Collections.Generic.List[Object]]@()

    if ($null -ne $Set) {
        $setString = [string[]]@($Set | ForEach-Object ToString)
        $value.AddRange($Set)

        for ($i = 0; $i -lt $setString.Length; $i++) {
            $setElement = $setString[$i]
            if (-not [System.Linq.Enumerable]::Contains($existingString, $setElement, $comparer)) {
                $toAdd.Add($Set[$i])
            }
        }
        for ($i = 0; $i -lt $existingString.Length; $i++) {
            $existingElement = $existingString[$i]
            if (-not [System.Linq.Enumerable]::Contains($setString, $existingElement, $comparer)) {
                $toRemove.Add($Existing[$i])
            }
        }
    }
    else {
        if ($Remove) {
            $removeString = [string[]]@($Remove | ForEach-Object ToString)

            for ($i = 0; $i -lt $existingString.Length; $i++) {
                $existingElement = $existingString[$i]
                if ([System.Linq.Enumerable]::Contains($removeString, $existingElement, $comparer)) {
                    $toRemove.Add($Existing[$i])
                }
                else {
                    $value.Add($Existing[$i])
                }
            }
        }
        else {
            $value.AddRange($Existing)
        }

        if ($Add) {
            $addString = [string[]]@($Add | ForEach-Object ToString)

            for ($i = 0; $i -lt $addString.Length; $i++) {
                $addElement = $addString[$i]
                if (-not [System.Linq.Enumerable]::Contains($existingString, $addElement, $comparer)) {
                    $toAdd.Add($Add[$i])
                    $value.Add($Add[$i])
                }
            }
        }
    }

    [PSCustomObject]@{
        # $null is explicit here as the AD modules use it to unset a value
        Value = if ($value.Count) { $value.ToArray() } else { $null }
        # Also returned if the API doesn't support explicitly setting 1 value
        ToAdd = $toAdd.ToArray()
        ToRemove = $toRemove.ToArray()
        Changed = [bool]($toAdd.Count -or $toRemove.Count)
    }
}

Function ConvertTo-AnsibleADDistinguishedName {
    <#
    .SYNOPSIS
    Converts the input list into DistinguishedNames for later comparison.

    .PARAMETER InputObject
    The identity parameter, this can either be a string or a hashtable.
    If a hashtable it should contain the name and optional server key to
    identity the object to search and set a specific server to search on.

    .PARAMETER Module
    The AnsibleModule object associated with the current module execution.

    .PARAMETER Context
    The context behind this conversion to add to the error message if there
    is one.

    .PARAMETER Server
    The default server to search. The Identity server key will override this
    value is present.

    .PARAMETER Credential
    The credential to search with. This is ignored if the Identity server key
    is present.

    .PARAMETER FailureAction
    The action to take if the lookup fails. Fail will cause the module to
    exit with an error, ignore will ignore the error, and warn will emit a
    warning on failure.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]
        $InputObject,

        [Parameter(Mandatory)]
        [object]
        $Module,

        [Parameter(Mandatory)]
        [string]
        $Context,

        [string]
        $Server,

        [PSCredential]
        $Credential,

        [ValidateSet('Fail', 'Ignore', 'Warn')]
        [string]
        $FailureAction = 'Fail'
    )

    begin {
        $allowedKeys = [string[]]@('name', 'server')
        $results = [System.Collections.Generic.List[string]]@()
        $getErrors = [System.Collections.Generic.List[string]]@()
        $invalidIdentities = [System.Collections.Generic.List[string]]@()
    }

    process {
        foreach ($obj in $InputObject) {
            $getParams = @{}
            if ($Server) {
                $getParams.Server = $Server
            }
            if ($Credential) {
                $getParams.Credential = $Credential
            }

            if ($obj -is [System.Collections.IDictionary]) {
                # When using a hashtable, the name and server key can be used
                # to specify the identity and server to use. If no server is
                # set then it defaults to the default server (if provided) and
                # it's credentials.
                $existingKeys = [string[]]$obj.Keys

                if ('name' -notin $existingKeys) {
                    $getErrors.Add("Identity entry does not contain the required name key")
                    continue
                }
                $name = [string]$obj.name

                [string[]]$extraKeys = [System.Linq.Enumerable]::Except($existingKeys, $allowedKeys)
                if ($extraKeys) {
                    $extraKeys = $extraKeys | Sort-Object
                    $getErrors.Add("Identity entry for '$name' contains extra keys: '$($extraKeys -join "', '")'")
                    continue
                }
                $getParams.Identity = $name

                if ($obj.server) {
                    # If a custom server is specified we use that and the
                    # credential (if any) associated with that server.
                    $getParams.Server = $obj.server

                    if ($Module.ServerCredentials.ContainsKey($obj.server)) {
                        $getParams.Credential = $Module.ServerCredentials[$obj.server]
                    }
                    elseif (-not $Module.DefaultCredentialSet) {
                        $null = $getParams.Remove('Credential')
                    }
                }
            }
            else {
                # Treat the value as just the identity as a string.
                $getParams.Identity = [string]$obj
            }

            if (-not $getParams.Identity) {
                continue
            }

            $adDN = Get-AnsibleADObject @getParams |
                Select-Object -ExpandProperty DistinguishedName
            if ($adDN) {
                $results.Add($adDN)
            }
            else {
                $invalidIdentities.Add($getParams.Identity)
            }
        }
    }

    end {
        # This is a weird workaround as FailJson calls exit which means the
        # caller won't capture the output causing junk data in the output. By
        # only outputting the results if no errors occurred we can avoid that
        # problem.
        $errorPrefix = "Failed to find the AD object DNs for $Context"
        if ($getErrors) {
            $msg = "$errorPrefix. $($getErrors -join '. ')."
            $Module.FailJson($msg)
        }

        if ($invalidIdentities) {
            if ($FailureAction -ne 'Ignore') {
                $identityString = "'$($invalidIdentities -join "', '")'"
                if ($FailureAction -eq 'Fail') {
                    $Module.FailJson("$errorPrefix. Invalid identities: $identityString")
                }
                else {
                    $module.Warn("$errorPrefix. Ignoring invalid identities: $identityString")
                }
            }
        }

        $results
    }
}

Function Get-AnsibleADObject {
    <#
    .SYNOPSIS
    The -Identity params is limited to just objectGuid and distinguishedName
    on Get-ADObject. Try to preparse the value to support more common props
    like sAMAccountName, objectSid, userPrincipalName.

    .PARAMETER Identity
    The Identity to get.

    .PARAMETER Properties
    Extra properties to request on the object

    .PARAMETER Server
    The explicit domain controller to query.

    .PARAMETER Credential
    Custom queries to authenticate with.

    .PARAMETER GetCommand
    The Get-AD* cmdlet to use to get the AD object. Defaults to Get-ADObject.
    #>
    [OutputType([Microsoft.ActiveDirectory.Management.ADObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Identity,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]
        $Properties,

        [string]
        $Server,

        [PSCredential]
        $Credential,

        [Parameter()]
        [System.Management.Automation.CommandInfo]
        $GetCommand = $null
    )

    $getParams = @{}
    if ($Properties.Count) {
        $getParams.Properties = $Properties
    }
    if ($Server) {
        $getParams.Server = $Server
    }
    if ($Credential) {
        $getParams.Credential = $Credential
    }

    # The -Identity parameter is used where possible as LDAPFilter is limited
    # to just the defaultNamingContext as defined by -SearchBase.
    $objectGuid = [Guid]::Empty
    $tryDollarFallback = $false
    if ([System.Guid]::TryParse($Identity, [ref]$objectGuid)) {
        $getParams.Identity = $objectGuid
    }
    elseif ($Identity -match '^.*\@.*\..*$') {
        $getParams.LDAPFilter = "(userPrincipalName=$($Matches[0]))"
    }
    else {
        try {
            $sid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $Identity
            $sidBytes = New-Object -TypeName System.Byte[] -ArgumentList $sid.BinaryLength
            $sid.GetBinaryForm($sidBytes, 0)

            $value = @($sidBytes | ForEach-Object {
                    '\' + [System.BitConverter]::ToString($_).ToLowerInvariant()
                }) -join ''
            $getParams.LDAPFilter = "(objectSid=$value)"
        }
        catch [System.ArgumentException] {
            if ($Identity -match '^(?:[^:*?""<>|\/\\]+\\)?(?<username>[^;:""<>|?,=\*\+\\\(\)]+)$') {
                $tryDollarFallback = -not $Matches.username.EndsWith('$')
                $getParams.LDAPFilter = "(sAMAccountName=$($Matches.username))"
            }
            else {
                # Finally fallback to DistinguishedName.
                $getParams.Identity = $Identity
            }
        }
    }

    if ($GetCommand) {
        $null = $getParams.Remove('GetCommand')
    }
    else {
        $GetCommand = Get-Command -Name Get-ADObject -Module ActiveDirectory
    }
    try {
        $obj = & $GetCommand @getParams | Select-Object -First 1
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # AD cmdlets only raise this error when -Identity was used.
        # This means the account wasn't found and we don't need the fallback
        # logic below.
        return
    }

    # If we are dealing with a known object type where the sAMAccountName
    # typically ends with $ we want to try again with the $ append to the
    # filter.
    # https://github.com/ansible-collections/microsoft.ad/issues/124
    $dollarCommands = @(
        'Get-ADComputer'
        'Get-ADServiceAccount'
    )
    if (-not $obj -and $tryDollarFallback -and $GetCommand.Name -in $dollarCommands) {
        $getParams.LDAPFilter = $getParams.LDAPFilter.Substring(0, $getParams.LDAPFilter.Length - 1) + '$)'
        $obj = & $GetCommand @getParams | Select-Object -First 1
    }

    $obj
}

Function Invoke-AnsibleADObject {
    <#
    .SYNOPSIS
    Runs the module code for managing an AD object.

    .PARAMETER PropertyInfo
    The properties to compare on the AD object and what the module supports.
    Each object in this array must have the following keys set
        Name - The module option name
        Option - Module options to define in the arg spec

    The following keys are optional:
        Attribute - The ldap attribute name to compare against
        CaseInsensitive - The values are case insensitive (defaults to $false)
        StateRequired - Set to 'present' or 'absent' if this needs to be defined for either state
        DNLookup - Whether each value needs to be looked up to get the DN
        IsRawAttribute - Whether the attribute is a raw LDAP attribute name and not a parameter name
        SupportsReplace - Whether the IsRawAttribute supports setting through -Replace or needs -Add/-Remove
        New - Called when the option is to be set on the New-AD* cmdlet splat
        Set - Called when the option is to be set on the Set-AD* cmdlet splat

    The 'type' key in 'Option' should be a valid Ansible.Basic type or
    'add_remove_set'. When 'add_remove_set' is used the option type becomes
    dict with the options subentry for add/remove/set being the Option value
    specified. This can be combined with DNLookup to set the value as raw that
    can lookup the DN value from the string or dict specified.

    If Attribute is set then requested value will be compared with the
    attribute specified. The current attribute value is added to the before
    diff state for the option it is on. If New is not specified then the
    value requested is added to the New-AD* splat based on the attribute name.
    If Set is not specified then the value requested is added to the Set-AD*
    splat based on the attribute name.

    If New is specified it is called with the current module, common AD
    parameters and a splat that is called with New-AD*. It is up to the
    scriptblock to set the required splat parameters or called whatever
    function is needed.

    If Set is specified it is called with the current module, common AD
    parameters, a splat that is called with Set-AD*, and the current AD object.
    It is up to the scriptblock to set the required splat parameters or call
    whatever function is needed.

    The DNLookup key is used to indicate that the add/remove/set values can
    either be a string or a dictionary containing the name/server to specify
    the name and server to lookup the object DN value.

    Both New and Set must set the $Module.Diff.after results accordingly and/or
    mark $Module.Result.changed if it is making a change outside of adjusting
    the splat hashtable passed in.

    .PARAMETER DefaultPath
    A scriptblock that retrieves the default path the object is created in.
    Defaults to the defaultNamingContext. This is invoked with a hashtable
    containing parameters used to connect to AD, such as the Server and/or
    Credential.

    .PARAMETER ModuleNoun
    The module cmdlet noun that is being managed. This is used to run the
    correct Get-AD*, Set-AD*, and New-AD* cmdlets when needed.

    .PARAMETER ExtraProperties
    Extra properties to request when getting the AD object.

    .PARAMETER PreAction
    A scriptblock that is called at the beginning to perform any tasks needed
    before the module util is run. This is called with the module object,
    common ad parameters, and the ad object if it was found based on the input
    options.

    .PARAMETER PostAction
    A scriptblock that is called at the end to perform any tasks once the
    object has been configured. This is called with the module object, common
    ad parameters, and the ad object (state=present) else $null (state=absent)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object[]]
        $PropertyInfo,

        [Parameter()]
        [ScriptBlock]
        $DefaultPath = { param ($Module, $Params) (Get-ADRootDSE @Params -Properties defaultNamingContext).defaultNamingContext },

        [Parameter()]
        [string]
        $ModuleNoun = 'ADObject',

        [Parameter()]
        [string[]]
        $ExtraProperties,

        [Parameter()]
        [ScriptBlock]
        $PreAction,

        [Parameter()]
        [ScriptBlock]
        $PostAction
    )

    $defaultPathSentinel = 'microsoft.ad.default_path'

    $spec = @{
        options = @{
            attributes = @{
                default = @{}
                type = 'dict'
                options = @{
                    add = @{
                        default = @{}
                        type = 'dict'
                    }
                    remove = @{
                        default = @{}
                        type = 'dict'
                    }
                    set = @{
                        default = @{}
                        type = 'dict'
                    }
                }
            }
            domain_credentials = @{
                default = @()
                type = 'list'
                elements = 'dict'
                options = @{
                    name = @{
                        type = 'str'
                    }
                    username = @{
                        required = $true
                        type = 'str'
                    }
                    password = @{
                        no_log = $true
                        required = $true
                        type = 'str'
                    }
                }
            }
            domain_password = @{
                no_log = $true
                type = 'str'
            }
            domain_server = @{
                type = 'str'
            }
            domain_username = @{
                type = 'str'
            }
            identity = @{
                type = 'str'
            }
            name = @{
                type = 'str'
            }
            path = @{
                type = 'str'
            }
            state = @{
                choices = 'absent', 'present'
                default = 'present'
                type = 'str'
            }
        }
        required_one_of = @(
            , @("identity", "name")
        )
        required_together = @(, @('domain_username', 'domain_password'))
        supports_check_mode = $true
    }

    $stateRequiredIf = @{
        present = @()
        absent = @()
    }

    $PropertyInfo = @(
        $PropertyInfo

        # These 3 options are common to all AD objects.
        [PSCustomObject]@{
            Name = 'description'
            Option = @{ type = 'str' }
            Attribute = 'description'
        }
        [PSCustomObject]@{
            Name = 'display_name'
            Option = @{ type = 'str' }
            Attribute = 'displayName'
        }
        [PSCustomObject]@{
            Name = 'protect_from_deletion'
            Option = @{ type = 'bool' }
            Attribute = 'ProtectedFromAccidentalDeletion'
        }
    )

    [string[]]$requestedAttributes = @(
        foreach ($propInfo in $PropertyInfo) {
            $ansibleOption = $propInfo.Name

            if ($propInfo.StateRequired) {
                $stateRequiredIf[$propInfo.StateRequired] += $ansibleOption
            }

            $option = $propInfo.Option
            if ($option.type -eq 'add_remove_set') {
                $option.type = 'dict'

                $optionElement = $option.Clone()
                $optionElement.type = 'list'

                $option = @{
                    type = 'dict'
                    options = @{}
                }
                if ($optionElement.ContainsKey('no_log')) {
                    $option.no_log = $optionElement.no_log
                }

                if ($propInfo.DNLookup) {
                    $optionElement.elements = 'raw'
                    $option.options.lookup_failure_action = @{
                        choices = @('fail', 'ignore', 'warn')
                        default = 'fail'
                        type = 'str'
                    }
                }
                elseif (-not $optionElement.ContainsKey('elements')) {
                    $optionElement.elements = 'str'
                }

                if ($optionElement.ContainsKey('aliases')) {
                    $option.aliases = $optionElement.aliases
                    $null = $optionElement.Remove('aliases')
                }

                $option.options.add = $optionElement
                $option.options.remove = $optionElement
                $option.options.set = $optionElement
            }
            elseif ($propInfo.DNLookup) {
                $option.type = 'raw'
            }

            if (-not $propInfo.PSObject.Properties.Match('SupportsReplace')) {
                $propInfo.PSObject.Properties.Add(
                    [System.Management.Automation.PSNoteProperty]::new('SupportsReplace', $true))
            }

            $spec.options[$ansibleOption] = $option

            if ($propInfo.Attribute) {
                $propInfo.Attribute
            }
        }

        $ExtraProperties
    )

    $spec.required_if = @(
        foreach ($kvp in $stateRequiredIf.GetEnumerator()) {
            if ($kvp.Value) {
                , @("state", $kvp.Key, $kvp.Value)
            }
        }
    )

    $module = [Ansible.Basic.AnsibleModule]::Create(@(), $spec)
    $module.Result.distinguished_name = $null
    $module.Result.object_guid = $null

    $adParams = @{}
    $serverCredentials = @{}
    foreach ($domainCred in $module.Params.domain_credentials) {
        $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
            $domainCred.username,
            (ConvertTo-SecureString -AsPlainText -Force -String $domainCred.password)
        )

        if ($domainCred.name) {
            $serverCredentials[$domainCred.name] = $cred
        }
        elseif ($adParams.Credential) {
            $module.FailJson("Cannot specify default domain_credentials with domain_username and domain_password")
        }
        else {
            $adParams.Credential = $cred
        }
    }
    $module | Add-Member -MemberType NoteProperty -Name ServerCredentials -Value $serverCredentials

    if ($module.Params.domain_server) {
        $adParams.Server = $module.Params.domain_server
    }

    if ($module.Params.domain_username) {
        if ($adParams.Credential) {
            $msg = "Cannot specify domain_username/domain_password and domain_credentials with an entry that has no name."
            $module.FailJson($msg)
        }
        $adParams.Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
            $module.Params.domain_username,
            (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.domain_password)
        )
        $module | Add-Member -MemberType NoteProperty -Name DefaultCredentialSet -Value $true
    }

    $defaultObjectPath = & $DefaultPath $module $adParams
    $getCommand = Get-Command -Name "Get-$ModuleNoun" -Module ActiveDirectory
    $newCommand = Get-Command -Name "New-$ModuleNoun" -Module ActiveDirectory
    $setCommand = Get-Command -Name "Set-$ModuleNoun" -Module ActiveDirectory

    $requestedAttributes = [System.Collections.Generic.HashSet[string]]@(
        $requestedAttributes
        'name'
        $module.Params.attributes.add.Keys
        $module.Params.attributes.remove.Keys
        $module.Params.attributes.set.Keys
    ) | Where-Object { $_ }

    $namePrefix = 'CN'
    if ($ModuleNoun -eq 'ADOrganizationalUnit' -or $Module.Params.type -eq 'organizationalUnit') {
        $namePrefix = 'OU'
    }

    $identity = if ($module.Params.identity) {
        $module.Params.identity
    }
    else {
        $ouPath = $defaultObjectPath
        if ($module.Params.path -and $module.Params.path -ne $defaultPathSentinel) {
            $ouPath = $module.Params.path
        }
        "$namePrefix=$($Module.Params.name -replace ',', '\,'),$ouPath"
    }

    $getParams = @{
        GetCommand = $getCommand
        Identity = $identity
        Properties = $requestedAttributes
    }
    $adObject = Get-AnsibleADObject @getParams @adParams
    if ($adObject) {
        $module.Result.object_guid = $adObject.ObjectGUID
        $module.Result.distinguished_name = $adObject.DistinguishedName

        $module.Diff.before = @{
            attributes = $null
            name = $adObject.Name
            path = @($adObject.DistinguishedName -split '[^\\],', 2)[-1]
        }

        foreach ($propInfo in $PropertyInfo) {
            $propValue = $module.Params[$propInfo.Name]
            if ($null -eq $propValue -or -not $propInfo.Attribute) {
                continue
            }

            $actualValue = $adObject[$propInfo.Attribute].Value
            if ($module.Option.no_log) {
                $actualValue = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
            }
            if ($actualValue -is [System.Collections.IList]) {
                $actualValue = @($actualValue | Sort-Object)
            }
            $module.Diff.before[$propInfo.Name] = $actualValue
        }
    }
    else {
        $module.Diff.before = $null
    }

    if ($PreAction) {
        $null = & $PreAction $module $adParams $adObject
    }

    if ($module.Params.state -eq 'absent') {
        if ($adObject) {
            $removeParams = @{
                Confirm = $false
                WhatIf = $module.CheckMode
            }

            # Remove-ADObject -Recursive fails with access is denied, use this
            # instead to remove the child objects manually
            Get-ADObject -Filter * -Properties ProtectedFromAccidentalDeletion -Searchbase $adObject.DistinguishedName @adParams |
                Sort-Object -Property { $_.DistinguishedName.Length } -Descending |
                ForEach-Object -Process {
                    if ($_.ProtectedFromAccidentalDeletion) {
                        $_ | Set-ADObject -ProtectedFromAccidentalDeletion $false @removeParams @adParams
                    }
                    $_ | Remove-ADObject @removeParams @adParams
                }

            $module.Result.changed = $true
        }

        $module.Diff.after = $null
    }
    else {
        $attributes = $module.Params.attributes
        $objectDN = $null
        $objectGuid = $null

        if (-not $adObject) {
            $adName = if ($module.Params.name) {
                $module.Params.name
            }
            else {
                $module.Params.identity
            }
            $newParams = @{
                Confirm = $false
                Name = $adName
                WhatIf = $module.CheckMode
                PassThru = $true
            }

            $objectPath = $null
            if ($module.Params.path -and $module.Params.path -ne $defaultPathSentinel) {
                $newParams.Path = $objectPath = $module.Params.path
            }
            else {
                $objectPath = $defaultObjectPath
            }

            $diffAttributes = @{}
            $null = Update-AnsibleADSetADObjectParam @attributes -Splat $newParams -Diff $diffAttributes -ForNew

            $module.Diff.after = @{
                attributes = $diffAttributes.after
                name = $adName
                path = $objectPath
            }

            foreach ($propInfo in $PropertyInfo) {
                $propValue = $module.Params[$propInfo.Name]
                if ($propValue -is [System.Collections.IDictionary]) {
                    if ($propValue.Count -eq 0) {
                        continue
                    }
                }
                elseif ([string]::IsNullOrWhiteSpace($propValue)) {
                    continue
                }

                if ($propInfo.New) {
                    $null = & $propInfo.New $module $adParams $newParams
                }
                elseif ($propInfo.Attribute) {
                    # If a dictionary (add/set/remove) and is not a DNLookup single value
                    if ($propValue -is [System.Collections.IDictionary] -and $propInfo.Option.type -ne 'raw') {
                        $propValue = if ($propInfo.DNLookup) {
                            foreach ($actionKvp in $propValue.GetEnumerator()) {
                                if ($null -eq $actionKvp.Value -or $actionKvp.Key -in @('lookup_failure_action', 'remove')) {
                                    continue
                                }

                                $convertParams = @{
                                    Module = $module
                                    Context = "$($propInfo.Name).$($actionKvp.Key)"
                                    FailureAction = $propValue.lookup_failure_action
                                }
                                $actionKvp.Value | ConvertTo-AnsibleADDistinguishedName @adParams @convertParams
                            }
                        }
                        else {
                            $propValue['add']
                            $propValue['set']
                        }

                        $propValue = $propValue | Select-Object -Unique
                    }
                    elseif ($propInfo.DNLookup) {
                        $propValue = $propValue | ConvertTo-AnsibleADDistinguishedName @adParams -Module $module -Context $propInfo.Name
                    }

                    # If the value is empty we don't want to explicitly set it
                    # as that will be the default and can fail if empty.
                    if ($propInfo.IsRawAttribute -and @($propValue).Count) {
                        if (-not $newParams.ContainsKey('OtherAttributes')) {
                            $newParams.OtherAttributes = @{}
                        }

                        # The AD cmdlets don't like explicitly casted arrays, use
                        # ForEach-Object to get back a vanilla object[] to set.
                        $newParams.OtherAttributes[$propInfo.Attribute] = $propValue | ForEach-Object { "$_" }
                    }
                    elseif (-not $propInfo.IsRawAttribute) {
                        $newParams[$propInfo.Attribute] = $propValue
                    }

                    if ($propInfo.Option.no_log) {
                        $propValue = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
                    }
                    if ($propValue -is [System.Collections.IList]) {
                        $propValue = @($propValue | Sort-Object)
                    }
                    $module.Diff.after[$propInfo.Name] = $propValue
                }
            }

            # Only New-ADObject has the -ProtectedFromAccidentialDeletion while
            # other cmdlets do not. Check for this and manually run with
            # Set-ADObject later if protection is desired.
            # https://github.com/ansible-collections/microsoft.ad/issues/47
            $protectFromDeletion = $false
            if (
                $newParams.ContainsKey('ProtectedFromAccidentalDeletion') -and
                -not $newCommand.Parameters.ContainsKey('ProtectedFromAccidentalDeletion')
            ) {
                $protectFromDeletion = $newParams.ProtectedFromAccidentalDeletion
                $newParams.Remove('ProtectedFromAccidentalDeletion')
            }

            try {
                $adObject = & $newCommand @newParams @adParams
            }
            catch {
                # Using FailJson means other useful debugging information
                # like the diff output is returned
                $module.FailJson("New-$ModuleNoun failed: $_", $_)
            }
            $module.Result.changed = $true

            if ($module.CheckMode) {
                $objectDN = "$namePrefix=$($adName -replace ',', '\,'),$objectPath"
                $objectGuid = [Guid]::Empty  # Dummy value for check mode
            }
            else {
                $objectDN = $adObject.DistinguishedName
                $objectGuid = $adObject.ObjectGUID

                if ($protectFromDeletion) {
                    $adObject | Set-ADObject @adParams -ProtectedFromAccidentalDeletion $true
                }
            }
        }
        else {
            $objectDN = $adObject.DistinguishedName
            $objectGuid = $adObject.ObjectGUID
            $objectName = $adObject.Name
            $objectPath = @($objectDN -split '[^\\],', 2)[-1]

            $commonParams = @{
                Confirm = $false
                Identity = $adObject.ObjectGUID
                PassThru = $true
                WhatIf = $module.CheckMode
            }
            $setParams = @{}

            $diffAttributes = @{}
            $null = Update-AnsibleADSetADObjectParam @attributes -Splat $setParams -Diff $diffAttributes -ADObject $adObject

            $module.Diff.before.attributes = $diffAttributes.before
            $module.Diff.after = @{
                attributes = $diffAttributes.after
                name = $objectName
                path = $objectPath
            }

            foreach ($propInfo in $PropertyInfo) {
                $propValue = $module.Params[$propInfo.Name]
                if ($null -eq $propValue) {
                    continue
                }

                if ($propInfo.Set) {
                    $null = & $propInfo.Set $module $adParams $setParams $adObject
                }
                elseif ($propInfo.Attribute) {
                    $actualValue = $adObject[$propInfo.Attribute]

                    $compareParams = @{
                        Existing = $actualValue
                        CaseInsensitive = $propInfo.DNLookup -or $propInfo.CaseInsensitive
                    }

                    # If a dictionary (add/set/remove) and is not a DNLookup single value
                    if ($propValue -is [System.Collections.IDictionary] -and $propInfo.Option.type -ne 'raw') {
                        if ($propInfo.DNLookup) {
                            foreach ($actionKvp in $propValue.GetEnumerator()) {
                                if ($null -eq $actionKvp.Value -or $actionKvp.Key -eq 'lookup_failure_action') { continue }

                                $convertParams = @{
                                    Module = $module
                                    Context = "$($propInfo.Name).$($actionKvp.Key)"
                                    FailureAction = $propValue.lookup_failure_action
                                }
                                $dns = $actionKvp.Value | ConvertTo-AnsibleADDistinguishedName @adParams @convertParams
                                $compareParams[$actionKvp.Key] = @($dns)
                            }
                        }
                        else {
                            $compareParams.Add = $propValue['add']
                            $compareParams.Remove = $propValue['remove']
                            $compareParams.Set = $propValue['set']
                        }
                    }
                    elseif ([string]::IsNullOrWhiteSpace($propValue)) {
                        $compareParams.Set = @()
                    }
                    elseif ($propInfo.DNLookup) {
                        $compareParams.Set = @($propValue | ConvertTo-AnsibleADDistinguishedName @adParams -Module $module -Context $propInfo.Name)
                    }
                    else {
                        $compareParams.Set = @($propValue)
                    }

                    $res = Compare-AnsibleADIdempotentList @compareParams
                    $newValue = $res.Value
                    if ($res.Changed) {
                        if ($propInfo.IsRawAttribute) {
                            if ($newValue) {
                                $toSet = @(
                                    if ($propInfo.SupportsReplace) {
                                        @{ Prop = 'Replace'; Value = $newValue }
                                    }
                                    else {
                                        @{ Prop = 'Add'; Value = $res.ToAdd }
                                        @{ Prop = 'Remove'; Value = $res.ToRemove }
                                    }
                                )

                                foreach ($setInfo in $toSet) {
                                    if (-not $setInfo.Value) {
                                        continue
                                    }
                                    if (-not $setParams.ContainsKey($setInfo.Prop)) {
                                        $setParams[$setInfo.Prop] = @{}
                                    }
                                    $setParams[$setInfo.Prop][$propInfo.Attribute] = $setInfo.Value
                                }
                            }
                            else {
                                if (-not $setParams.ContainsKey('Clear')) {
                                    $setParams['Clear'] = [System.Collections.Generic.List[string]]@()
                                }
                                $setParams['Clear'].Add($propInfo.Attribute)
                            }
                        }
                        else {
                            $setParams[$propInfo.Attribute] = $newValue
                        }
                    }

                    $noLog = $propInfo.Option.no_log
                    if ($newValue) {
                        if ($res.Changed -and $noLog) {
                            $newValue = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER - changed'
                        }
                        elseif ($noLog) {
                            $newValue = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
                        }

                        if ($newValue -is [System.Collections.IList]) {
                            $newValue = @($newValue | Sort-Object)
                        }
                    }

                    $module.Diff.after[$propInfo.Name] = $newValue
                }
            }

            $finalADObject = $null
            $desiredName = $module.Params.name
            if ($desiredName -and $desiredName -cne $objectName) {
                $objectName = $desiredName
                $module.Diff.after.name = $objectName

                $finalADObject = Rename-ADObject @commonParams @adParams -NewName $objectName
                $module.Result.changed = $true
            }

            $desiredPath = $module.Params.path
            if ($desiredPath -eq $defaultPathSentinel) {
                $desiredPath = $defaultObjectPath
            }
            if ($desiredPath -and $desiredPath -ne $objectPath) {
                $objectPath = $desiredPath
                $module.Diff.after.path = $objectPath

                $addProtection = $false
                if ($adObject.ProtectedFromAccidentalDeletion) {
                    $addProtection = $true
                    $null = Set-ADObject -ProtectedFromAccidentalDeletion $false @commonParams @adParams
                }

                try {
                    $finalADObject = Move-ADObject @commonParams @adParams -TargetPath $objectPath
                }
                finally {
                    if ($addProtection) {
                        $null = Set-ADObject -ProtectedFromAccidentalDeletion $true @commonParams @adParams
                    }
                }

                $module.Result.changed = $true
            }

            $protectFromDeletion = $null
            if (
                $setParams.ContainsKey('ProtectedFromAccidentalDeletion') -and
                -not $setCommand.Parameters.ContainsKey('ProtectedFromAccidentalDeletion')
            ) {
                $protectFromDeletion = $setParams.ProtectedFromAccidentalDeletion
                $setParams.Remove('ProtectedFromAccidentalDeletion')
            }

            if ($setParams.Count) {
                try {
                    $finalADObject = & $setCommand @commonParams @setParams @adParams
                }
                catch {
                    # Using FailJson means other useful debugging information
                    # like the diff output is returned
                    $module.FailJson("Set-$ModuleNoun failed: $_", $_)
                }
                $module.Result.changed = $true
            }

            if ($null -ne $protectFromDeletion) {
                $finalADObject = Set-ADObject -ProtectedFromAccidentalDeletion $protectFromDeletion @commonParams @adParams
                $module.Result.changed = $true
            }

            # Won't be set in check mode
            if ($finalADObject) {
                $objectDN = $finalADObject.DistinguishedName
            }
            else {
                $objectDN = "$namePrefix=$($objectName -replace ',', '\,'),$objectPath"
            }
        }

        # Explicit vars are set when running in check mode as the adObject may not
        # have the desired values set at runtime
        $module.Result.distinguished_name = $objectDN
        $module.Result.object_guid = $objectGuid.Guid
    }

    if ($PostAction) {
        $null = & $PostAction $Module $adParams $adObject
    }

    $module.ExitJson()
}

$exportMembers = @{
    Function = @(
        "Compare-AnsibleADIdempotentList"
        "ConvertTo-AnsibleADDistinguishedName"
        "Get-AnsibleADObject"
        "Invoke-AnsibleADObject"
    )
}
Export-ModuleMember @exportMembers
