#!powershell

# Copyright: (c) 2022, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell Ansible.ModuleUtils.AddType

$spec = @{
    options = @{
        domain_password = @{ type = 'str'; no_log = $true }
        domain_server = @{ type = 'str' }
        domain_username = @{ type = 'str' }
        filter = @{ type = 'str' }
        identity = @{ type = 'str' }
        include_deleted = @{ type = 'bool'; default = $false }
        ldap_filter = @{ type = 'str' }
        properties = @{ type = 'list'; elements = 'str' }
        search_base = @{ type = 'str' }
        search_scope = @{ type = 'str'; choices = @('base', 'one_level', 'subtree') }
    }
    supports_check_mode = $true
    mutually_exclusive = @(
        @('filter', 'identity', 'ldap_filter'),
        @('identity', 'search_base'),
        @('identity', 'search_scope')
    )
    required_one_of = @(
        , @('filter', 'identity', 'ldap_filter')
    )
    required_together = @(, @('domain_username', 'domain_password'))
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.objects = @()  # Always ensure this is returned even in a failure.

$domainServer = $module.Params.domain_server
$domainPassword = $module.Params.domain_password
$domainUsername = $module.Params.domain_username
$filter = $module.Params.filter
$identity = $module.Params.identity
$includeDeleted = $module.Params.include_deleted
$ldapFilter = $module.Params.ldap_filter
$properties = $module.Params.properties
$searchBase = $module.Params.search_base
$searchScope = $module.Params.search_scope

# Attempt import of ActiveDirectory module
try {
    Import-Module -Name ActiveDirectory
}
catch {
    $module.FailJson("The ActiveDirectory module failed to load properly: $($_.Exception.Message)", $_)
}

$credential = $null
if ($domainUsername) {
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
        $domainUsername,
        (ConvertTo-SecureString -AsPlainText -Force -String $domainPassword)
    )
}

Add-CSharpType -AnsibleModule $module -References @'
using System;

namespace Ansible.WinDomainObjectInfo
{
    [Flags]
    public enum GroupType : uint
    {
        GROUP_TYPE_BUILTIN_LOCAL_GROUP = 0x00000001,
        GROUP_TYPE_ACCOUNT_GROUP = 0x00000002,
        GROUP_TYPE_RESOURCE_GROUP = 0x00000004,
        GROUP_TYPE_UNIVERSAL_GROUP = 0x00000008,
        GROUP_TYPE_APP_BASIC_GROUP = 0x00000010,
        GROUP_TYPE_APP_QUERY_GROUP = 0x00000020,
        GROUP_TYPE_SECURITY_ENABLED = 0x80000000,
    }

    [Flags]
    public enum UserAccountControl : int
    {
        ADS_UF_SCRIPT = 0x00000001,
        ADS_UF_ACCOUNTDISABLE = 0x00000002,
        ADS_UF_HOMEDIR_REQUIRED = 0x00000008,
        ADS_UF_LOCKOUT = 0x00000010,
        ADS_UF_PASSWD_NOTREQD = 0x00000020,
        ADS_UF_PASSWD_CANT_CHANGE = 0x00000040,
        ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080,
        ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0x00000100,
        ADS_UF_NORMAL_ACCOUNT = 0x00000200,
        ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800,
        ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000,
        ADS_UF_SERVER_TRUST_ACCOUNT = 0x00002000,
        ADS_UF_DONT_EXPIRE_PASSWD = 0x00010000,
        ADS_UF_MNS_LOGON_ACCOUNT = 0x00020000,
        ADS_UF_SMARTCARD_REQUIRED = 0x00040000,
        ADS_UF_TRUSTED_FOR_DELEGATION = 0x00080000,
        ADS_UF_NOT_DELEGATED = 0x00100000,
        ADS_UF_USE_DES_KEY_ONLY = 0x00200000,
        ADS_UF_DONT_REQUIRE_PREAUTH = 0x00400000,
        ADS_UF_PASSWORD_EXPIRED = 0x00800000,
        ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000,
    }

    [Flags]
    public enum SupportedEncryptionTypes : int
    {
        None = 0x00,
        DES_CBC_CRC = 0x01,
        DES_CBC_MD5 = 0x02,
        RC4_HMAC = 0x04,
        AES128_CTS_HMAC_SHA1_96 = 0x08,
        AES256_CTS_HMAC_SHA1_96 = 0x10,
    }

    public enum sAMAccountType : int
    {
        SAM_DOMAIN_OBJECT = 0x00000000,
        SAM_GROUP_OBJECT = 0x10000000,
        SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001,
        SAM_ALIAS_OBJECT = 0x20000000,
        SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001,
        SAM_USER_OBJECT = 0x30000000,
        SAM_NORMAL_USER_ACCOUNT = 0x30000000,
        SAM_MACHINE_ACCOUNT = 0x30000001,
        SAM_TRUST_ACCOUNT = 0x30000002,
        SAM_APP_BASIC_GROUP = 0x40000000,
        SAM_APP_QUERY_GROUP = 0x40000001,
        SAM_ACCOUNT_TYPE_MAX = 0x7fffffff,
    }
}
'@

Function ConvertTo-OutputValue {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [Object]
        $InputObject
    )

    if ($InputObject -is [System.Security.Principal.SecurityIdentifier]) {
        # Syntax: SID - Only serialize the SID as a string and not the other metadata properties.
        $sidInfo = @{
            Sid = $InputObject.Value
        }

        # Try and map the SID to the account name, this may fail if the SID is invalid or not mappable.
        try {
            $sidInfo.Name = $InputObject.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch [System.Security.Principal.IdentityNotMappedException] {
            $sidInfo.Name = $null
        }

        $sidInfo
    }
    elseif ($InputObject -is [Byte[]]) {
        # Syntax: Octet String - By default will serialize as a list of decimal values per byte, instead return a
        # Base64 string as Ansible can easily parse that.
        [System.Convert]::ToBase64String($InputObject)
    }
    elseif ($InputObject -is [DateTime]) {
        # Syntax: UTC Coded Time - .NET DateTimes serialized as in the form "Date(FILETIME)" which isn't easily
        # parsable by Ansible, instead return as an ISO 8601 string in the UTC timezone.
        [TimeZoneInfo]::ConvertTimeToUtc($InputObject).ToString("o")
    }
    elseif ($InputObject -is [System.Security.AccessControl.ObjectSecurity]) {
        # Complex object which isn't easily serializable. Instead we should just return the SDDL string. If a user
        # needs to parse this then they really need to reprocess the SDDL string and process their results on another
        # win_shell task.
        $InputObject.GetSecurityDescriptorSddlForm(([System.Security.AccessControl.AccessControlSections]::All))
    }
    else {
        # Syntax: (All Others) - The default serialization handling of other syntaxes are fine, don't do anything.
        $InputObject
    }
}

<#
Calling Get-ADObject that returns multiple objects with -Properties * will only return the properties that were set on
the first found object. To counter this problem we will first call Get-ADObject to list all the objects that match the
filter specified then get the properties on each object.
#>

$commonParams = @{
    IncludeDeletedObjects = $includeDeleted
}

if ($credential) {
    $commonParams.Credential = $credential
}

if ($domainServer) {
    $commonParams.Server = $domainServer
}

# First get the IDs for all the AD objects that match the filter specified.
$getParams = @{
    Properties = @('DistinguishedName', 'ObjectGUID')
}

if ($filter) {
    $getParams.Filter = $filter
}
elseif ($identity) {
    $getParams.Identity = $identity
}
elseif ($ldapFilter) {
    $getParams.LDAPFilter = $ldapFilter
}

# Explicit check on $null as an empty string is different from not being set.
if ($null -ne $searchBase) {
    $getParams.SearchBase = $searchbase
}

if ($searchScope) {
    $getParams.SearchScope = switch ($searchScope) {
        base { 'Base' }
        one_level { 'OneLevel' }
        subtree { 'Subtree' }
    }
}

try {
    # We run this in a custom PowerShell pipeline so that users of this module can't use any of the variables defined
    # above in their filter. While the cmdlet won't execute sub expressions we don't want anyone implicitly relying on
    # a defined variable in this module in case we ever change the name or remove it.
    $iss = [InitialSessionState]::CreateDefault()
    $iss.ImportPSModule("ActiveDirectory")
    $ps = [PowerShell]::Create($iss)
    $null = $ps.AddCommand('Get-ADObject').AddParameters($commonParams).AddParameters($getParams)
    $null = $ps.AddCommand('Select-Object').AddParameter('Property', @('DistinguishedName', 'ObjectGUID'))

    $foundGuids = @($ps.Invoke())
}
catch {
    # Because we ran in a pipeline we can't catch ADIdentityNotFoundException. Instead this scans each InnerException
    # to see if it contains ADIdentityNotFoundException.
    $exp = $_.Exception
    $foundGuids = $null
    while ($exp) {
        $exp = $exp.InnerException
        if ($exp -is [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]) {
            $foundGuids = @()
            break
        }
    }

    if ($null -eq $foundGuids) {
        # The exception is from the .Invoke() call, compare on the InnerException which was what was actually raised by
        # the pipeline.
        $innerException = $_.Exception.InnerException.InnerException
        if ($innerException -is [Microsoft.ActiveDirectory.Management.ADServerDownException]) {
            # Point users in the direction of the double hop problem as that is what is typically the cause of this.
            $msg = "Failed to contact the AD server, this could be caused by the double hop problem over WinRM. "
            $msg += "Try using the module with auth as Kerberos with credential delegation or CredSSP, become, or "
            $msg += "defining the domain_username and domain_password module parameters."
            $module.FailJson($msg, $innerException)
        }
        else {
            throw $innerException
        }
    }
}

$getParams = @{}
if ($properties) {
    $getParams.Properties = $properties
}
$module.Result.objects = @(foreach ($adId in $foundGuids) {
        try {
            $adObject = Get-ADObject @commonParams @getParams -Identity $adId.ObjectGUID
        }
        catch {
            $msg = "Failed to retrieve properties for AD Object '$($adId.DistinguishedName)': $($_.Exception.Message)"
            $module.Warn($msg)
            continue
        }

        $propertyNames = $adObject.PropertyNames
        $propertyNames += ($properties | Where-Object { $_ -ne '*' })

        # Now process each property to an easy to represent string
        $filteredObject = [Ordered]@{}
        foreach ($name in ($propertyNames | Sort-Object)) {
            # In the case of explicit properties that were asked for but weren't set, Get-ADObject won't actually return
            # the property so this is a defensive check against that scenario.
            if (-not $adObject.PSObject.Properties.Name.Contains($name)) {
                $filteredObject.$name = $null
                continue
            }

            $value = $adObject.$name
            if ($value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
                $value = @(
                    foreach ($v in $value) {
                        ConvertTo-OutputValue -InputObject $v
                    }
                )
            }
            else {
                $value = ConvertTo-OutputValue -InputObject $value
            }
            $filteredObject.$name = $value

            # For these 3 properties, add an _AnsibleFlags attribute which contains the enum strings that are set.
            $enumValue = switch ($name) {
                groupType {
                    [Ansible.WinDomainObjectInfo.GroupType]$value
                }
                'msDS-SupportedEncryptionTypes' {
                    [Ansible.WinDomainObjectInfo.SupportedEncryptionTypes]$value
                }
                sAMAccountType {
                    [Ansible.WinDomainObjectInfo.sAMAccountType]$value
                }
                userAccountControl {
                    [Ansible.WinDomainObjectInfo.UserAccountControl]$value
                }
            }
            if ($null -ne $enumValue) {
                $filteredObject."$($name)_AnsibleFlags" = $enumValue.ToString() -split ', '
            }
        }

        $filteredObject
    })

$module.ExitJson()
