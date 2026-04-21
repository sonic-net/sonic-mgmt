#!powershell

# Copyright: (c) 2020, Brian Scholer <@briantist>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -CSharpUtil Ansible.AccessToken

$type = @{
    guid = [Func[[Object], [System.Guid]]] {
        [System.Guid]::ParseExact($args[0].Trim([char[]]'}{').Replace('-', ''), 'N')
    }
    version = [Func[[Object], [System.Version]]] {
        [System.Version]::Parse($args[0])
    }
    int64 = [Func[[Object], [System.Int64]]] {
        [System.Int64]::Parse($args[0])
    }
    double = [Func[[Object], [System.Double]]] {
        [System.Double]::Parse($args[0])
    }
}

$pssc_options = @{
    guid = @{ type = $type.guid }
    schema_version = @{ type = $type.version }
    author = @{ type = 'str' }
    description = @{ type = 'str' }
    company_name = @{ type = 'str' }
    copyright = @{ type = 'str' }
    session_type = @{ type = 'str' ; choices = @('default', 'empty', 'restricted_remote_server') }
    transcript_directory = @{ type = 'path' }
    run_as_virtual_account = @{ type = 'bool' }
    run_as_virtual_account_groups = @{ type = 'list' ; elements = 'str' }
    mount_user_drive = @{ type = 'bool' }
    user_drive_maximum_size = @{ type = $type.int64 }
    group_managed_service_account = @{ type = 'str' }
    scripts_to_process = @{ type = 'list' ; elements = 'str' }
    role_definitions = @{ type = 'dict' }
    required_groups = @{ type = 'dict' }
    language_mode = @{ type = 'str' ; choices = @('no_language', 'restricted_language', 'constrained_language', 'full_language') }
    execution_policy = @{ type = 'str' ; choices = @('default', 'remote_signed', 'restricted', 'undefined', 'unrestricted') }
    powershell_version = @{ type = $type.version }
    modules_to_import = @{ type = 'list' ; elements = 'raw' }
    visible_aliases = @{ type = 'list' ; elements = 'str' }
    visible_cmdlets = @{ type = 'list' ; elements = 'raw' }
    visible_functions = @{ type = 'list' ; elements = 'raw' }
    visible_external_commands = @{ type = 'list' ; elements = 'str' }
    alias_definitions = @{ type = 'dict' }
    function_definitions = @{ type = 'dict' }
    variable_definitions = @{ type = 'list' ; elements = 'dict' }
    environment_variables = @{ type = 'dict' }
    types_to_process = @{ type = 'list' ; elements = 'path' }
    formats_to_process = @{ type = 'list' ; elements = 'path' }
    assemblies_to_load = @{ type = 'list' ; elements = 'str' }
}

$session_configuration_options = @{
    name = @{ type = 'str' ; required = $true }
    processor_architecure = @{ type = 'str' ; choices = @('amd64', 'x86') }
    access_mode = @{ type = 'str' ; choices = @('disabled', 'local', 'remote') }
    use_shared_process = @{ type = 'bool' }
    thread_apartment_state = @{ type = 'str' ; choices = @('mta', 'sta') }
    thread_options = @{ type = 'str' ; choices = @('default', 'reuse_thread', 'use_current_thread', 'use_new_thread') }
    startup_script = @{ type = 'path' }
    maximum_received_data_size_per_command_mb = @{ type = $type.double }
    maximum_received_object_size_mb = @{ type = $type.double }
    security_descriptor_sddl = @{ type = 'str' }
    run_as_credential_username = @{ type = 'str' }
    run_as_credential_password = @{ type = 'str' ; no_log = $true }
}

$behavior_options = @{
    state = @{ type = 'str' ; choices = @('present', 'absent') ; default = 'present' }
    lenient_config_fields = @{ type = 'list' ; elements = 'str' ; default = @('guid', 'author', 'company_name', 'copyright', 'description') }
    async_timeout = @{ type = 'int' ; default = 300 }
    async_poll = @{ type = 'int' ; default = 1 }
    <#
    # TODO: possible future enhancement to wait for existing connections to finish
    # Existing connections can be found with:
    # Get-WSManInstance -ComputerName localhost -ResourceURI shell -Enumerate

    existing_connection_timeout_seconds       = @{ type = 'int' ; default = 0 }
    existing_connection_timeout_interval_ms   = @{ type = 'int' ; default = 500 }
    existing_connection_timeout_action        = @{ type = 'str' ; choices = @('terminate', 'fail') ; default = 'terminate' }
    existing_connection_wait_states           = @{ type = 'list' ; elements = 'str' ; default = @('connected') }
#>
}

$spec = @{
    options = $pssc_options + $session_configuration_options + $behavior_options
    required_together = @(
        , @('run_as_credential_username', 'run_as_credential_password')
    )
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)


function Import-PowerShellDataFileLegacy {
    <#
        .SYNOPSIS
        A pre-PowerShell 5.0 version of Import-PowerShellDataFile

        .DESCRIPTION
        Safely imports a PowerShell Data file in PowerShell versions before 5.0
        when the built-in command was introduced. Non-literal Path support is not included.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Required to process PS data file')]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('Path')]
        [String]
        $LiteralPath
    )

    End {
        $astloader = [System.Management.Automation.Language.Parser]::ParseFile($LiteralPath, [ref] $null , [ref] $null)
        $ht = $astloader.Find({ param($ast)
                $ast -is [System.Management.Automation.Language.HashtableAst]
            }, $false)

        if (-not $ht) {
            throw "Invalid PowerShell Data File."
        }

        # SafeGetValue() is not available before PowerShell 5 anyway, so we'll do the unsafe load and just execute it.
        # The only files we're loading are ones we generated from options, or ones that were already attached to existing
        # session configurations.
        # $ht.SafeGetValue()
        Invoke-Expression -Command $ht.Extent.Text
    }
}

if (-not (Get-Command -Name 'Microsoft.PowerShell.Utility\Import-PowerShellDataFile' -ErrorAction SilentlyContinue)) {
    New-Alias -Name 'Import-PowerShellDataFile' -Value 'Import-PowerShellDataFileLegacy'
}

function ConvertFrom-SnakeCase {
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]
        $SnakedString
    )

    Process {
        [regex]::Replace($SnakedString, '^_?.|_.', { param($m) $m.Value.TrimStart('_').ToUpperInvariant() })
    }
}

function ConvertFrom-AnsibleOption {
    [CmdletBinding()]
    [OutputType([System.Collections.IDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $Params ,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $OptionSet
    )

    End {
        $ret = @{}
        foreach ($option in $OptionSet.GetEnumerator()) {
            $raw_name = $option.Name
            switch -Wildcard ($raw_name) {
                'run_as_credential_*' {
                    $raw_name = $raw_name -replace '_[^_]+$'
                    $name = ConvertFrom-SnakeCase -SnakedString $raw_name
                    if (-not $ret.Contains($name)) {
                        $un = $Params["${raw_name}_username"]
                        if ($un) {
                            $secpw = ConvertTo-SecureString -String $Params["${raw_name}_password"] -AsPlainText -Force
                            $value = New-Object -TypeName PSCredential -ArgumentList $un, $secpw
                            $ret[$name] = $value
                        }
                    }
                    break
                }

                default {
                    $value = $Params[$raw_name]
                    if ($null -ne $value) {
                        if ($option.Value.choices) {
                            # the options that have choices have them listed in snake_case versions of their real values
                            $value = ConvertFrom-SnakeCase -SnakedString $value
                        }
                        $name = ConvertFrom-SnakeCase -SnakedString $raw_name
                        $ret[$name] = $value
                    }
                }
            }
        }

        $ret
    }
}

function Write-GeneratedSessionConfiguration {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $ParameterSet ,

        [Parameter()]
        [String]
        $OutFile
    )

    End {
        $file = if ($OutFile) {
            $OutFile
        }
        else {
            [System.IO.Path]::GetTempFileName()
        }

        $file = $file -replace '(?<!\.pssc)$', '.pssc'
        New-PSSessionConfigurationFile -Path $file @ParameterSet
        [System.IO.FileInfo]$file
    }
}

function Compare-ConfigFile {
    <#
        .SYNOPSIS
        This function compares the existing config file to the desired

        .DESCRIPTION
        We'll load the contents of both the desired and existing config, remove fields that shouldn't be
        compared, then generate a new config based on the existing and compare those files.

        This could be done as a direct file compare, without loading the contents as objects.
        The primary reasons to do it this slightly more complicated way are:

        - To ignore GUID as a value that matters: if you don't supply it a new one is generated for you,
          but PSSessionConfigurations don't use this for anything; it's just metadata. If you supply one,
          we want to compare it. If you don't, we shouldn't count the "mismatch" against you though.

        - To normalize the existing file based on the following stuff so we avoid unnecessary changes:

        - A file compare either has to be case insensitive (won't catch changes in values) or case sensitive
          (will may force changes on differences that don't matter, like case differences in key values)

        - A file compare will see changes on whitespace and line ending differences; although those could be
          accounted for in other ways, this method handles them.

        - A file compare will see changes on other non-impacting syntax style differences like indentation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]
        $ConfigFilePath ,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]
        $NewConfigFile ,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $Params ,

        [Parameter()]
        [String[]]
        $UseExistingIfMissing
    )

    Process {
        $desired_config = $NewConfigFile.FullName

        $existing_content = Import-PowerShellDataFile -LiteralPath $ConfigFilePath.FullName
        $desired_content = Import-PowerShellDataFile -LiteralPath $desired_config

        $module.Diff.before.pscc = $existing_content
        $module.Diff.after.pscc = $desired_content

        $regen = $false
        foreach ($ignorable_param in $UseExistingIfMissing) {
            # here we're checking for the parameters that shouldn't be compared if they are in the existing
            # config, but missing in the desired config. To account for this, we copy the value from the
            # existing into the desired so that when we regenerate it, it'll match the existing if there
            # aren't other changes.
            if (-not $Params.Contains($ignorable_param) -and $existing_content.Contains($ignorable_param)) {
                $desired_content[$ignorable_param] = $existing_content[$ignorable_param]
                $regen = $true
            }
        }

        # re-write and read the desired config file
        if ($regen) {
            $NewConfigFile.Delete()
            $desired_config = Write-GeneratedSessionConfiguration -ParameterSet $desired_content -OutFile $desired_config
        }

        $desired_content = Get-Content -Raw -LiteralPath $desired_config

        # re-write/import the existing one too to get a pristine version
        # this will account for unimporant case differences, comments, whitespace, etc.
        $pristine_config = Write-GeneratedSessionConfiguration -ParameterSet $existing_content
        $existing_content = Get-Content -Raw -LiteralPath $pristine_config

        # with all this de/serializing out of the way we can just do a simple case-sensitive string compare
        $desired_content -ceq $existing_content

        Remove-Item -LiteralPath $pristine_config -Force -ErrorAction SilentlyContinue
    }
}

function Compare-SessionOption {
    <#
        .DESCRIPTION
        This function is used for comparing the session options that don't get set in the config file.
        This _should_ have been straightforward for anything other than RunAsCredential, except that for
        some godforesaken reason a smattering of settings have names that differ from their parameter name.

        This list is defined internally in PowerShell here:
        https://git.io/JfUk7

    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $DesiredOptions ,

        [Parameter(Mandatory = $true)]
        [Object]
        $ExistingOptions
    )

    End {
        $optnamer = @{
            ThreadApartmentState = 'pssessionthreadapartmentstate'
            ThreadOptions = 'pssessionthreadoptions'
            MaximumReceivedDataSizePerCommandMb = 'PSMaximumReceivedDataSizePerCommandMB'
            MaximumReceivedObjectSizeMb = 'PSMaximumReceivedObjectSizeMB'
        } | Add-Member -MemberType ScriptMethod -Name GetValueOrKey -Value {
            param($key)

            $val = $this[$key]
            if ($null -eq $val) {
                return $key
            }
            else {
                return $val
            }
        } -Force -PassThru

        # Determine diffs in diff mode
        # AccessMode is not a property itself, it's a switch for the Register/Set command which changes some other config properties.
        # Remove it from Diff because it cannot be determined...
        $ignore_options_in_diff = @('AccessMode', 'RunAsCredential')

        $smatch = $true
        $after = @{}
        $before = @{}

        foreach ($opt in $session_configuration_options.GetEnumerator()) {
            if ($opt.Name -in $ignore_options_in_diff) { continue }
            $key = ConvertFrom-SnakeCase -SnakedString $optnamer.GetValueOrKey($opt.Name)
            $before.Add($key, $ExistingOptions.($key))
        }
        $after = $before.Clone()

        foreach ($opt in $DesiredOptions.GetEnumerator()) {
            if ($opt.Name -in $ignore_options_in_diff) { continue }
            $key = ConvertFrom-SnakeCase -SnakedString $optnamer.GetValueOrKey($opt.Name)
            $after[$key] = $opt.Value

            $smatch = $smatch -and (
                $ExistingOptions.($optnamer.GetValueOrKey($opt.Name)) -ceq $opt.Value
            )
            if (-not $smatch -and -not $module.DiffMode) {
                break
            }
        }

        $module.Diff.before.session = $before
        $module.Diff.after.session = $after

        if ($DesiredOptions.Contains('RunAsCredential')) {
            # since we can't retrieve/compare password, a change must always be made if a cred is specified
            return $false
        }

        return $smatch
    }
}

<#
    For use with possible future enhancement.
    Right now the biggest challenges to this are:
        - Ansible's connection itself: the number doesn't go to 0 while we're here running
          and waiting for it. I thought being async it would disappear but either that's not
          the case or it's taking too long to do so.

        - I have not found a reliable way to determine which WinRM connection is the one used for
          the Ansible connection. Over psrp we can use Get-PSSession -ComputerName but that won't
          work for the winrm connection plugin.

        - Connections seem to take time to disappear. In tests when trying to start time-limited
          sessions, like:
          icm -computername . -scriptblock { Start-Sleep -Seconds 30 } -AsJob
          After the time elapses the connection lingers for a little while after. Should be ok but
          does add some challenges to writing tests.

        - Checking for instances of the shell resource looks reliable, but I'm not yet certain
          if it captures all WinRM connections, like CIM connections. Still would be better than
          nothing.
#>
# function Wait-WinRMConnection {
#     <#
#         .SYNOPSIS
#         Waits for existing WinRM connections to finish

#         .DESCRIPTION
#         Finds existing WinRM connections that are in a set of states (configurable), and waits for them
#         to disappear, or times out.
#     #>
#     [CmdletBinding()]
#     param(
#         [Parameter(Mandatory=$true)]
#         [Ansible.Basic.AnsibleModule]
#         $Module
#     )

#     End {
#         $action     = $Module.Params.existing_connection_timeout_action
#         $states     = $Module.Params.existing_connection_wait_states
#         $timeout_ms = [System.Math]::Min(0, $Module.Params.existing_connection_timeout_seconds) * 1000
#         $interval   = [System.Math]::Max([System.Math]::Min(100, $Module.Params.existing_connection_timeout_interval_ms), $timeout_ms)

#         # Would only with psrp
#         $thiscon = Get-PSSession -ComputerName . | Select-Object -ExpandProperty InstanceId

#         $sw = New-Object -TypeName System.Diagnostics.Stopwatch

#         do {
#             $connections = Get-WSManInstance -ComputerName localhost -ResourceURI shell -Enumerate |
#                 Where-Object -FilterScript {
#                     $states -contains $_.State -and (
#                         -not $thiscon -or
#                         $thiscon -ne $_.ShellId
#                     )
#                 }

#             $sw.Start()
#             Start-Sleep -Milliseconds $interval
#         } while ($connections -and $sw.ElapsedMilliseconds -lt $timeout_ms)
#         $sw.Stop()

#         if ($connections -and $action -eq 'fail') {
#             # somehow $connections.Count sometimes is blank (not 0) but I can't figure out how that's possible
#             $Module.FailJson("$($connections.Count) remained after timeout.")
#         }
#     }
# }

$PSDefaultParameterValues = @{
    '*-PSSessionConfiguration:Force' = $true
    'ConvertFrom-AnsibleOption:Params' = $module.Params
    'Wait-WinRMConnection:Module' = $module
}

$opt_pssc = ConvertFrom-AnsibleOption -OptionSet $pssc_options
$opt_session = ConvertFrom-AnsibleOption -OptionSet $session_configuration_options

$existing = Get-PSSessionConfiguration -Name $opt_session.Name -ErrorAction SilentlyContinue

try {
    $module.Diff.before = @{ session = $null; pscc = $null; }
    $module.Diff.after = @{ session = $null; pscc = $null; }

    if ($opt_pssc.Count) {
        # config file options were passed to the module, so generate a config file from those
        $desired_config = Write-GeneratedSessionConfiguration -ParameterSet $opt_pssc
    }
    if ($existing) {
        # the endpoint is registered
        if ($existing.ConfigFilePath -and (Test-Path -LiteralPath $existing.ConfigFilePath)) {
            # the registered endpoint uses a config file
            if ($desired_config) {
                # a desired config file exists, so compare it to the existing one
                $content_match = $existing |
                    Compare-ConfigFile -NewConfigFile $desired_config -Params $opt_pssc -UseExistingIfMissing (
                        $module.Params.lenient_config_fields | ConvertFrom-SnakeCase
                    )
            }
            else {
                # existing endpoint has a config file but no config file options were passed, so there is no match
                $content_match = $false
            }
        }
        else {
            # existing endpoint doesn't use a config file, so it's a match if there are also no config options passed
            $content_match = $opt_pssc.Count -eq 0
        }

        $session_match = Compare-SessionOption -DesiredOptions $opt_session -ExistingOptions $existing
    }

    $state = $module.Params.state

    $create = $state -eq 'present' -and (-not $existing -or -not $content_match)
    $remove = $existing -and ($state -eq 'absent' -or -not $content_match)
    $session_change = -not $session_match -and $state -ne 'absent'

    $module.Result.changed = $create -or $remove -or $session_change

    # In this module, we pre-emptively remove the session configuratin if there's any change
    # in the config file options, and then re-register later if needed.
    # But if the RunAs credential is wrong, the register will fail, and since we already removed
    # the existing one, it will be gone.
    #
    # So let's ensure we can actually use the credential by logging on with TokenUtil,
    # that way we can fail before touching the existing config.
    if ($opt_session.Contains('RunAsCredential')) {
        $cred = $opt_session.RunAsCredential
        $username = $cred.Username
        $domain = $null
        if ($username.Contains('\')) {
            $domain, $username = $username.Split('\')
        }
        try {
            $handle = [Ansible.AccessToken.TokenUtil]::LogonUser($username, $domain, $cred.GetNetworkCredential().Password, 'Network', 'Default')
            $handle.Dispose()
        }
        catch {
            $module.FailJson("Could not validate RunAs Credential: $($_.Exception.Message)", $_)
        }
    }

    if (-not $module.CheckMode) {
        if ($remove) {
            # Wait-WinRMConnection
            $null = Unregister-PSSessionConfiguration -Name $opt_session.Name
        }

        if ($create) {
            if ($desired_config) {
                $opt_session.Path = $desired_config
            }
            # Wait-WinRMConnection
            $null = Register-PSSessionConfiguration @opt_session
        }
        elseif ($session_change) {
            $psso = $opt_session
            # Wait-WinRMConnection
            $null = Set-PSSessionConfiguration @psso
        }
    }
}
catch [System.Management.Automation.ParameterBindingException] {
    $e = $_
    if ($e.Exception.ErrorId -eq 'NamedParameterNotFound') {
        $psv = $PSVersionTable.PSVersion.ToString(2)
        $param = $e.Exception.ParameterName
        $cmd = $e.InvocationInfo.MyCommand.Name
        $message = "Parameter '$param' is not available for '$cmd' in PowerShell $psv."
    }
    else {
        $message = "Unknown parameter binding error: $($e.Exception.Message)"
    }

    $module.FailJson($message, $e)
}
finally {
    if ($desired_config) {
        Remove-Item -LiteralPath $desired_config -Force -ErrorAction SilentlyContinue
    }
}

$module.ExitJson()
