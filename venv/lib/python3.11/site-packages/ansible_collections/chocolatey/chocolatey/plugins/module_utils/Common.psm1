#AnsibleRequires -CSharpUtil Ansible.Basic

$script:module = $null

function Set-ActiveModule {
    <#
        .SYNOPSIS
        Sets the currently active Ansible module.

        .DESCRIPTION
        Caches a reference to the currently active Ansible module object that
        to be retrieved and used by other commands, so we can minimise the need
        to specify values for `-Module` parameters on every command we use.
    #>
    [CmdletBinding()]
    param(
        # The Ansible.Basic.AnsibleModule to set as active.
        [Parameter(Mandatory = $true)]
        [Ansible.Basic.AnsibleModule]
        $Module
    )

    $script:module = $Module
}

function Get-AnsibleModule {
    <#
        .SYNOPSIS
        Retrieves the currently active module object.

        .DESCRIPTION
        Returns the currently cached module object.
    #>
    [CmdletBinding()]
    param()

    $script:module
}

function Get-ChocolateyCommand {
    <#
        .SYNOPSIS
        Retrieves a CommandInfo object for `choco.exe` if it is present on the system.

        .DESCRIPTION
        Returns either a CommandInfo object which contains the path the `choco.exe`
        or registers a task failure and exits if it cannot be found.
    #>
    [CmdletBinding()]
    param(
        # If provided, does not terminate the task run when choco.exe is not found.
        [Parameter()]
        [switch]
        $IgnoreMissing
    )

    $command = Get-Command -Name choco.exe -CommandType Application -ErrorAction SilentlyContinue -TotalCount 1

    if (-not $command) {
        $installDir = if ($env:ChocolateyInstall) {
            $env:ChocolateyInstall
        }
        else {
            "$env:SYSTEMDRIVE\ProgramData\Chocolatey"
        }

        $command = Get-Command -Name "$installDir\bin\choco.exe" -CommandType Application -ErrorAction SilentlyContinue

        if (-not ($command -or $IgnoreMissing)) {
            $message = "Failed to find Chocolatey installation, make sure choco.exe is in the PATH env value"
            Assert-TaskFailed -Message $message
        }
    }

    $command
}

function Assert-TaskFailed {
    <#
        .SYNOPSIS
        Notifies Ansible that the task failed, and exits after providing the necessary details.

        .DESCRIPTION
        Exits the current Ansible task with a failure state, recording a message as well as
        any other relevant information for the current task.
    #>
    [CmdletBinding()]
    param(
        # Message to be returned to the task runner, indicating why the failure happened.
        [Parameter(Mandatory = $true)]
        [string]
        $Message,

        # The Ansible module object to register the failure with.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule),

        # The native command call that resulted in the error, if any.
        [Parameter()]
        [string]
        $Command,

        # A hashtable containing `stdout`, `stderr`, and `rc` keys resulting from
        # a native command execution, which will be copied to the module's Result
        # dictionary before returning the fail state.
        [Parameter()]
        [hashtable]
        $CommandResult,

        # An exception to provide to the `$module.ExitJson()` method with further
        # information about the error, if any.
        [Parameter()]
        [Exception]
        $Exception
    )

    if ($null -ne $CommandResult) {
        $resultKeys = 'rc', 'stdout', 'stderr'

        foreach ($key in $resultKeys) {
            $Module.Result.$key = $CommandResult.$key
        }
    }

    if ($null -ne $Command) {
        $Module.Result.command = $Command
    }

    if ($null -ne $Exception) {
        $Module.FailJson($Message, $Exception)
    }
    else {
        $Module.FailJson($Message)
    }
}

function ConvertFrom-Stdout {
    <#
        .SYNOPSIS
        Trims and splits the stdout from the given result so that individual
        lines can be processed.

        .DESCRIPTION
        Retrieves the `stdout` key from the given dictionary and trims and splits
        the value in a standardised way.
    #>
    [CmdletBinding()]
    param(
        # The command result dictionary from a native command invocation.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [hashtable]
        $CommandResult
    )
    process {
        $CommandResult.stdout.Trim() -split "\r?\n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    }
}

function Set-TaskResultChanged {
    <#
        .SYNOPSIS
        Flags the task result for the module as being changed.
    #>
    [CmdletBinding()]
    param(
        # The module to set the task result on.
        # Defaults to the currently active module.
        [Parameter()]
        [Ansible.Basic.AnsibleModule]
        $Module = (Get-AnsibleModule)
    )

    $Module.Result.changed = $true
}

Export-ModuleMember -Function @(
    'Get-ChocolateyCommand'
    'Get-AnsibleModule'
    'ConvertFrom-Stdout'
    'Set-ActiveModule'
    'Set-TaskResultChanged'
    'Assert-TaskFailed'
)
