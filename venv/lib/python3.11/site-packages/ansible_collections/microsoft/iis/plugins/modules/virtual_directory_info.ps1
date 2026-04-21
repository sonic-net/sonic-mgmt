#!powershell

# Copyright: (c) 2025, Hen Yaish <hyaish@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        name = @{ type = "str" }
        site = @{ type = "str" }
        application = @{ type = "str" }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$name = $module.Params.name
$site = $module.Params.site
$application = $module.Params.application

try {
    if ($null -eq (Get-Module "WebAdministration" -ErrorAction SilentlyContinue)) {
        Import-Module WebAdministration
    }
}
catch {
    $module.FailJson("Failed to ensure WebAdministration module is loaded: $_", $_)
}

try {
    $directoryParams = @{}
    if ($name) {
        $directoryParams.Name = $name
    }
    if ($site) {
        $directoryParams.Site = $site
    }
    if ($application) {
        $directoryParams.Application = $application
    }
    $directories = Get-WebVirtualDirectory @directoryParams

    $module.Result.exists = $false
    $module.Result.directories = @()

    foreach ($directory in $directories) {
        if (-not $module.Result.exists) {
            $module.Result.exists = $true
        }

        $app = $directory.GetParentElement()
        $appName = $app.GetAttribute('path').Value.TrimStart('/')
        $site = $app.GetParentElement()

        $module.Result.directories += @{
            name = $directory.Path.Trim('/')
            site = $site.GetAttribute('name').Value
            physical_path = $directory.PhysicalPath
            application = $appName
            username = $directory.userName
            connect_as = if ($directory.userName) { 'specific_user' } else { 'pass_through' }
        }
    }
}
catch {
    $module.FailJson($_.Exception.Message, $_)
}

$module.ExitJson()