#!powershell

# Copyright: (c) 2024, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


#AnsibleRequires -CSharpUtil Ansible.Basic

function Get-ConnectAsInfo {
    param (
        [string] $site,
        [string] $appName
    )

    # Construct the IIS path
    $appPath = "IIS:\Sites\$($site)\$($appName)"

    # Get the properties of the web application or virtual directory
    $appProperties = Get-ItemProperty -LiteralPath $appPath

    # Determine the Connect-As mode
    if ($appProperties.userName -and $appProperties.userName -ne "") {
        $connect_as = "specific_user"
        $username = $appProperties.userName
    }
    else {
        $connect_as = "pass_through"
        $username = ""
    }
    return @{
        connect_as = $connect_as
        username = $username
    }
}
$spec = @{
    options = @{
        name = @{ type = "str" }
        site = @{ type = "str" }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$name = $module.Params.name
$site = $module.Params.site

$module.Result.exists = $false
$module.Result.applications = @()

try {
    # Ensure WebAdministration module is loaded
    if ($null -eq (Get-Module "WebAdministration" -ErrorAction SilentlyContinue)) {
        Import-Module WebAdministration
    }
}
catch {
    $module.FailJson("Failed to load WebAdministration module, Exception: $($_.Exception.Message)", $_)
}

try {
    $getParams = @{}
    if ($name) {
        $getParams.Name = $name
    }
    if ($site) {
        $getParams.Site = $site
    }
    $applications = Get-WebApplication @getParams
}
catch {
    $module.FailJson("Failed to get web applications, Exception: $($_.Exception.Message)", $_)
}
if ($null -ne $applications) {
    $module.Result.exists = $true
}

try {
    $module.Result.applications = @(
        foreach ($application in $applications) {
            # Get site name from the application object
            $site_name = $application.GetParentElement().Attributes["name"].Value
            $app_name = $application.Path.TrimStart('/')

            # Fetch Connect-As information once
            $connectAsInfo = Get-ConnectAsInfo -site $site_name -appName $app_name
            @{
                name = $app_name
                site = $site_name
                connect_as = $connectAsInfo.connect_as
                username = $connectAsInfo.username
                application_pool = $application.ApplicationPool
                physical_path = $application.PhysicalPath
                enabled_protocols = $application.EnabledProtocols
            }
        }
    )
}
catch {
    $module.FailJson("Failed to get application details, Exception: $($_.Exception.Message)", $_)
}

$module.ExitJson()
