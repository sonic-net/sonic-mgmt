#!powershell

# Copyright: (c) 2021, Kento Yagisawa <thel.vadam2485@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        # Need to support \* which type='path' does not, the path is expanded further down.
        src = @{ type = 'str'; required = $true }
        dest = @{ type = 'path'; required = $true }
    }
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$src = [Environment]::ExpandEnvironmentVariables($module.Params.src)
$dest = $module.Params.dest

$srcFile = [System.IO.Path]::GetFileName($src)
$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
$encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$srcWildcard = $false

# If the path ends with '\*' we want to include the dir contents and not the dir itself
If ($src -match '\\\*$') {
    $srcWildcard = $true
    $src = $src.Substring(0, $src.Length - 2)
}

If (-not (Test-Path -LiteralPath $src)) {
    $module.FailJson("The source file or directory '$src' does not exist.")
}

If ($dest -notlike "*.zip") {
    $module.FailJson("The destination zip file path '$dest' need to be zip file path.")
}

If (Test-Path -LiteralPath $dest) {
    $module.Result.msg = "The destination zip file '$dest' already exists."
    $module.ExitJson()
}

# Check .NET v4.5 or later version exists or not
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
}
catch {
    $module.FailJson(".NET Framework 4.5 or later version needs to be installed.", $_)
}

Function Compress-Zip($src, $dest) {
    # Disable using backslash for Zip path. This works for .NET 4.6.1 or later
    if ([object].Assembly.GetType("System.AppContext")) {
        [System.AppContext]::SetSwitch('Switch.System.IO.Compression.ZipFile.UseBackslash', $false)
    }

    If (-not $module.CheckMode) {
        If (Test-Path -LiteralPath $src -PathType Container) {
            [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $dest, $compressionLevel, (-not $srcWildcard), $encoding)
        }
        Else {
            $zip = [System.IO.Compression.ZipFile]::Open($dest, 'Update')
            try {
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $src, $srcFile, $compressionLevel)
            }
            finally {
                $zip.Dispose()
            }
        }
    }
    $module.Result.changed = $true
}

Compress-Zip -src $src -dest $dest

$module.ExitJson()
