#!powershell

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell Ansible.ModuleUtils.AddType

$spec = @{
    options = @{
        blob_path = @{
            type = 'str'
        }
        domain_server = @{
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
        provision_root_ca_certs = @{
            type = 'bool'
            default = $false
        }
    }
    mutually_exclusive = @(
        , @('identity', 'name')
    )
    required_one_of = @(
        , @('identity', 'name')
    )
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$adParams = @{}
if ($module.Params.domain_server) {
    $adParams.Server = $module.Params.domain_server
}

$module.Result.blob = $null

Add-CSharpType -AnsibleModule $module -References @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace microsoft.ad.domain_join
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct NETSETUP_PROVISIONING_PARAMS
    {
        internal const int NETSETUP_PROVISIONING_PARAMS_CURRENT_VERSION = 0x00000001;

        public int dwVersion;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpDomain;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpHostName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpMachineAccountOU;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpDCName;
        public int dwProvisionOptions;
        public IntPtr aCertTemplateNames;
        public int cCertTemplateNames;
        public IntPtr aMachinePolicyNames;
        public int cMachinePolicyNames;
        public IntPtr aMachinePolicyPaths;
        public int cMachinePolicyPaths;
        public IntPtr lpNetbiosName;
        public IntPtr lpSiteName;
        public IntPtr lpPrimaryDNSDomain;
    }

    [Flags]
    public enum ProvisionOptions
    {
        NETSETUP_PROVISION_DOWNLEVEL_PRIV_SUPPORT = 0x00000001,
        NETSETUP_PROVISION_REUSE_ACCOUNT = 0x00000002,
        NETSETUP_PROVISION_USE_DEFAULT_PASSWORD = 0x00000004,
        NETSETUP_PROVISION_SKIP_ACCOUNT_SEARCH = 0x00000008,
        NETSETUP_PROVISION_ROOT_CA_CERTS = 0x00000010,
        NETSETUP_PROVISION_PERSISTENTSITE = 0x00000020,
    }

    public static class Native
    {
        [DllImport("Netapi32.dll", EntryPoint = "NetCreateProvisioningPackage")]
        private static extern int NativeNetCreateProvisioningPackage(
            ref NETSETUP_PROVISIONING_PARAMS pProvisioningParams,
            ref IntPtr ppPackageBinData,
            out int ppdwPackageBinDataSize,
            IntPtr ppPackageTextData);

        public static byte[] NetCreateProvisioningPackage(string domain, string hostName, string machineAccountOU,
            string dcName, ProvisionOptions options)
        {
            domain = String.IsNullOrWhiteSpace(domain) ? null : domain;
            hostName = String.IsNullOrWhiteSpace(hostName) ? null : hostName;
            machineAccountOU = String.IsNullOrWhiteSpace(machineAccountOU) ? null : machineAccountOU;
            dcName = String.IsNullOrWhiteSpace(dcName) ? null : dcName;

            NETSETUP_PROVISIONING_PARAMS p = new NETSETUP_PROVISIONING_PARAMS()
            {
                dwVersion = NETSETUP_PROVISIONING_PARAMS.NETSETUP_PROVISIONING_PARAMS_CURRENT_VERSION,
                lpDomain = domain,
                lpHostName = hostName,
                lpMachineAccountOU = machineAccountOU,
                lpDCName = dcName,
                dwProvisionOptions = (int)options,
            };

            IntPtr outBuffer = IntPtr.Zero;
            int outBufferLength = 0;
            int res = NativeNetCreateProvisioningPackage(ref p, ref outBuffer, out outBufferLength, IntPtr.Zero);
            if (res != 0)
            {
                throw new Win32Exception(res);
            }

            byte[] data = new byte[outBufferLength];
            Marshal.Copy(outBuffer, data, 0, data.Length);

            return data;
        }
    }
}
'@

$identity = if ($module.Params.identity) {
    $module.Params.identity
}
else {
    $path = $module.Params.path
    if (-not $path) {
        $GUID_COMPUTERS_CONTAINER_W = 'AA312825768811D1ADED00C04FD8D5CD'
        $defaultNamingContext = (Get-ADRootDSE @adParams -Properties defaultNamingContext).defaultNamingContext

        $path = Get-ADObject @ADParams -Identity $defaultNamingContext -Properties wellKnownObjects |
            Select-Object -ExpandProperty wellKnownObjects |
            Where-Object { $_.StartsWith("B:32:$($GUID_COMPUTERS_CONTAINER_W):") } |
            ForEach-Object Substring 38
    }

    "CN=$($Module.Params.name -replace ',', '\,'),$path"
}

try {
    $computer = Get-ADComputer -Identity $identity @adParams
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    $msg = "Failed to find domain computer account '$identity': $($_.Exception.Message)"
    $module.FailJson($msg, $_)
}


# The name expected by NetCreateProvisioningPackage is the sAMAccountName but
# without the trailing $.
$computerName = $computer.SamAccountName.Substring(0,
    $computer.SamAccountName.Length - 1)
$computerPath = @($computerName.DistinguishedName -split '[^\\],', 2)[-1]

$flags = [microsoft.ad.domain_join.ProvisionOptions]::NETSETUP_PROVISION_REUSE_ACCOUNT
if ($module.Params.provision_root_ca_certs) {
    $flags = $flags -bor [microsoft.ad.domain_join.ProvisionOptions]::NETSETUP_PROVISION_ROOT_CA_CERTS
}

$domainInfo = Get-ADDomain @adParams

if ($module.Params.blob_path -and (Test-Path -LiteralPath $module.Params.blob_path)) {
    $module.ExitJson()
}

if (-not $Module.CheckMode) {
    $blob = [microsoft.ad.domain_join.Native]::NetCreateProvisioningPackage(
        $domainInfo.DNSRoot,
        $computerName,
        $computerPath,
        $adParams.Server,
        $flags)
}
else {
    $blob = New-Object -TypeName System.Byte[] -ArgumentList 0
}

$module.Result.changed = $true

if ($module.Params.blob_path) {
    if (-not $Module.CheckMode) {
        [System.IO.File]::WriteAllBytes($module.Params.blob_path, $blob)
    }
}
else {
    $module.Result.blob = [System.Convert]::ToBase64String($blob)
}

$module.ExitJson()
