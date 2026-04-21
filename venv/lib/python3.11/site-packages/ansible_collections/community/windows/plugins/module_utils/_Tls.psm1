# Copyright: (c) 2025, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# This module_util is for internal use only. It is not intended to be used by
# collections outside of community.windows.

using namespace System.Net
using namespace System.Reflection

function Enable-TlsProtocol {
    <#
    .SYNOPSIS
    Gets .NET to use the system configured TLS protocols for outbound connections.

    .DESCRIPTION
    This function ensures that the .NET runtime is configured to use the system
    configured TLS protocols for outbound connections. This is particularly
    important for PowerShell hosts running on older versions of .NET Framework
    where only TLS 1.0 is used.

    This also handles running in a PSRemoting WSMan host where the default is
    hardcoded to use 1.0, 1.1, and 1.2 only even if 1.3 is available.

    .NOTES
    https://github.com/ansible-collections/ansible.windows/pull/573#issuecomment-1865477707
    #>
    [CmdletBinding()]
    param ()

    $currentProtocol = [ServicePointManager]::SecurityProtocol
    if ([SecurityProtocolType].GetMember("Tls13")) {
        # If the Tls13 member is present we are on .NET Framework 4.8+ so using
        # the SystemDefault setting will use the OS policies. If it's not set
        # to SystemDefault already we are running in a PSRemoting WSMan host
        # and need some reflection to reconfigure the policies to get it to use
        # the OS policies.

        if ($currentProtocol -ne 'SystemDefault') {
            # https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls#switchsystemnetdontenablesystemdefaulttlsversions
            $disableSystemTlsField = [ServicePointManager].GetField(
                's_disableSystemDefaultTlsVersions',
                [BindingFlags]'NonPublic, Static')
            if ($disableSystemTlsField -and $disableSystemTlsField.GetValue($null)) {
                $disableSystemTlsField.SetValue($null, $false)
            }

            [ServicePointManager]::SecurityProtocol = [SecurityProtocolType]::SystemDefault
        }
    }
    else {
        # We are on .NET 4.7 or older, as TLS 1.2 is the max version we can
        # use here regardless of the OS, manually enable the protocols known to
        # the runtime.
        if ([SecurityProtocolType].GetMember("Tls11")) {
            $currentProtocol = $currentProtocol -bor [SecurityProtocolType]::Tls11
        }
        if ([SecurityProtocolType].GetMember("Tls12")) {
            $currentProtocol = $currentProtocol -bor [SecurityProtocolType]::Tls12
        }
        [ServicePointManager]::SecurityProtocol = $currentProtocol
    }

}

Export-ModuleMember -Function Enable-TlsProtocol
