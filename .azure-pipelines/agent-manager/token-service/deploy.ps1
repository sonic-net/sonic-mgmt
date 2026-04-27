#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deploy the sonic-nightly-service Python app to Azure App Service.

.DESCRIPTION
    Idempotent, repeatable deployment script. Runs from a Windows machine
    that has the `az` CLI installed and `az login` already done.

    Steps:
      1. Verify az is installed and a session is active.
      2. Optionally switch to the requested subscription.
      3. Package the runtime files of this folder into a temporary zip
         (excludes tests/, __pycache__, this script, the README, etc.).
      4. Deploy via `az webapp deploy --type zip`.
      5. Smoke-test the public endpoint (`GET /` must return 401).
      6. Clean up the temporary zip.

.PARAMETER ResourceGroup
    Azure resource group containing the Web App. Defaults to "sonic-nightly".

.PARAMETER WebAppName
    Web App name (must match the one created by provision.ps1). Defaults
    to "sonic-nightly-service".

.PARAMETER SubscriptionId
    Optional. If provided, the script switches the active subscription
    before deploying.

.PARAMETER SkipSmokeTest
    Skip the post-deploy "GET / must return 401" probe.

.EXAMPLE
    .\deploy.ps1
    Deploys with all defaults.

.EXAMPLE
    .\deploy.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"
    Switches subscription before deploying.
#>

[CmdletBinding()]
param(
    [string]$ResourceGroup  = "sonic-nightly",
    [string]$WebAppName     = "sonic-nightly-service",
    [string]$SubscriptionId = "",
    [switch]$SkipSmokeTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Assert-AzReady {
    Write-Step "Verifying az CLI"
    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if ($null -eq $azCmd) {
        throw "az CLI not found in PATH. Install it from https://aka.ms/InstallAzureCli."
    }
    try {
        $account = az account show --output json 2>$null | ConvertFrom-Json
    } catch {
        throw "Not logged in. Run 'az login' and try again."
    }
    if ($null -eq $account) {
        throw "Not logged in. Run 'az login' and try again."
    }
    Write-Host "  Subscription: $($account.name) ($($account.id))"
    Write-Host "  User:         $($account.user.name)"
    return $account
}

function Switch-Subscription($targetId) {
    if ([string]::IsNullOrWhiteSpace($targetId)) { return }
    Write-Step "Switching active subscription to $targetId"
    az account set --subscription $targetId | Out-Null
}

function New-DeployZip {
    Write-Step "Packaging app for deployment"
    $sourceDir = $PSScriptRoot
    $zipPath   = Join-Path $sourceDir "deploy.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

    $stagingDir = Join-Path ([System.IO.Path]::GetTempPath()) `
        ("sonic-nightly-service-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $stagingDir | Out-Null

    try {
        $excludePatterns = @(
            "deploy.ps1",
            "provision.ps1",
            "README.md",
            ".gitignore",
            ".venv",
            "__pycache__",
            "tests",
            "*.pyc",
            "deploy.zip",
            ".pytest_cache"
        )
        Get-ChildItem -Path $sourceDir -Force | Where-Object {
            $name = $_.Name
            -not ($excludePatterns | Where-Object { $name -like $_ })
        } | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination $stagingDir -Recurse -Force
        }

        # Sanity check: app.py must be at the zip root.
        if (-not (Test-Path (Join-Path $stagingDir "app.py"))) {
            throw "Packaging error: app.py is not at the zip root."
        }

        Compress-Archive -Path (Join-Path $stagingDir "*") `
                         -DestinationPath $zipPath -Force
        Write-Host "  Created $zipPath"
        return $zipPath
    } finally {
        Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Deploy($rg, $app, $zipPath) {
    Write-Step "Deploying $zipPath to $rg/$app"
    az webapp deploy `
        --resource-group $rg `
        --name $app `
        --src-path $zipPath `
        --type zip `
        --async false `
        --output table
}

function Invoke-SmokeTest($app) {
    Write-Step "Smoke test: GET https://$app.azurewebsites.net/ must return 401"
    $url = "https://$app.azurewebsites.net/"
    # The app may take a few seconds to start a fresh worker after deploy.
    $maxAttempts = 12
    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $resp = Invoke-WebRequest -Uri $url -Method GET `
                                      -TimeoutSec 15 `
                                      -SkipHttpErrorCheck
            $code = [int]$resp.StatusCode
            if ($code -eq 401) {
                Write-Host "  OK (HTTP 401)"
                return
            }
            Write-Host "  Attempt ${i}/${maxAttempts}: HTTP $code, retrying in 5s..."
        } catch {
            Write-Host "  Attempt ${i}/${maxAttempts}: $($_.Exception.Message), retrying in 5s..."
        }
        Start-Sleep -Seconds 5
    }
    throw "Smoke test failed: $url did not return 401 within $($maxAttempts * 5) seconds."
}

# ---- main ----
Assert-AzReady | Out-Null
Switch-Subscription $SubscriptionId

$zip = New-DeployZip
try {
    Invoke-Deploy -rg $ResourceGroup -app $WebAppName -zipPath $zip
    if (-not $SkipSmokeTest) {
        Invoke-SmokeTest -app $WebAppName
    } else {
        Write-Step "Smoke test skipped (-SkipSmokeTest)"
    }
} finally {
    if (Test-Path $zip) { Remove-Item $zip -Force }
}

Write-Host ""
Write-Host "Deployed: https://$WebAppName.azurewebsites.net/" -ForegroundColor Green
