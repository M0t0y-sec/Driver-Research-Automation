<#
.SYNOPSIS
    Build and test-sign DraTestDriver.

.DESCRIPTION
    Locates Visual Studio through vswhere, builds the project with MSBuild
    (WDK toolset), then signs the resulting .sys with a self-signed test
    certificate.

    Run this from an elevated PowerShell prompt. Requires Visual Studio 2022
    with "Desktop development with C++" and the Windows 11 WDK.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Configuration Release
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vcxproj = Join-Path $projectDir 'DraTestDriver.vcxproj'

function Get-VsInstallPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe not found. Install Visual Studio 2022 with the C++ workload."
    }
    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $path) {
        throw "No Visual Studio installation with the C++ toolset was found."
    }
    return $path.Trim()
}

function Get-MSBuildPath([string]$vsPath) {
    $candidate = Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (-not (Test-Path $candidate)) {
        throw "MSBuild.exe not found under $vsPath."
    }
    return $candidate
}

function Invoke-Build([string]$msbuild, [string]$vsPath) {
    $env:VCTargetsPath = Join-Path $vsPath 'MSBuild\Microsoft\VC\v170\'
    & $msbuild $vcxproj /p:Configuration=$Configuration /p:Platform=$Platform /m /v:minimal
    if ($LASTEXITCODE -ne 0) {
        throw "MSBuild failed with exit code $LASTEXITCODE."
    }
}

function Get-SysPath {
    $path = Join-Path $projectDir "bin\$Platform\$Configuration\DraTestDriver.sys"
    if (-not (Test-Path $path)) {
        throw "Build reported success but $path is missing."
    }
    return $path
}

function Ensure-TestCertificate {
    $subject = 'CN=DraTestDriverTest'
    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $subject } |
        Select-Object -First 1

    if ($existing) {
        return $existing
    }

    Write-Host "Creating self-signed test certificate $subject"
    return New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $subject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -HashAlgorithm SHA256 `
        -KeyLength 2048 `
        -NotAfter (Get-Date).AddYears(3)
}

function Get-SignToolPath {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $found = Get-ChildItem $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    throw "signtool.exe not found under Windows Kits. Install the Windows SDK signing tools."
}

function Invoke-Sign([string]$signtool, [string]$sysPath, $cert) {
    $pfx = Join-Path $projectDir 'DraTestDriver.pfx'
    $cer = Join-Path $projectDir 'DraTestDriver.cer'
    $password = ConvertTo-SecureString -String 'dratest' -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $password | Out-Null

    # The guest must trust this public certificate before the .sys will load.
    Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null

    & $signtool sign /fd sha256 /f $pfx /p dratest /t http://timestamp.digicert.com $sysPath
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Timestamping failed; retrying without a timestamp server."
        & $signtool sign /fd sha256 /f $pfx /p dratest $sysPath
        if ($LASTEXITCODE -ne 0) {
            throw "signtool sign failed with exit code $LASTEXITCODE."
        }
    }

    Remove-Item $pfx -Force
    Write-Host "Signed $sysPath"
    Write-Host "Public certificate written to $cer -- copy it into the guest."
}

$vsPath = Get-VsInstallPath
$msbuild = Get-MSBuildPath $vsPath
Write-Host "Visual Studio: $vsPath"

Invoke-Build $msbuild $vsPath
$sysPath = Get-SysPath
Write-Host "Built $sysPath"

$cert = Ensure-TestCertificate
$signtool = Get-SignToolPath
Invoke-Sign $signtool $sysPath $cert

Write-Host ''
Write-Host 'Build complete. Next steps:'
Write-Host '  1. Guest must have: bcdedit /set testsigning on  and a reboot'
Write-Host '  2. Copy the .sys into the guest'
Write-Host '  3. Run install.ps1 inside the guest, as Administrator'
