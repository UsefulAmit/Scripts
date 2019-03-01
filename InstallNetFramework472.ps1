#Requires -Version 3.0

<#
.DESCRIPTION
    Install .Net Framework 4.7.2
#>


[CmdletBinding()]
Param(
    [switch]$norestart
)

Set-StrictMode -Version Latest

function Set-PrivateKeyPermissions {
param(
[Parameter(Mandatory=$true)][string]$thumbprint,
[Parameter(Mandatory=$true)][string]$account 
)
#Open Certificate store and locate certificate based on provided thumbprint
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
$store.Open("ReadWrite")
$cert = $store.Certificates | where {$_.Thumbprint -eq $thumbprint}

#Create new CSP object based on existing certificate provider and key name
$csp = New-Object System.Security.Cryptography.CspParameters($cert.PrivateKey.CspKeyContainerInfo.ProviderType, $cert.PrivateKey.CspKeyContainerInfo.ProviderName, $cert.PrivateKey.CspKeyContainerInfo.KeyContainerName)

# Set flags and key security based on existing cert
$csp.Flags = "UseExistingKey","UseMachineKeyStore"
$csp.CryptoKeySecurity = $cert.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity
$csp.KeyNumber = $cert.PrivateKey.CspKeyContainerInfo.KeyNumber

# Create new access rule - could use parameters for permissions, but I only needed GenericRead
$access = New-Object System.Security.AccessControl.CryptoKeyAccessRule($account,"GenericRead","Allow")
# Add access rule to CSP object
$csp.CryptoKeySecurity.AddAccessRule($access)

#Create new CryptoServiceProvider object which updates Key with CSP information created/modified above
$rsa2 = New-Object System.Security.Cryptography.RSACryptoServiceProvider($csp)

#Close certificate store
$store.Close()

}

Set-PrivateKeyPermissions "36f06018884256cd94cc916341d83aad75bc4559" "Network Service"
Set-PrivateKeyPermissions "1f5dbdbf7eb641795024b601e63c66fcd2720b4e" "Network Service"

$logFile = Join-Path $env:TEMP -ChildPath "InstallNetFx472ScriptLog.txt"

Write-Host $logFile

# Check if the latest NetFx472 version exists
$netFxKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\" -ErrorAction Ignore

if($netFxKey -and $netFxKey.Release -ge 461808) {
    "$(Get-Date): The machine already has NetFx 4.7.2 or later version installed." | Tee-Object -FilePath $logFile -Append
    exit 0
}

# Download the latest NetFx472
$setupFileSourceUri = "https://download.microsoft.com/download/0/5/C/05C1EC0E-D5EE-463B-BFE3-9311376A6809/NDP472-KB4054531-Web.exe"
$setupFileLocalPath = Join-Path $env:TEMP -ChildPath "NDP472-KB4054531-Web.exe"

"$(Get-Date): Start to download NetFx 4.7.2 to $setupFileLocalPath." | Tee-Object -FilePath $logFile -Append

if(Test-Path $setupFileLocalPath)
{
    Remove-Item -Path $setupFileLocalPath -Force
}

$webClient = New-Object System.Net.WebClient

$retry = 0

do
{
    try {
        $webClient.DownloadFile($setupFileSourceUri, $setupFileLocalPath)
        break
    }
    catch [Net.WebException] {
        $retry++

        if($retry -gt 3) {
            "$(Get-Date): Download failed as the network connection issue. Exception detail: $_" | Tee-Object -FilePath $logFile -Append
            break
        }

        $waitInSecond = $retry * 30
        "$(Get-Date): It looks the Internet network is not available now. Simply wait for $waitInSecond seconds and try again." | Tee-Object -FilePath $logFile -Append
        Start-Sleep -Second $waitInSecond
    }
} while ($true)


if(!(Test-Path $setupFileLocalPath))
{
    "$(Get-Date): Failed to download NetFx 4.7.2 setup package." | Tee-Object -FilePath $logFile -Append
    exit -1
}

# Install NetFx472
$setupLogFilePath = Join-Path $env:TEMP -ChildPath "NetFx472SetupLog.txt"
if($norestart) {
    $arguments = "/q /norestart /serialdownload /log $setupLogFilePath"
}
else {
    $arguments = "/q /serialdownload /log $setupLogFilePath"
}
"$(Get-Date): Start to install NetFx 4.7.2" | Tee-Object -FilePath $logFile -Append
$process = Start-Process -FilePath $setupFileLocalPath -ArgumentList $arguments -Wait -PassThru

if(-not $process) {
    "$(Get-Date): Install NetFx failed." | Tee-Object -FilePath $logFile -Append
    exit -1
}
else {
    $exitCode = $process.ExitCode

    # 0, 1641 and 3010 indicate success. See https://msdn.microsoft.com/en-us/library/ee390831(v=vs.110).aspx for detail.
    if($exitCode -eq 0 -or $exitCode -eq 1641 -or $exitCode -eq 3010) {
        "$(Get-Date): Install NetFx succeeded with exit code : $exitCode." | Tee-Object -FilePath $logFile -Append
        exit 0
    }
    else {
        "$(Get-Date): Install NetFx failed with exit code : $exitCode." | Tee-Object -FilePath $logFile -Append
        exit -1
    }
}
