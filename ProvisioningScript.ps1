#Script written by Matt Brooks with help from the Intranetz

<#
.PURPOSE
This script is to be run after initial imaging of a computer for Revision Skincare or Goodier Cosmetics.
.Prerequisites
Copy script to 'C:\Provisioning' directory
Open PowerShell as administrator, and run 'Set-ExecutionPolicy -ExecutionPolicy Unrestricted'
Go to the 'C:\Provisioning' directory in PowerShell and run '.\ProvisioningScript.ps1'
If on a domain, remove the computer from the domain before running script.
#>

$VerbosePreference = "Continue"

#RENAME THE COMPUTER AND JOIN TO THE DOMAIN

$ExistingDC = ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)

If ($ExistingDC -eq $False) {
    Write-Verbose '---Renaming computer and joining to the domain.'

#If Computer Is Not On A Domain
#Get New Computer Name
$CompName = Read-Host -Prompt "Input New Computer Name"

#Get Domain Name
$FullDC = Read-Host -Prompt "Input Full Domain Name: RSC.LOCAL/GC.LOCAL"
$ShortDC = Read-Host -Prompt "Input Short Domain Name: RSC/GC"

#Get Network Admin Credentials
$NTCred = Get-Credential -Credential "NTAdmin"

#Add Computer To Proper OU
Add-Computer -DomainName $FullDC -Credential $NTCred -OUPath "OU=Workstations,OU=$ShortDC Computers,DC=$ShortDC,DC=local"

#Rename Computer With Network Admin Credentials
$Computer = Get-WmiObject Win32_ComputerSystem
$r = $Computer.Rename($CompName, $NTCred.GetNetworkCredential().Password, $NTCred.Username)

    Write-Verbose '---Checking for successful joining of domain.'

$ExistingDC = ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)

#Successful Or Unsuccessful With Joining Domain
    If ($ExistingDC -eq $True) {
        Write-Verbose '---Computer has been joined to a domain'
    } Else {
        Write-Verbose '---Computer failed to join a domain. Join manually or check inputs. Be sure to run PowerShell as Administrator.'
        break
    }

#If Successfully Joined To Domain
} Else { 
    Write-Verbose '---Computer is on a domain. Continuing with Office installation.'
}

#UNINSTALL OFFICE2013/INSTALL OFFICE2016

function Is-Installed( $program ) {
    
    $x86 = ((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;

    $x64 = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") |
        Where-Object { $_.GetValue( "DisplayName" ) -like "*$program*" } ).Length -gt 0;

    return $x86 -or $x64;
}
$Office = Is-Installed("Office")

If ($Office -eq $False) {
    Write-Verbose '---Use RSC NTAdmin password for access to shared folder.'
net use \\192.168.110.89 /user:rsc\ntadmin *

Copy-Item "\\192.168.110.89\itg\Provisioning\*" -Destination "C:\Provisioning" -Force -Recurse

cmd /c "C:\Provisioning\Setup.exe /configure C:\Provisioning\install.xml"

} Else {
#Download and run Office Removal Tool
Invoke-WebRequest -Uri "https://aka.ms/diag_officeuninstall" -OutFile C:\Provisioning\o15-ctrremove.diagcab

Invoke-Item "C:\Provisioning\o15-ctrremove.diagcab"
    Write-Verbose '---Uninstalling Office. Continue to click "Next" until you are prompted to close the troubleshooter'

cmd /c pause

Remove-Item "C:\Provisioning\o15-ctrremove.diagcab"

#Check for and remove Access Runtime Registry key
$RegKeyPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Office16.AccessRT"
If ((Test-Path $RegKeyPath) -eq $True) {
    Remove-Item $RegKeyPath
    Write-Verbose '---Access Runtime uninstalled'
} Else {
    Write-Verbose '---Access Runtime is not present'
}

#Check for and remove Visual Studio Runtime Registry key
$RegKeyPath2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9495AEB4-AB97-39DE-8C42-806EEF75ECA7}"
If ((Test-Path $RegKeyPath2) -eq $True) {
    Remove-Item $RegKeyPath2
    Write-Verbose '---Visual Studio Runtime uninstalled'
} Else {
    Write-Verbose '---Visual Studio Runtime is not present'
}

#Check for and remove Visual Studio Runtime (x64) Registry key
$RegKeyPath3 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Visual Studio 2010 Tools for Office Runtime (x64)"
If ((Test-Path $RegKeyPath3) -eq $True) {
    Remove-Item $RegKeyPath3
    Write-Verbose '---Visual Studio Runtime (x64) uninstalled'
} Else {
    Write-Verbose '---Visual Studio Runtime (x64) is not present'
}

    Write-Verbose '---Rebooting before Office install...'
shutdown -r -t 15
    break
}

#RUN WINDOWS UPDATE

Install-PackageProvider NuGet -Force
    Write-Verbose '---Installing NuGet Package'
Install-Module PSWindowsUpdate -Force
    Write-Verbose '---Installing WindowsUpdate PS Module'
Get-WindowsUpdate
    Write-Verbose '---Getting list of Windows Updates'
Install-WindowsUpdate -Force
    Write-Verbose '---Installing Windows Updates'

Remove-Item -Path C:\Provisioning -Recurse
