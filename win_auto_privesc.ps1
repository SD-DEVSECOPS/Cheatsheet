# win_auto_privesc.ps1 - Tactical Windows PrivEsc Enumerator
# USAGE: powershell -ep bypass -c ". .\win_auto_privesc.ps1; Invoke-AutoPrivEsc"

function Invoke-AutoPrivEsc {
    Write-Host "[*] Starting Windows Tactical PrivEsc Check" -ForegroundColor Cyan
    Write-Host "[*] ---------------------------------------" -ForegroundColor Cyan
    
    # 1. Privileges (The "Big Boys")
    Write-Host "[*] Checking Token Privileges..." -ForegroundColor Cyan
    $privs = whoami /priv
    
    if ($privs -match "SeImpersonatePrivilege") {
        Write-Host "[!] SeImpersonate ENABLED! -> Use GodPotato (Win2022) or PrintSpoofer (Old)" -ForegroundColor Red
    }
    if ($privs -match "SeBackupPrivilege") {
        Write-Host "[!] SeBackup ENABLED! -> Dump SAM/SYSTEM via 'reg save'" -ForegroundColor Red
    }
    if ($privs -match "SeRestorePrivilege") {
        Write-Host "[!] SeRestore ENABLED! -> Hijack Utilman/Sticky Keys" -ForegroundColor Red
    }
    if ($privs -match "SeManageVolumePrivilege") {
        Write-Host "[!] SeManageVolume ENABLED! -> Use SeManageVolumeExploit (DLL Hijack)" -ForegroundColor Red
    }
    if ($privs -match "SeTakeOwnershipPrivilege") {
        Write-Host "[!] SeTakeOwnership ENABLED! -> Take file ownership of system binaries" -ForegroundColor Red
    }

    # 2. Services & Paths
    Write-Host "`n[*] Checking Service Misconfigurations..." -ForegroundColor Cyan
    
    # Unquoted Service Paths
    $unquoted = Get-WmiObject win32_service | Where-Object {$_.PathName -like "* *" -and $_.PathName -notlike '"*'}
    if ($unquoted) {
        Write-Host "[!] UNQUOTED SERVICE PATHS FOUND!" -ForegroundColor Red
        $unquoted | Select-Object Name, PathName | ForEach-Object { Write-Host "  [+] $($_.Name): $($_.PathName)" -ForegroundColor Yellow }
    }

    # AlwaysInstallElevated
    $reg1 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $reg2 = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    if ($reg1.AlwaysInstallElevated -eq 1 -and $reg2.AlwaysInstallElevated -eq 1) {
        Write-Host "[!] ALWAYSINSTALLELEVATED ENABLED! -> MSI Exploit Possible" -ForegroundColor Red
    }

    # 3. Credential Hunting (Registry & Files)
    Write-Host "`n[*] Hunting for Stored Credentials..." -ForegroundColor Cyan
    
    # Check AutoLogon
    $autologon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    if ($autologon.DefaultPassword) {
        Write-Host "[!] AUTO-LOGON CREDENTIALS FOUND!" -ForegroundColor Red
        Write-Host "  [+] User: $($autologon.DefaultUserName) / Pass: $($autologon.DefaultPassword)" -ForegroundColor Yellow
    }

    # Check cmdkey
    $cmdkey = cmdkey /list
    if ($cmdkey -match "Target") {
        Write-Host "[!] STORED CREDENTIALS IN CMDKEY FOUND!" -ForegroundColor Red
        Write-Host "  [+] Try running: runas /savecred /user:[USER] cmd.exe" -ForegroundColor Yellow
    }

    # Sensitive Files
    $sensitiveFiles = @("unattend.xml", "web.config", "sysprep.inf", "sysprep.xml", "App.config")
    foreach ($file in $sensitiveFiles) {
        $found = Get-ChildItem -Path C:\ -Include $file -Recurse -ErrorAction SilentlyContinue | Select-Object -First 3
        if ($found) {
            Write-Host "[!] SENSITIVE FILE FOUND: $file" -ForegroundColor Red
            $found | ForEach-Object { Write-Host "  [+] Path: $($_.FullName)" -ForegroundColor Yellow }
        }
    }

    # 4. Active Directory Context (LAPS & GMSA)
    Write-Host "`n[*] Checking AD Components..." -ForegroundColor Cyan
    
    # LAPS Check
    if (Test-Path "C:\Program Files\LAPS\CSE") {
        Write-Host "[!] LAPS IS INSTALLED! -> Check for read permissions on ms-Mcs-AdmPwd" -ForegroundColor Yellow
    }

    # GPO Access
    Write-Host "[*] Check if you have GenericWrite on GPOs via BloodHound/NetExec" -ForegroundColor Gray

    Write-Host "`n[*] ---------------------------------------" -ForegroundColor Cyan
    Write-Host "[*] Enumeration Complete!" -ForegroundColor Green
}

# Run it
Invoke-AutoPrivEsc
