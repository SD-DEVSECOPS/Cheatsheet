# win_auto_privesc.ps1 - The Definitive OSCP Tactical Enumerator
# USAGE: powershell -ep bypass -c ". .\win_auto_privesc.ps1; Invoke-AutoPrivEsc"
# COMBINES: Original V1 checks + V2 Research Improvements.

function Invoke-AutoPrivEsc {
    Write-Host "[*] Starting Windows MASTER Tactical PrivEsc Check" -ForegroundColor Cyan
    Write-Host "[*] -----------------------------------------------" -ForegroundColor Cyan
    
    # 1. Privileges (The "Big Boys")
    Write-Host "[*] Checking Token Privileges & OS Version..." -ForegroundColor Cyan
    $privs = whoami /priv
    
    # Build Check for HiveNightmare (SeriousSAM)
    $version = [System.Environment]::OSVersion.Version
    if ($version.Major -eq 10 -and $version.Build -ge 17763 -and $version.Build -le 19043) {
        Write-Host "[!] OS BUILD ($($version.Build)) VULNERABLE TO HIVENIGHTMARE (SeriousSAM)!" -ForegroundColor Red
        Write-Host "  [+] Action: Check for shadow copies: dir \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*" -ForegroundColor Yellow
    }

    $checkPrivs = @(
        @{Name="SeImpersonatePrivilege"; Desc="SYSTEM Shell -> Use GodPotato or PrintSpoofer"},
        @{Name="SeBackupPrivilege"; Desc="SAM/SYSTEM Dump via 'reg save'"},
        @{Name="SeRestorePrivilege"; Desc="SYSTEM Shell via Utilman Hijack"},
        @{Name="SeManageVolumePrivilege"; Desc="SYSTEM Shell via SeManageVolumeExploit (tzres.dll)"},
        @{Name="SeTakeOwnershipPrivilege"; Desc="Persistence/Hijack via sethc.exe ownership"},
        @{Name="SeLoadDriverPrivilege"; Desc="Kernel Exploit potential (Capcom.sys etc)"}
    )

    foreach ($p in $checkPrivs) {
        if ($privs -match $p.Name) {
            Write-Host "[!] $($p.Name) ENABLED!" -ForegroundColor Red
            Write-Host "  [+] Action: $($p.Desc)" -ForegroundColor Yellow
        }
    }

    # 2. Network - Local Only (Pivoting Leads)
    Write-Host "`n[*] Checking Local Listening Ports (Pivoting/Tunneling Leads)..." -ForegroundColor Cyan
    netstat -ano | Select-String "LISTENING" | Select-String "127.0.0.1|0.0.0.0" | ForEach-Object {
        Write-Host "  [+] Port Found: $($_.ToString().Trim())" -ForegroundColor Yellow
    }

    # 3. Services & Registry Vulnerabilities
    Write-Host "`n[*] Checking Service & Registry Misconfigurations..." -ForegroundColor Cyan
    
    # Unquoted Service Paths
    $unquoted = Get-WmiObject win32_service | Where-Object {$_.PathName -like "* *" -and $_.PathName -notlike '"*'}
    if ($unquoted) {
        Write-Host "[!] UNQUOTED SERVICE PATHS FOUND!" -ForegroundColor Red
        foreach($s in $unquoted) { Write-Host "  [+] $($s.Name): $($s.PathName)" -ForegroundColor Yellow }
    }

    # Modifiable Service Registry Keys (ImagePath Hijack)
    $services = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" | Select-Object PSChildName, ImagePath
    foreach ($s in $services) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.PSChildName)"
        try {
            $acl = Get-Acl $path -ErrorAction SilentlyContinue
            if ($acl.AccessToString -match "BUILTIN\\Users.*(Write|FullControl|Modify|ChangePermissions)") {
                Write-Host "[!] MODIFIABLE REGISTRY KEY: $($s.PSChildName)" -ForegroundColor Red
                Write-Host "  [+] Action: Hijack 'ImagePath' for SYSTEM shell" -ForegroundColor Yellow
            }
        } catch {}
    }

    # Weak Service Permissions (sc.exe check)
    Get-Service | Select-Object -First 20 | ForEach-Object {
        $n = $_.Name
        $sd = sc.exe sdshow $n 2>$null
        if ($sd -match "WD.*RP") { Write-Host "[!] WEAK SERVICE PERMS: $n" -ForegroundColor Red }
    }

    # AlwaysInstallElevated
    $reg1 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $reg2 = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    if ($reg1.AlwaysInstallElevated -eq 1 -and $reg2.AlwaysInstallElevated -eq 1) {
        Write-Host "[!] ALWAYSINSTALLELEVATED ENABLED! -> Use msfvenom MSI" -ForegroundColor Red
    }

    # 4. Credential & History Hunting
    Write-Host "`n[*] Hunting for Credentials & Secrets..." -ForegroundColor Cyan
    
    # PowerShell History
    $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $historyPath) {
        Write-Host "[!] POWERSHELL HISTORY FOUND!" -ForegroundColor Red
        Get-Content $historyPath -Tail 10 | ForEach-Object { Write-Host "  > $_" -ForegroundColor Gray }
    }

    # Stored Credentials
    if (cmdkey /list -match "Target") { Write-Host "[!] STORED CREDENTIALS IN CMDKEY!" -ForegroundColor Red }
    $autologon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    if ($autologon.DefaultPassword) { Write-Host "[!] AUTO-LOGON: $($autologon.DefaultUserName):$($autologon.DefaultPassword)" -ForegroundColor Red }

    # Sensitive Files (Partial System Crawl)
    $files = @("unattend.xml", "web.config", "sysprep.xml", "App.config")
    foreach ($f in $files) {
        $res = Get-ChildItem -Path C:\ -Include $f -Recurse -ErrorAction SilentlyContinue | Select-Object -First 2
        if ($res) { Write-Host "[!] SENSITIVE FILE: $($res.FullName)" -ForegroundColor Red }
    }

    # 5. Tasks & Scheduled Events
    Write-Host "`n[*] Checking Scheduled Tasks..." -ForegroundColor Cyan
    $tasks = Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM" -and $_.State -eq "Ready"}
    if ($tasks) {
        Write-Host "[!] SYSTEM TASKS FOUND (Check if you can modify binaries/XMLs)" -ForegroundColor Red
        $tasks | Select-Object TaskName -First 5 | ForEach-Object { Write-Host "  [+] Task: $($_.TaskName)" -ForegroundColor Yellow }
    }

    # 6. AD/LAPS Context
    if (Test-Path "C:\Program Files\LAPS\CSE") { Write-Host "[!] LAPS INSTALLED! -> Search for ms-Mcs-AdmPwd" -ForegroundColor Yellow }

    Write-Host "`n[*] -----------------------------------------------" -ForegroundColor Cyan
    Write-Host "[*] MASTER CHECK COMPLETE! Results over theories." -ForegroundColor Green
}

Invoke-AutoPrivEsc
