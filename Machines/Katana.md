# Katana: Machine Notes (PG-Play)

## Recon

### Nmap
- Port 21/tcp: FTP (vsftpd 3.0.3)
- Port 22/tcp: SSH (OpenSSH 7.9p1)
- Port 80/tcp: HTTP (Apache 2.4.38)
- Port 7080/tcp: HTTPS (LiteSpeed)
- Port 8088/tcp: HTTP (LiteSpeed)
- Port 8715/tcp: HTTP (Nginx - Basic Auth required)

### Web Enumeration
- Ebook store found on port 80.
- Admin panel at `/ebook/admin_book.php` uses `admin:admin`.
- Fuzzing port 8088 revealed `/upload.html` and `/upload.php`.

## Initial Access

### Weak Credentials (SSH)
- Surprisingly, weak credentials worked for initial access:
- `katana` : `root`

### Web Shell Upload (Alternative Foothold)
1. Found an upload form at `http://[IP]:8088/upload.html`.
2. Uploaded a PHP reverse shell (`rev.php`).
3. The server response indicated the file was moved:
   - `Moved to other web server: /tmp/php[random] ====> /opt/manager/html/katana_rev.php`
4. This new location is served on port 8715.
5. Access the shell via `http://[IP]:8715/katana_rev.php` using Basic Auth `admin:admin`.

## Privilege Escalation

### Capability Enumeration
- Ran `linpeas` or `getcap` to find file capabilities:
```bash
getcap -r / 2>/dev/null
```
- Found: `/usr/bin/python2.7 = cap_setuid+ep`

### Python setuid Abuse
- Since Python 2.7 has the `cap_setuid` capability, we can set our UID to 0 (root) and spawn a shell.
```bash
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
- Result: **Root shell**.
